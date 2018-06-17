using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.MSBuild;
using Pwning.Posse.Tracker;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Reflection;
using System.ServiceProcess;
using System.Management;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Reflection.Metadata;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using CL = CommandLine;
using CommandLine;

namespace Pwning.Posse.CommandLine
{
    class ServiceDetails
    {        
        public string ServiceName;
        public string ServicePath;
        public string RunningAs;
    }

    [Verb("scan", HelpText = "Scan source code for security vulnerability")]
    class ScanOptions
    {
        [Option(Required = true, HelpText = "Path to containing folder of .csproj")]
        public string Path { get; set; }

        [Option('r', "recursive", Default = false, HelpText = "Perform recursive search of sub folders")]
        public bool Recursive { get; set; }
    }

    [Verb("decompile", HelpText = "Decompile an assembly into source code")]
    class DecompileOptions
    {
        [Option(Required = true, HelpText = "Path to .Net assembly")]
        public string Path { get; set; }

        [Option('s', Required = false, HelpText = "Performs scanning on decompiled .Net assembly")]
        public bool ScanOutput { get; set; }
    }

    [Verb("find", HelpText = "Find a .Net assembly")]
    class FindOptions
    {
        [Option('s', Default = false, HelpText = "Decompile and scan assemblies ater locating")]
        public bool Scan { get; set; }

        [Option('r', "recursive", Default = false, HelpText = "Perform recursive search of sub folders")]
        public bool Recursive { get; set; }

        [Option(Required = true, HelpText = "Folder to search for .net assembly")]
        public string Path { get; set; }
    }

    enum InformationType
    {        
        Services,
        Scanners
    }

    [Verb("list", HelpText = "List system information")]
    class ListOptions
    {        
        [Option('i', "InformationType", Required = true, HelpText = "0=Services 1=Scanners")]
        public InformationType InformationType { get; set; }       

        [Option('s', Default = false, HelpText = "Scans listed .net services")]
        public bool Scan { get; set; }
    }

    class DotNetAssemblyInfo
    {
        public string AssemblyPath;
        public string ProjectPath;
    }

    class Program
    {
        [DllImport("user32.dll")]
        public static extern bool ShowWindow(System.IntPtr hWnd, int cmdShow);       

        static void MaximizeWindow()
        {
            Process p = Process.GetCurrentProcess();
            ShowWindow(p.MainWindowHandle, 3); //SW_MAXIMIZE = 3
        }        

        static void HandleParseError(IEnumerable<Error> errs)
        {
        }

        static void Main(string[] args)
        {
            MaximizeWindow();

            //To handle input lower and upper
            args = args.ToList().Select(x => x.ToLower()).ToArray();

            CL.Parser.Default.ParseArguments<ScanOptions, DecompileOptions, FindOptions, ListOptions>(args)
                                .MapResult(
                                            (ScanOptions option) => ProcessScan(option),
                                            (DecompileOptions option) => ProcessDecompile(option),
                                            (FindOptions option) => ProcessFind(option),
                                            (ListOptions option) => ProcessLists(option),
                                            errs => 1);             
        }

        private static int ProcessFind(FindOptions option)
        {
            if (!string.IsNullOrEmpty(option.Path))
            {
                if (!Directory.Exists(option.Path))
                {
                    Console.WriteLine($"{option.Path} is not a valid path");
                    return 1;
                }

                var dotNetAssemblyPaths = FindDotNetAssemblies(option.Path, option.Recursive);

                if(option.Scan)
                {
                    throw new NotImplementedException();
                }

                return 0;
            }

            return 1;
        }

        private static int ProcessScan(ScanOptions option)
        {
            if (!string.IsNullOrEmpty(option.Path))
            {
                if (!Directory.Exists(option.Path))
                {
                    Console.WriteLine($"{option.Path} is not a valid path");
                    return 1;
                }

                var pathList    = new List<string>();                
                pathList        = DotNetScout.FindFiles(option.Path, ".csproj", option.Recursive);     
                
                if(pathList.Count <= 0)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"No csproj files found under {option.Path}");
                    Console.ResetColor();
                }

                FindDotNetVulnerabilities(pathList);
                return 0;
            }

            return 1;
        }

        private static int ProcessDecompile(DecompileOptions option)
        {
            if(!string.IsNullOrEmpty(option.Path))
            {
                var outputDirectory = DecompileTarget(option.Path);

                if(option.ScanOutput)
                {
                    var pathList = DotNetScout.FindFiles(outputDirectory, ".csproj");
                    FindDotNetVulnerabilities(pathList);
                }

                return 0;
            }

            return 1;
        }

        private static int ProcessLists(ListOptions option)
        {
            if (option.InformationType == InformationType.Services)
            {
                Console.WriteLine();
                Console.WriteLine("Displaying services running as localsystem that do not start from system32");
                Console.ResetColor();

                var serviceList = FindDotNetServices();

                serviceList.ForEach(x =>
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("{2,-30}{0,-30}{1, 0}", x.ServiceName, x.ServicePath, x.RunningAs);
                    Console.ResetColor();
                });

                if (option.Scan)
                {
                    serviceList.ForEach(x =>
                    {
                        ProcessDecompile(new DecompileOptions() { Path = x.ServicePath, ScanOutput = true });
                    });
                }

                return 0;
            }

            return 1;
        }

        /*private static void ListDecompiledAssemblies()
        {
            if (_dotNetAssemblyPaths.Keys.Count <= 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"No paths have been added");
                Console.ResetColor();
            }

            _dotNetAssemblyPaths.Keys.AsParallel()
                .Where(x => !string.IsNullOrEmpty(_dotNetAssemblyPaths[x]))
                .ForAll(bin => Console.WriteLine($"Assembly {bin} is decompiled in {_dotNetAssemblyPaths[bin]}"));
        }*/       

        private static string DecompileTarget(string assemblyFileName)
        {
            string decompileDirectory = string.Empty;
            if (File.Exists(assemblyFileName))
            {               
                var module                          = UniversalAssemblyResolver.LoadMainModule(assemblyFileName);
                WholeProjectDecompiler decompiler   = new WholeProjectDecompiler();
                decompileDirectory                  = FileUtilities.GetTemporaryDirectory(assemblyFileName);

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine();
                Console.WriteLine($"Decompiling {assemblyFileName} to {decompileDirectory}");
                Console.ResetColor();

                try
                {
                    decompiler.DecompileProject(module, decompileDirectory);                   
                }
                catch
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Decompiling {assemblyFileName} threw an exception");
                    Console.ResetColor();
                }
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"The assembly '{assemblyFileName}' does not exist");
                Console.ResetColor();
            }

            return decompileDirectory;
        }

        static ServiceDetails GetDotNetService(ServiceController service)
        {
            ServiceDetails serviceDetails = null;
            using (var wmiService = new ManagementObject($"Win32_Service.Name='{service.ServiceName}'"))
            {
                wmiService.Get();

                var servicePath = wmiService["PathName"].ToString();
                var exePath     = servicePath.Substring(0, servicePath.IndexOf(".exe") + 4);
                var isDotNet    = DotNetScout.IsDotNetAssembly(exePath);

                if (isDotNet)
                {
                    serviceDetails = new ServiceDetails()
                    {
                        RunningAs   = wmiService["StartName"].ToString(),
                        ServiceName = service.ServiceName,
                        ServicePath = wmiService["PathName"].ToString()
                    };
                }
            }

            return serviceDetails;
        }

        static bool IsLocalSystemService(ServiceController service)
        {
            bool isFiltered = false;
            using (var wmiService = new ManagementObject($"Win32_Service.Name='{service.ServiceName}'"))
            {
                wmiService.Get();
                var isSystem32 = false;

                try
                {
                    var servicePath         = wmiService["PathName"].ToString();
                    var serviceDirectory    = Path.GetDirectoryName(servicePath);
                    isSystem32              = serviceDirectory.ToLower().Contains(@"c:\windows\system32");
                }
                catch
                {
                    //TODO: Log exception - get real exception type
                    isSystem32 = true;
                }

                isFiltered = wmiService["StartName"] != null && wmiService["StartName"].ToString().Contains("LocalSystem") && !isSystem32;
            }

            return isFiltered;
        }

        static List<ServiceDetails> FindDotNetServices()
        {
            var dotNetServiceList = ServiceController.GetServices()
                     .Where(x => x.Status == ServiceControllerStatus.Running)
                     .Where(y => IsLocalSystemService(y))
                     .Select(svc => GetDotNetService(svc))
                     .Where(detail => detail != null)
                     .ToList();
            
            return dotNetServiceList;
        }

        static void FindDotNetVulnerabilities(List<string> assemblyPathList)
        {  
            var issuesFound = AnalyzeDotNetAssemblies(assemblyPathList);
            
            if (issuesFound.Count > 0)
            {                
                Console.ForegroundColor = ConsoleColor.Red;             

                issuesFound                    
                    .AsParallel()
                    .ForAll(issue =>
                    {
                        Console.WriteLine("{0} {1})", issue.GetMessage(), issue.Location.GetMappedLineSpan());
                    });
                Console.ResetColor();
            }
            else
            {
                assemblyPathList.ForEach(x => Console.WriteLine($"No security issues found in {x}"));
            }
        }

        static IEnumerable<string> FindDotNetAssemblies(string rootPath, bool recursiveSearch)
        {
            //TODO: Save details to disk + add stop and restore during process
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine("Scanning for .Net assemblies");
            if (recursiveSearch)
            {
                Console.WriteLine("This will take some time if a high root folder has been selected");
            }
            Console.ResetColor();          
           
            var allAssemblies   = DotNetScout.FindFiles(rootPath, ".exe;.dll", recursiveSearch).Where(x => DotNetScout.IsDotNetAssembly(x));            

            Console.WriteLine($"Found {allAssemblies.Count()} .Net assemblies");

            return allAssemblies;
        }

        static List<Diagnostic> AnalyzeDotNetAssemblies(List<string> projectFiles)
        {             
            List<Diagnostic> issueList  = new List<Diagnostic>();

            projectFiles.ToList().ForEach(x =>
            {                
                var msWorkspace     = MSBuildWorkspace.Create();              
                var project         = msWorkspace.OpenProjectAsync(x).Result;

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine();
                Console.WriteLine($"Inspecting project {project.FilePath}");
                Console.ResetColor();

                DiagnosticAnalyzer analyzer     = new BinaryFormatterTracker();                    
                var compilationWithAnalyzers    = project.GetCompilationAsync().Result.WithAnalyzers(ImmutableArray.Create(analyzer));
                issueList.AddRange(compilationWithAnalyzers.GetAnalyzerDiagnosticsAsync().Result);                
            });

            return issueList;
        }
    }
}
