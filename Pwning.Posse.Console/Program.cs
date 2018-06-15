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

namespace Pwning.Posse.CommandLine
{
    class Program
    {
        [DllImport("user32.dll")]
        public static extern bool ShowWindow(System.IntPtr hWnd, int cmdShow);

        private static Dictionary<String, String> _userOptions          = new Dictionary<string, string>();
        private static List<string> _validOptions                       = new List<string> {"target_folder", "target_bin"};
        private static Dictionary<string, string> _dotNetAssemblyPaths  = new Dictionary<string, string>();

        static void RenderMenu()
        {
            var target          = _userOptions.ContainsKey("target_folder") ? _userOptions["target_folder"] : "<target not set>";
            var assemblyPath    = _userOptions.ContainsKey("target_bin") ? _userOptions["target_bin"] : "<target not set>";

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine("Select one of the options below:");
            Console.WriteLine("1. Scan machine for .Net assemblies");
            Console.WriteLine($"2. Scan {target} .Net assembly for vulnerabilities");
            Console.WriteLine("3. List services running .Net assemblies");
            Console.WriteLine("4. Set console options");
            Console.WriteLine($"5. Decompile {assemblyPath}");
            Console.WriteLine("6. List decompiled assemblies and their project location");
            Console.WriteLine("0. Exit");
            Console.ResetColor();
        }

        static void MaximizeWindow()
        {
            Process p = Process.GetCurrentProcess();
            ShowWindow(p.MainWindowHandle, 3); //SW_MAXIMIZE = 3
        }

        static void Main(string[] args)
        {
            MaximizeWindow();
            RenderMenu();

            bool exit = false;
            while (!exit)
            {
                Console.WriteLine();
                char option = Console.ReadKey(true).KeyChar;
                Console.WriteLine();

                switch (option)
                {
                    case '0':
                        {
                            exit = true;
                            break;
                        }
                    case '1':
                        {
                            FindAllDotNetAssemblies();                           
                            break;
                        }
                    case '2':
                        {
                            ScanFolderForVulnerabilities();
                            break;
                        }                    
                    case '3':
                        {
                            FindDotNetServices();
                            break;
                        }
                    case '4':
                        {
                            SetConsoleOption();
                            break;
                        }
                    case '5':
                        {
                            DecompileTarget();
                            break;
                        }
                    case '6':
                        {
                            ListDecompiledAssemblies();
                            break;
                        }
                    default:
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine("Invalid selection");
                            Console.ResetColor();
                            break;                          
                        }
                }

                RenderMenu();
            }
        }

        private static void ListDecompiledAssemblies()
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
        }

        private static void ScanFolderForVulnerabilities()
        {
            if (_userOptions.ContainsKey("target_folder"))
            {
                FindDotNetVulnerabilities(_userOptions["target_folder"]);
            }
            else
            {
                Console.WriteLine("'target_folder' not set. Defaulting to root folder.");
                var projectFolder = Directory.GetDirectoryRoot(Assembly.GetExecutingAssembly().Location);
                Console.WriteLine($"'target_folder' not set. Defaulting to root folder '{projectFolder}'");
                FindDotNetVulnerabilities(projectFolder);
            }
        }

        private static void DecompileTarget()
        {
            if (_userOptions.ContainsKey("target_bin"))
            {
                var assemblyFileName                =_userOptions["target_bin"];
                var module                          = UniversalAssemblyResolver.LoadMainModule(assemblyFileName);
                WholeProjectDecompiler decompiler   = new WholeProjectDecompiler();
                var outputDirectory                 = FileUtilities.GetTemporaryDirectory();

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"Decompiling {assemblyFileName} ");
                Console.ResetColor();

                try
                {
                    decompiler.DecompileProject(module, outputDirectory);
                    _dotNetAssemblyPaths[assemblyFileName] = outputDirectory;
                    _userOptions["target_folder"] = outputDirectory;
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
                Console.WriteLine($"The option 'target_bin' has not been set");
                Console.ResetColor();
            }
        }

        private static void SetConsoleOption()
        {
            Console.WriteLine("Allowed option settings:");
            _validOptions.ForEach(x => Console.WriteLine(x));
            Console.WriteLine();
            Console.WriteLine("Select option");
            var key = Console.ReadLine().ToLower();

           if( _validOptions.IndexOf(key) == -1)
            {
                Console.WriteLine($"{key} is an invalid option");
                return;
            }

            Console.WriteLine("Set option value");
            var value = Console.ReadLine();
            Console.WriteLine($"{key} set to {value}");
            _userOptions[key] = value;
        }

        static void DisplayDotNetService(ServiceController service)
        {
            using (var wmiService = new ManagementObject($"Win32_Service.Name='{service.ServiceName}'"))
            {
                wmiService.Get();

                var servicePath = wmiService["PathName"].ToString();
                var exePath     = servicePath.Substring(0, servicePath.IndexOf(".exe") + 4);
                var isDotNet    = DotNetScout.IsDotNetAssembly(exePath);

                if (isDotNet)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    _userOptions["target_bin"] = wmiService["PathName"].ToString();
                }
                Console.WriteLine("{2,-30}{0,-30}{1, 0}", service.ServiceName, wmiService["PathName"], wmiService["StartName"]);
                Console.ResetColor();
            }
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

        static void FindDotNetServices()
        {
            Console.WriteLine();
            Console.WriteLine("Displaying services running as localsystem that do not start from system32 and have a valid path");
            Console.Write("Dotnet assemblies will appear in ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Green");
            Console.ResetColor();

            ServiceController.GetServices()
                     .Where(x => x.Status == ServiceControllerStatus.Running)
                     .Where(y => IsLocalSystemService(y))
                     .ToList()
                     .ForEach(svc => DisplayDotNetService(svc));
        }

        static void FindDotNetVulnerabilities(string projectPath)
        {
            if(string.IsNullOrEmpty(projectPath) || !Directory.Exists(projectPath))
            {
                Console.WriteLine($"{projectPath} is not a valid path");
                return;
            }

            Console.WriteLine($"Looking for possible deserialization vulnerabilities under {projectPath}");
            Console.WriteLine();
            var issuesFound = AnalyzeDotNetAssembly(projectPath);
            
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
                Console.WriteLine($"No security issues found in {projectPath}");
            }
        }

        static void FindAllDotNetAssemblies()
        {
            //TODO: Save details to disk + add stop and restore during process
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine("Scanning for all .Net assemblies. This will take some time.");
            Console.ResetColor();
          
            var rootPath        = Directory.GetDirectoryRoot(Assembly.GetExecutingAssembly().Location);
            var allAssemblies   = DotNetScout.FindFiles(rootPath, ".exe;.dll").Where(x => DotNetScout.IsDotNetAssembly(x));

            Console.WriteLine($"Found {allAssemblies.Count()} .Net assemblies");
        }

        static List<Diagnostic> AnalyzeDotNetAssembly(string projectPath)
        {  
            var projectFiles           = DotNetScout.FindFiles(projectPath, ".csproj");
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
