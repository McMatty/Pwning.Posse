using CommandLine;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.MSBuild;
using Pwning.Posse.CommandLine.Options;
using Pwning.Posse.Tracker;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using CL = CommandLine;

namespace Pwning.Posse.CommandLine
{  
    class Program
    {
        [DllImport("user32.dll")]
        public static extern bool ShowWindow(System.IntPtr hWnd, int cmdShow);       

        static void MaximizeWindow()
        {
            Process p = Process.GetCurrentProcess();
            ShowWindow(p.MainWindowHandle, 3); //SW_MAXIMIZE = 3
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

                if(option.Save)
                {
                    File.WriteAllLines("paths.txt", dotNetAssemblyPaths);                   
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
                pathList        = DotNetAssemblyLocater.FindFiles(option.Path, ".csproj", option.Recursive);     
                
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
                    var pathList = DotNetAssemblyLocater.FindFiles(outputDirectory, ".csproj");
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

                var serviceList = DotNetServiceUtilities.FindDotNetServices();

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
           
            var allAssemblies   = DotNetAssemblyLocater.FindFiles(rootPath, ".exe;.dll", recursiveSearch).Where(x => DotNetAssemblyLocater.IsDotNetAssembly(x));            

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
