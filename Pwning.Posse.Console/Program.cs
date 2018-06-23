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

        //TODO:IOC or reflection to load all analyzers   
        private static List<DiagnosticAnalyzer> _analyzers = new List<DiagnosticAnalyzer>() { new BinaryDeserializeTracker() , new XXETracker(), new JsonDeserializeTracker() };

        static void MaximizeWindow()
        {
            Process p = Process.GetCurrentProcess();
            ShowWindow(p.MainWindowHandle, 3); //SW_MAXIMIZE = 3
        }  

        static void Main(string[] args)
        {
            MaximizeWindow();

            CL.Parser.Default.ParseArguments<ScanOptions, DecompileOptions, ListOptions>(args)
                                .MapResult(
                                            (ScanOptions option) => ProcessScan(option),
                                            (DecompileOptions option) => ProcessDecompile(option),                                            
                                            (ListOptions option) => ProcessLists(option),
                                            errs => 1);             
        }

        private static int ProcessScan(ScanOptions option)
        {
            var targetPath = option.Path;
            if (!string.IsNullOrEmpty(targetPath))
            {
                if (!Directory.Exists(targetPath))
                {
                    Console.WriteLine($"{targetPath} is not a valid path");
                    return 1;
                }

                var searchString    = string.Empty;
                var pathList        = new List<string>();

                switch (option.FileType)
                {                   
                    case FileType.Assemblies:
                        {
                            Console.WriteLine($"Searching {targetPath} for files ending with '.dll;.exe'");
                            FindDotNetAssemblies(targetPath, option.Recursive)
                                                    .ToList()
                                                    .ForEach(x => pathList.Add(DecompileTarget(x)));
                            
                            break;
                        };
                    case FileType.Nuget:
                        {
                            searchString = ".nupkg";
                            Console.WriteLine($"Searching {targetPath} for files ending with '{searchString}'");
                            DotNetAssemblyLocater.FindFiles(targetPath, searchString, option.Recursive)                                
                                .ForEach(x => FileUtilities.ExtractNugetAssemblies(x)
                                                          .ForEach(dll => pathList.Add(DecompileTarget(dll))
                                                          ));
                            break;
                        };
                    case FileType.Project:
                        {
                            Console.WriteLine($"Searching {targetPath} for files ending with '.csproj'");
                            pathList.Add(targetPath);
                            break;
                        };
                    default: break;
                }                             

                if (pathList.Count <= 0)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"No {searchString} files found under {targetPath}");
                    Console.ResetColor();

                    return 1;
                }

                FindDotNetVulnerabilities(pathList, option.Recursive);

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
                    FindDotNetVulnerabilities(pathList, false);
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
                var module                                          = UniversalAssemblyResolver.LoadMainModule(assemblyFileName, false);
                WholeProjectDecompiler decompiler                   = new WholeProjectDecompiler();
                decompiler.Settings.ThrowOnAssemblyResolveErrors    = false;
                decompileDirectory                                  = FileUtilities.GetDecompileDirectory(assemblyFileName, false);

                if(Directory.Exists(decompileDirectory) && Directory.GetFiles(decompileDirectory).Count() > 0)
                {
                    //TODO: Add a override option + better faster way to check
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine();
                    Console.WriteLine($"Already decompiled located here {decompileDirectory}");
                    Console.ResetColor();

                    return decompileDirectory;
                }
                else
                {
                    Directory.CreateDirectory(decompileDirectory);
                }

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine();
                Console.WriteLine($"Decompiling {assemblyFileName} to {decompileDirectory}");
                Console.ResetColor();

                try
                {
                    decompiler.DecompileProject(module, decompileDirectory);                   
                }
                catch(Exception ex)
                {
                    var message             = ex.InnerException != null ? ex.InnerException.Message : ex.Message;
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Decompiling {assemblyFileName} threw an exception with the message {message}");
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
        
        static void FindDotNetVulnerabilities(List<string> pathList, bool isRecursive)
        {
            pathList.SelectMany(x => AnalyzeDotNetAssemblies(DotNetAssemblyLocater.FindFiles(x, ".csproj", isRecursive)))
                   .AsParallel()
                   .ForAll(issue =>
                   {
                       Console.ForegroundColor = ConsoleColor.Red;
                       Console.WriteLine("{0} {1})", issue.GetMessage(), issue.Location.GetMappedLineSpan());
                       Console.ResetColor();
                   });
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
            var msWorkspace             = MSBuildWorkspace.Create();

            projectFiles.ToList().ForEach(x =>
            {                
                var project         = msWorkspace.OpenProjectAsync(x).Result;

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine();
                Console.WriteLine($"Inspecting project {project.FilePath}");
                Console.ResetColor();
                             
                var compilationWithAnalyzers        = project.GetCompilationAsync().Result.WithAnalyzers(_analyzers.ToImmutableArray());
                issueList.AddRange(compilationWithAnalyzers.GetAnalyzerDiagnosticsAsync().Result);                
            });

            return issueList;
        }        
    }
}
