using CommandLine;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.MSBuild;
using Mono.Cecil;
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
        private static List<DiagnosticAnalyzer> _analyzers = new List<DiagnosticAnalyzer>() { new BinaryDeserializeTracker(), new XXETracker(), new JsonDeserializeTracker() };

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
                                            (ListOptions option) => ListServices(option),
                                            errs => 1);
        }

        private static int ProcessScan(ScanOptions option)
        {
            var targetPath = option.Path;
            if (Directory.Exists(targetPath))
            {
                var searchString = string.Empty;
                var pathList = new List<string>();

                switch (option.FileType)
                {
                    case FileType.Assemblies:
                        {
                            pathList = ScanAssembly(targetPath, option.Recursive);
                            break;
                        };
                    case FileType.Nuget:
                        {
                            pathList = ScanNuget(targetPath, option.Recursive);
                            break;
                        };
                    case FileType.Project:
                        {
                            ConsoleOutput.Message($"Searching {targetPath} for files ending with '.csproj'");
                            pathList.Add(targetPath);
                            break;
                        };
                    default: break;
                }

                if (pathList.Count <= 0)
                {
                    ConsoleOutput.ErrorMessage($"No {searchString} files found under {targetPath}");

                    return 1;
                }
                FindDotNetVulnerabilities(pathList, option.Recursive);

                return 0;
            }
            else
            {
                ConsoleOutput.ErrorMessage($"'{targetPath}' is not a valid path");
            }

            return 1;
        }

        private static List<String> ScanAssembly(string targetPath, bool isRecursive)
        {
            ConsoleOutput.Message($"Searching {targetPath} for files ending with '.dll;.exe'");

            var pathList = new List<String>();
            FindDotNetAssemblies(targetPath, isRecursive)
                                    .ToList()
                                    .ForEach(x => pathList.Add(DecompileTarget(x)));

            return pathList;
        }

        private static List<String> ScanNuget(string targetPath, bool isRecursive)
        {
            var pathList = new List<String>();
            var searchString = ".nupkg";
            ConsoleOutput.Message($"Searching {targetPath} for files ending with '{searchString}'");

            DotNetAssemblyLocater.FindFiles(targetPath, searchString, isRecursive)
                .ForEach(x => FileUtilities.ExtractNugetAssemblies(x)
                                          .ForEach(dll => pathList.Add(DecompileTarget(dll))
                                          ));

            return pathList;
        }

        private static int ProcessDecompile(DecompileOptions option)
        {
            if (!string.IsNullOrEmpty(option.Path))
            {
                var outputDirectory = DecompileTarget(option.Path);

                if (option.ScanOutput)
                {
                    var pathList = DotNetAssemblyLocater.FindFiles(outputDirectory, ".csproj");
                    FindDotNetVulnerabilities(pathList, false);
                }
                return 0;
            }
            return 1;
        }

        private static int ListServices(ListOptions option)
        {
            if (option.InformationType == InformationType.Services)
            {
                ConsoleOutput.Message("Displaying services running as localsystem that do not start from system32");
                var serviceList = DotNetServiceUtilities.FindDotNetServices();

                serviceList.ForEach(x =>
                {
                    ConsoleOutput.SystemMessage(string.Format("{2,-30}{0,-30}{1, 0}", x.ServiceName, x.ServicePath, x.RunningAs));

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
                decompileDirectory = FileUtilities.GetDecompileDirectory(assemblyFileName, false);
                ModuleDefinition module = null;
                WholeProjectDecompiler decompiler = null;

                if (Directory.Exists(decompileDirectory) && Directory.GetFiles(decompileDirectory).Count() > 0)
                {
                    module = UniversalAssemblyResolver.LoadMainModule(assemblyFileName, false);
                    decompiler = new WholeProjectDecompiler();
                    decompiler.Settings.ThrowOnAssemblyResolveErrors = false;
                    decompileDirectory = FileUtilities.GetDecompileDirectory(assemblyFileName, false);

                    if (Directory.Exists(decompileDirectory) && Directory.GetFiles(decompileDirectory).Count() > 0)
                    {
                        ConsoleOutput.SystemMessage($"Already decompiled located here {decompileDirectory}");
                        return decompileDirectory;
                    }
                    else
                    {
                        Directory.CreateDirectory(decompileDirectory);
                    }


                    try
                    {
                        ConsoleOutput.SystemMessage($"Decompiling {assemblyFileName} to {decompileDirectory}");
                        decompiler.DecompileProject(module, decompileDirectory);
                    }
                    catch (Exception ex)
                    {
                        var message = ex.InnerException != null ? ex.InnerException.Message : ex.Message;
                        ConsoleOutput.ErrorMessage($"Decompiling {assemblyFileName} threw an exception with the message {message}");
                    }
                }
                else
                {
                    ConsoleOutput.ErrorMessage($"The assembly '{assemblyFileName}' does not exist");
                }
            }

            return decompileDirectory;
        }

        static void FindDotNetVulnerabilities(List<string> pathList, bool isRecursive)
        {
            pathList.SelectMany(x => AnalyzeDotNetAssemblies(DotNetAssemblyLocater.FindFiles(x, ".csproj", isRecursive)))
                   .ToList()
                   .ForEach(issue =>
                   {
                       ConsoleOutput.ErrorMessage(string.Format("{0} {1})", issue.GetMessage(), issue.Location.GetMappedLineSpan()));
                   });
        }

        static IEnumerable<string> FindDotNetAssemblies(string rootPath, bool recursiveSearch)
        {
            //TODO: Save details to disk + add stop and restore during process           
            ConsoleOutput.HeaderMessage("Scanning for .Net assemblies");
            if (recursiveSearch)
            {
                ConsoleOutput.Message("This will take some time if a high root folder has been selected");
            }

            var allAssemblies = DotNetAssemblyLocater.FindFiles(rootPath, ".exe;.dll", recursiveSearch).Where(x => DotNetAssemblyLocater.IsDotNetAssembly(x));
            ConsoleOutput.Message($"Found {allAssemblies.Count()} .Net assemblies");

            return allAssemblies;
        }

        static List<Diagnostic> AnalyzeDotNetAssemblies(List<string> projectFiles)
        {
            List<Diagnostic> issueList = new List<Diagnostic>();
            var msWorkspace = MSBuildWorkspace.Create();

            projectFiles.ToList().ForEach(x =>
            {
                try
                {
                    var project = msWorkspace.OpenProjectAsync(x).Result;
                    ConsoleOutput.SystemMessage($"Inspecting project {project.FilePath}");

                    var compilationWithAnalyzers = project.GetCompilationAsync().Result.WithAnalyzers(_analyzers.ToImmutableArray());
                    issueList.AddRange(compilationWithAnalyzers.GetAnalyzerDiagnosticsAsync().Result);
                }
                catch (Exception ex)
                {
                    ConsoleOutput.ErrorMessage($"Error loading {x} - '{ex.Message}'");
                }

            });

            return issueList;
        }
    }
}

