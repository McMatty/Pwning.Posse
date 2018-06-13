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

namespace Pwning.Posse.CommandLine
{
    class Program
    {
        static void Main(string[] args)
        {            
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine("Select one of the options below:");
            Console.WriteLine("1. Scan machine for .Net assemblies");
            Console.WriteLine("2. Scan target .Net assembly for vulnerabilities");
            Console.WriteLine("3. List services running .Net assemblies");
            Console.WriteLine("0. Exit");
            Console.ResetColor();

            bool exit = false;
            while (!exit)
            {
                Console.WriteLine();
                char option = Console.ReadKey().KeyChar;
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
                            //TODO: Save details to disk + add stop and restore during process
                            Console.ForegroundColor = ConsoleColor.DarkGreen;
                            Console.WriteLine("Scanning for all .Net assemblies. This will take some time.");
                            Console.ResetColor();

                            var allAssemblies = FindAllDotNetAssemblies();
                            Console.WriteLine($"Found {allAssemblies.Count()} .Net assemblies");
                            break;
                        }
                    case '2':
                        {
                            FindDotNetVulnerabilities();
                            break;
                        }                    
                    case '3':
                        {
                            ManagementObject wmiService = null;
                            try
                            {
                                ServiceController.GetServices()
                                    .Where(x => x.Status == ServiceControllerStatus.Running)
                                    .Where(y => {
                                                wmiService = new ManagementObject($"Win32_Service.Name='{y.ServiceName}'");
                                                wmiService.Get();

                                                var isSystem32 = false;
                                                
                                                try
                                                {
                                                    var servicePath      = wmiService["PathName"].ToString();
                                                    var serviceDirectory = Path.GetDirectoryName(servicePath);
                                                    isSystem32 = serviceDirectory.Equals(@"C:\Windows\system32", StringComparison.OrdinalIgnoreCase);
                                                }
                                                catch
                                                {
                                                    //TODO: Log exception - get real exception type
                                                    isSystem32 = true;
                                                }

                                                return wmiService["StartName"]!= null && wmiService["StartName"].ToString().Contains("LocalSystem") && !isSystem32;
                                    })
                                    .ToList()                                    
                                    .ForEach(svc =>
                                    {
                                        wmiService = new ManagementObject($"Win32_Service.Name='{svc.ServiceName}'");
                                        wmiService.Get();
                                        Console.WriteLine("{2,-30}{0,-30}{1, 0}", svc.ServiceName, wmiService["PathName"], wmiService["StartName"]);

                                        var servicePath = wmiService["PathName"].ToString();
                                        var exePath     = servicePath.Substring(0, servicePath.IndexOf(".exe") + 4);
                                        var isDotNet    = DotNetScout.IsDotNetAssembly(exePath);

                                        if (isDotNet) Console.WriteLine("Found .Net assembly");
                                    });
                            }
                            finally
                            {
                                if (wmiService != null) wmiService.Dispose();
                            }

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
            }
        }   
        
        static void FindDotNetVulnerabilities(string solutionPath = @"C:\Temp\DuckCreek\")
        {
            Console.WriteLine("Looking for possible deserialization vulnerabilities");
            Console.WriteLine();
            var issuesFound = AnalyzeDotNetAssembly(solutionPath);
            
            if (issuesFound.Count > 0)
            {                
                Console.ForegroundColor = ConsoleColor.Red;             

                issuesFound                    
                    .AsParallel()
                    .ForAll(issue =>
                    {
                        Console.WriteLine("{2,-30}{2,-30}{0,-30}@({1, 0})", issue.GetMessage(), issue.Location.GetMappedLineSpan(), String.Empty);
                    });
                Console.ResetColor();
            }            
        }

        static List<string> FindAllDotNetAssemblies()
        {
            var rootPath        = Directory.GetDirectoryRoot(Assembly.GetExecutingAssembly().Location);
            var allAssemblies   = DotNetScout.FindFiles(rootPath);

            return allAssemblies;
        }

        static List<Diagnostic> AnalyzeDotNetAssembly(string solutionPath)
        {            
            var sln                     = solutionPath;
            var solutionFiles           = Directory.GetFiles(sln, "*.sln", SearchOption.AllDirectories);
            List<Diagnostic> issueList  = new List<Diagnostic>();

            solutionFiles.ToList().ForEach(x =>
            {
                var msWorkspace     = MSBuildWorkspace.Create();
                var solution        = msWorkspace.OpenSolutionAsync(x).Result;

                foreach (var project in solution.Projects)
                {
                    DiagnosticAnalyzer analyzer     = new BinaryFormatterTracker();                    
                    var compilationWithAnalyzers    = project.GetCompilationAsync().Result.WithAnalyzers(ImmutableArray.Create(analyzer));
                    issueList.AddRange(compilationWithAnalyzers.GetAnalyzerDiagnosticsAsync().Result);
                }
            });

            return issueList;
        }
    }
}
