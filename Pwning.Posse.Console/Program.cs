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

namespace Pwning.Posse.CommandLine
{
    class Program
    {
        [DllImport("user32.dll")]
        public static extern bool ShowWindow(System.IntPtr hWnd, int cmdShow);

        private static Dictionary<String, String> _userOptions = new Dictionary<string, string>();
        private static List<string> _validOptions = new List<string> {"sln_folder"};

        static void RenderMenu()
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine("Select one of the options below:");
            Console.WriteLine("1. Scan machine for .Net assemblies");
            Console.WriteLine("2. Scan target .Net assembly for vulnerabilities");
            Console.WriteLine("3. List services running .Net assemblies");
            Console.WriteLine("4. Set console options");
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
                            if (_userOptions.ContainsKey("sln_folder"))
                            {
                                FindDotNetVulnerabilities(_userOptions["sln_folder"]);
                            }
                            else
                            {
                                Console.WriteLine("'sln_folder' not set. Defaulting to root folder.");
                                var solutionFolder = Directory.GetDirectoryRoot(Assembly.GetExecutingAssembly().Location);
                                FindDotNetVulnerabilities(solutionFolder);
                            }
                            
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

                if (isDotNet) Console.ForegroundColor = ConsoleColor.Green;
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
                    isSystem32              = serviceDirectory.Equals(@"C:\Windows\system32", StringComparison.OrdinalIgnoreCase);
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

        static void FindDotNetVulnerabilities(string solutionPath)
        {
            if(string.IsNullOrEmpty(solutionPath) || !Directory.Exists(solutionPath))
            {
                Console.WriteLine($"{solutionPath} is not a valid path");
                return;
            }

            Console.WriteLine($"Looking for possible deserialization vulnerabilities under {solutionPath}");
            Console.WriteLine();
            var issuesFound = AnalyzeDotNetAssembly(solutionPath);
            
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
                Console.WriteLine($"No solution files found in {solutionPath}");
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

        static List<Diagnostic> AnalyzeDotNetAssembly(string solutionPath)
        {  
            var solutionFiles           = DotNetScout.FindFiles(solutionPath, ".sln");
            List<Diagnostic> issueList  = new List<Diagnostic>();

            solutionFiles.ToList().ForEach(x =>
            {                
                var msWorkspace     = MSBuildWorkspace.Create();
                var solution        = msWorkspace.OpenSolutionAsync(x).Result;

                Console.WriteLine($"Inspecting solution {solution.FilePath}");

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
