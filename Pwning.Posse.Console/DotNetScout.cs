using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

namespace Pwning.Posse.CommandLine
{
    class DotNetScout
    {
        public static bool IsDotNetAssembly(string path)
        {
            var isDotNetAssembly = true;
            try
            {
                AssemblyName testAssembly = AssemblyName.GetAssemblyName(path);
            }            
            catch (BadImageFormatException)
            {
                isDotNetAssembly = false;
            }
            catch(FileLoadException ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Error yo {ex.Message}");
                Console.ResetColor();

                //Triggered by permissions
                //TODO: Add verbose logging
                isDotNetAssembly = false;
            }

            return isDotNetAssembly;
        }

        public static List<string> FindFiles(string currentFolder)
        {
            Console.WriteLine($"Searching {currentFolder}");

            List<string> fileList = new List<string>(Directory.GetFiles(currentFolder)
                .Where(x => x.EndsWith(".dll") || x.EndsWith(".exe"))
                .Where(path => IsDotNetAssembly(path)));

            Directory.GetDirectories(currentFolder).AsParallel().ForAll(x =>
            {
                try
                {
                    fileList.AddRange(FindFiles(x));
                }
                catch (Exception ex)
                {
                    //TODO: Remove console reference - provide a hook for exception gathering
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Error yo {ex.Message}");
                    Console.ResetColor();
                }
            });

            return fileList;
        }
    }
}
