using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;


namespace Pwning.Posse.CommandLine
{
    class DotNetScout
    {
        public static bool IsFileType(string path, string fileFilter)
        {
            var filters = fileFilter.Split(';');
            var isMatch = filters.All(x => path.EndsWith(x));

            return isMatch;
        }
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
                //Triggered by permissions
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Error yo {ex.Message}");
                Console.ResetColor();
               
                //TODO: Add verbose logging
                isDotNetAssembly = false;
            }

            return isDotNetAssembly;
        }        

        public static List<string> FindFiles(string currentFolder, string fileFilter)
        {
            Console.WriteLine($"Searching {currentFolder}");

            List<string> fileList = new List<string>(Directory.GetFiles(currentFolder).Where(x => IsFileType(x, fileFilter)));

            Directory.GetDirectories(currentFolder).AsParallel().ForAll(x =>
            {
                try
                {
                    fileList.AddRange(FindFiles(x, fileFilter));
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
