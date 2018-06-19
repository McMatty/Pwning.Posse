using System;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Collections.Generic;

namespace Pwning.Posse.CommandLine
{
    public class FileUtilities
    {
        //https://stackoverflow.com/questions/52797/how-do-i-get-the-path-of-the-assembly-the-code-is-in
        public static string AssemblyDirectory
        {
            get
            {
                string codeBase     = Assembly.GetExecutingAssembly().CodeBase;
                UriBuilder uri      = new UriBuilder(codeBase);
                string path         = Uri.UnescapeDataString(uri.Path);

                return Path.GetDirectoryName(path);
            }
        }

        public static string GetNugetDirectory(string fileName)
        {
            return GetSubDirectory("Nuget", fileName);
        }

        public static string GetDecompileDirectory(string fileName)
        {
            return GetSubDirectory("decompiler", fileName);
        }

        //https://stackoverflow.com/questions/278439/creating-a-temporary-directory-in-windows
        public static string GetSubDirectory(string subDirectory, string fileName)
        {
            //TODO: Add file hasing to generate path or something so assemblies are unique
            //The hashcode is because the path may be different and have a different version
            string tempDirectory = Path.Combine(AssemblyDirectory, subDirectory, fileName.GetHashCode().ToString("X8"), Path.GetFileName(fileName)); 
            Directory.CreateDirectory(tempDirectory);

            return tempDirectory;
        }

        public static List<string> ExtractNugetAssemblies(string filePath)
        {
            if (!File.Exists(filePath))
            {
                throw new ArgumentException($"{filePath} doesn't exist");
            }

            if (!filePath.EndsWith(".nupkg"))
            {
                throw new ArgumentException($"{filePath} is not a nupkg file.");
            }

            List<string> assemblyPaths  = new List<string>();
            using(FileStream fs         = new FileStream(filePath, FileMode.Open))
            using (ZipArchive archive   = new ZipArchive(fs))
            {
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    if (entry.FullName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                    {
                        var fileName            = Path.GetFileName(entry.FullName);                      
                        var decompileOutputPath = GetNugetDirectory(filePath);
                        var subDirectory        = Path.Combine(decompileOutputPath, Path.GetDirectoryName(entry.FullName));
                        Directory.CreateDirectory(subDirectory);
                        var extractDestination  = Path.Combine(subDirectory, fileName);
                        assemblyPaths.Add(extractDestination);
                        entry.ExtractToFile(extractDestination, true);
                    }
                }
            }

            return assemblyPaths;
        }
    }
}
