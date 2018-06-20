using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;

namespace Pwning.Posse.CommandLine
{
    public class FileUtilities
    {
        private static readonly string _assemblyDirectory;

        static FileUtilities()
        {
            string codeBase     = Assembly.GetExecutingAssembly().CodeBase;
            UriBuilder uri      = new UriBuilder(codeBase);
            string path         = Uri.UnescapeDataString(uri.Path);
            _assemblyDirectory  = Path.GetDirectoryName(path);
        }

        //https://stackoverflow.com/questions/52797/how-do-i-get-the-path-of-the-assembly-the-code-is-in
        public static string AssemblyDirectory
        {
            get { return _assemblyDirectory; }      
        }

        public static string GetFileHash(string filePath)
        {
            if (!File.Exists(filePath))
            {
                throw new ArgumentException($"{filePath} doesn't exist");
            }

            using (var md5      = MD5.Create())
            using (var stream   = File.OpenRead(filePath))
            {
                return BitConverter.ToString(md5.ComputeHash(stream)).Replace("-", "");
            }
        }

        public static string GetNugetDirectory(string fileName, bool createDirectory = true)
        {
            return GetSubDirectory("nuget", fileName, createDirectory);
        }

        public static string GetDecompileDirectory(string fileName, bool createDirectory = true)
        {
            return GetSubDirectory("decompiler", fileName, createDirectory);
        }

        //https://stackoverflow.com/questions/278439/creating-a-temporary-directory-in-windows
        public static string GetSubDirectory(string subDirectory, string fileName, bool createDirectory)
        {            
            //The hashcode is because the path may be different and have a different version
            var hashFileName        = string.Format("{0}+{1}", GetFileHash(fileName), Path.GetFileName(fileName));
            string tempDirectory    = Path.Combine(AssemblyDirectory, subDirectory, hashFileName);

            if(createDirectory) Directory.CreateDirectory(tempDirectory);

            return tempDirectory;
        }

        public static List<string> ExtractNugetAssemblies(string filePath)
        {
            //TODO:Add caching so we dont process files that have been previously processed
            if (!File.Exists(filePath))
            {
                throw new ArgumentException($"{filePath} doesn't exist");
            }

            if (!filePath.EndsWith(".nupkg"))
            {
                throw new ArgumentException($"{filePath} is not a nupkg file.");
            }
            var decompileOutputPath     = GetNugetDirectory(filePath);
            List<string> assemblyPaths  = new List<string>();

            using (FileStream fs        = new FileStream(filePath, FileMode.Open))
            using (ZipArchive archive   = new ZipArchive(fs))
            {
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    if (entry.FullName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                    {
                        var fileName        = Path.GetFileName(entry.FullName);
                        var subDirectory    = Path.Combine(decompileOutputPath, Path.GetDirectoryName(entry.FullName));
                        Directory.CreateDirectory(subDirectory);
                        var extractDestination = Path.Combine(subDirectory, fileName);

                        assemblyPaths.Add(extractDestination);
                        entry.ExtractToFile(extractDestination, true);
                    }
                }
            }

            return assemblyPaths;
        }
    }
}
