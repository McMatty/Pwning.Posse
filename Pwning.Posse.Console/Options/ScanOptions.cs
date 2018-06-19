using CommandLine;

namespace Pwning.Posse.CommandLine.Options
{
    public enum FileType
    {       
        Assemblies,
        Nuget,
        Project
    }

    [Verb("scan", HelpText = "Scan source code for security vulnerability")]
    class ScanOptions
    {
        [Option(Required = true, HelpText = "Search path for file type")]
        public string Path { get; set; }

        [Option('f', "FileType", HelpText = "File type that will be scanned when found", Default = FileType.Assemblies)]
        public FileType FileType { get; set; }

        [Option('r', "recursive", Default = false, HelpText = "Perform recursive search of sub folders")]
        public bool Recursive { get; set; }
    }
}
