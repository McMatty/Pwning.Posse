using CommandLine;

namespace Pwning.Posse.CommandLine.Options
{
    [Verb("scan", HelpText = "Scan source code for security vulnerability")]
    class ScanOptions
    {
        [Option(Required = true, HelpText = "Path to containing folder of .csproj")]
        public string Path { get; set; }

        [Option('r', "recursive", Default = false, HelpText = "Perform recursive search of sub folders")]
        public bool Recursive { get; set; }
    }
}
