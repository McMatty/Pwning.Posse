using CommandLine;

namespace Pwning.Posse.CommandLine.Options
{
    public enum InformationType
    {       
        Services = 0,
        Scanners
    }

    [Verb("list", HelpText = "List system information")]
    class ListOptions
    {
        [Option('i', "InformationType", Required = true, HelpText = "List .net services or  available scanners", Default =InformationType.Services)]
        public InformationType InformationType { get; set; }

        [Option('s', Default = false, HelpText = "Scans listed .net services")]
        public bool Scan { get; set; }
    }
}
