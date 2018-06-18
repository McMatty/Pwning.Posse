using CommandLine;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Pwning.Posse.CommandLine.Options
{

    enum InformationType
    {
        Services,
        Scanners
    }

    [Verb("list", HelpText = "List system information")]
    class ListOptions
    {
        [Option('i', "InformationType", Required = true, HelpText = "0=Services 1=Scanners")]
        public InformationType InformationType { get; set; }

        [Option('s', Default = false, HelpText = "Scans listed .net services")]
        public bool Scan { get; set; }
    }
}
