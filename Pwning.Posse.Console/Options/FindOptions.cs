using CommandLine;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Pwning.Posse.CommandLine.Options
{
    [Verb("find", HelpText = "Find a .Net assembly")]
    class FindOptions
    {
        [Option('s', Default = false, HelpText = "Save output to 'paths.txt'")]
        public bool Save { get; set; }

        [Option('r', "recursive", Default = false, HelpText = "Perform recursive search of sub folders")]
        public bool Recursive { get; set; }

        [Option(Required = true, HelpText = "Folder to search for .net assembly")]
        public string Path { get; set; }
    }
}
