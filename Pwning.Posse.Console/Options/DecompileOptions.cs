using CommandLine;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Pwning.Posse.CommandLine.Options
{
    [Verb("decompile", HelpText = "Decompile an assembly into source code")]
    class DecompileOptions
    {
        [Option(Required = true, HelpText = "Path to .Net assembly")]
        public string Path { get; set; }

        [Option('s', Required = false, HelpText = "Performs scanning on decompiled .Net assembly")]
        public bool ScanOutput { get; set; }
    }
}
