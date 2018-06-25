using Microsoft.CodeAnalysis;
using System.Collections.Immutable;
using System.Linq;

namespace Pwning.Posse.Common
{
    public enum DotNetVersion
    {
        
        None,
        DotNet1_0,
        DotNet1_1,
        DotNet2_0,
        DotNet3_0,
        DotNet3_5,
        DotNet4_0,
        DotNet4_5,
        DotNet4_6,
        DotNet4_6_2,
        DotNet4_7_1,
        DotNet4_7_2,
        NetStandard1_0,
        NetStandard1_1,
        NetStandard1_2,
        NetStandard1_3,
        NetStandard1_4,
        NetStandard1_5,
        NetStandard1_6,
        NetStandard2_0
    }
    public static class MetadataUtilities
    {
        private static string[] frameworkArray = new string[] {"netstandard1.0",
                                                                "netstandard1.1",
                                                                "netstandard1.2",
                                                                "netstandard1.3",
                                                                "netstandard1.4",
                                                                "netstandard1.5",
                                                                "netstandard1.6",
                                                                "netstandard2.0",
                                                                "v1.0",
                                                                "v1.1",
                                                                "v2.0",
                                                                "v3.0",
                                                                "v3.5",
                                                                "v4.0",
                                                                "v4.5",
                                                                "v4.6"};
        public static DotNetVersion LanguageToDotNetVersion(this ImmutableArray<MetadataReference> metadataReference)
        {
            var matchingString = frameworkArray.Where(x => metadataReference.Any(y => y.Display.Contains(x))).FirstOrDefault();

            //Yeah - I really don't know how accurate this is going to be against assemblies
            switch (matchingString.ToLower())
            {
                case "v1.0"             :   return DotNetVersion.DotNet1_0;
                case "v1.1"             :   return DotNetVersion.DotNet1_1;
                case "v2.0"             :   return DotNetVersion.DotNet2_0;
                case "v3.0"             :   return DotNetVersion.DotNet3_0;
                case "v3.5"             :   return DotNetVersion.DotNet3_5;
                case "v4.0"             :   return DotNetVersion.DotNet4_0;
                case "v4.5"             :   return DotNetVersion.DotNet4_5;
                case "v4.5.1"           :   return DotNetVersion.DotNet4_5;
                case "v4.5.2"           :   return DotNetVersion.DotNet4_5;
                case "v4.6"             :   return DotNetVersion.DotNet4_6;
                case "v4.6.1"           :   return DotNetVersion.DotNet4_6;
                case "netstandard1.0"   :   return DotNetVersion.NetStandard1_0;
                case "netstandard1.1"   :   return DotNetVersion.NetStandard1_1;
                case "netstandard1.2"   :   return DotNetVersion.NetStandard1_2;
                case "netstandard1.3"   :   return DotNetVersion.NetStandard1_3;
                case "netstandard1.4"   :   return DotNetVersion.NetStandard1_4;
                case "netstandard1.5"   :   return DotNetVersion.NetStandard1_5;
                case "netstandard1.6"   :   return DotNetVersion.NetStandard1_6;
                case "netstandard2.0"   :   return DotNetVersion.NetStandard2_0;           

                default: return DotNetVersion.None;
            }
        }
    }
}
