using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Pwning.Posse.CommandLine
{
    public class FileUtilities
    {
        //https://stackoverflow.com/questions/278439/creating-a-temporary-directory-in-windows
        public static string GetTemporaryDirectory()
        {
            string tempDirectory = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            Directory.CreateDirectory(tempDirectory);

            return tempDirectory;
        }
    }
}
