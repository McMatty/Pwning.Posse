using System.IO;

namespace Pwning.Posse.CommandLine
{
    public class FileUtilities
    {
        //https://stackoverflow.com/questions/278439/creating-a-temporary-directory-in-windows
        public static string GetTemporaryDirectory(string fileName)
        {
            string tempDirectory = Path.Combine(Path.GetTempPath(), fileName.GetHashCode().ToString()); ;
            Directory.CreateDirectory(tempDirectory);

            return tempDirectory;
        }
    }
}
