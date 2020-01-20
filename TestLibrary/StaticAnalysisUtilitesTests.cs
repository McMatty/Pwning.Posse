using System.Net;

namespace Pwning.Posse.Common.Tests
{
    public class StaticAnalysisUtilitesTests
    {
        public void TestMethod1()
        {
            var credentials = new NetworkCredential("noreply@pumasecurity.io", "supersecretpassword");
            _ = credentials.UserName;
        }
    }
}
