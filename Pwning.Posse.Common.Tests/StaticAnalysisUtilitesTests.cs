using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Net;
using System.Xml;

namespace Pwning.Posse.Common.Tests
{   
    public class StaticAnalysisUtilitesTests
    {       
        public void TestMethod1()
        {
            var xml = "";
            XmlUrlResolver resolver = new XmlUrlResolver();
            resolver.Credentials = CredentialCache.DefaultCredentials;

            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.XmlResolver = resolver;
            xmlDoc.LoadXml(xml);
        }
    }
}
