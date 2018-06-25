using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using Pwning.Posse.Analyzer.Tests.TestHelper;
using Pwning.Posse.Tracker;

namespace Pwning.Posse.Analyzer.Tests
{
    [TestClass]
    public class XXETrackerTest : CodeFixVerifier
    {
        //No diagnostics expected to show up
        [TestMethod]
        public void NoContent_NoErrorsDetected()
        {
            var test = @"";

            VerifyCSharpDiagnostic(test);
        }

        //Diagnostic and CodeFix both triggered and checked for
        [TestMethod]
        public void NotVulnerable_NoErrorsDetected()
        {
            var test = @"
using System;
using System.Xml;

namespace ConsoleApplication1
{
    public class CachedXmlResolver : XmlUrlResolver
    {
        public override object GetEntity(Uri absoluteUri, string role, Type ofObjectToReturn)
        {
            return base.GetEntity(absoluteUri, role, ofObjectToReturn);
        }

        public override Uri ResolveUri(Uri baseUri, string relativeUri)
        {
            return base.ResolveUri(baseUri, relativeUri);
        }
    }

    internal class XmlUtility
    {
        internal static XmlDocument ToXmlDocument(string xml)
        {
            var xmlDocument = new XmlDocument();  
            xmlDocument.XmlResolver = new XmlResolver();
            xmlDocument.LoadXml(xml);

            return xmlDocument;
        }
    }
}";           

            VerifyCSharpDiagnostic(test);                  
        }

        //Diagnostic and CodeFix both triggered and checked for
        [TestMethod]
        public void VulnerableAutoAssignment_InlineConstructor_ErrorsDetected()
        {
            var test = @"
using System;
using System.Xml;

namespace ConsoleApplication1
{
    public class CachedXmlResolver : XmlUrlResolver
    {
        public override object GetEntity(Uri absoluteUri, string role, Type ofObjectToReturn)
        {
            return base.GetEntity(absoluteUri, role, ofObjectToReturn);
        }

        public override Uri ResolveUri(Uri baseUri, string relativeUri)
        {
            return base.ResolveUri(baseUri, relativeUri);
        }
    }

    internal class XmlUtility
    {
        internal static XmlDocument ToXmlDocument(string xml)
        {
            var xmlDocument         = new XmlDocument();
            xmlDocument.XmlResolver = new CachedXmlResolver();
            xmlDocument.LoadXml(xml);

            return xmlDocument;
        }
    }
}";
            var expected = new DiagnosticResult
            {
                Id = "Vulnerability",
                Message = String.Format("'LoadXml' is open to XXE attacks. Running framework NetStandard1_3"),
                Severity = DiagnosticSeverity.Error,
                Locations =
                    new[] {
                            new DiagnosticResultLocation("Test0.cs", 26, 13)
                        }
            };

            VerifyCSharpDiagnostic(test, expected);
        }       

        protected override DiagnosticAnalyzer GetCSharpDiagnosticAnalyzer()
        {
            return new XXETracker();
        }
    }
}
