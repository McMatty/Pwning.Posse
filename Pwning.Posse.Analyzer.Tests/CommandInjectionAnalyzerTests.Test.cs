using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Pwning.Posse.Analyzer.Tests.TestHelper;
using System;

namespace Pwning.Posse.Analyzer.Tests
{
    [TestClass]
    public class CommandInjectionAnalyzerTests : CodeFixVerifier
    {
        //No diagnostics expected to show up
        [TestMethod]
        public void NoContent_NoErrorsDetected()
        {
            var test = @"";

            VerifyCSharpDiagnostic(test);
        }        

        protected override DiagnosticAnalyzer GetCSharpDiagnosticAnalyzer()
        {
            return new CommandInjectionAnalyzer();
        }
    }
}
