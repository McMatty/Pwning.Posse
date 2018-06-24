using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Pwning.Posse.Common;
using Pwning.Posse.Tracker.Analyzers.XXETracker;
using System.Collections.Immutable;
using System.Linq;

namespace Pwning.Posse.Tracker
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class XXETracker : DiagnosticAnalyzer
    {
        private static string _namespace        = "System.Xml.XmlDocument";
        private static string _methodName       = "LoadXml";
        private static string _dtdProcessing    = "DtdProcessing";
        private static string _dtdProhibit      = "DtdProcessing.Prohibit";

        // You can change these strings in the Resources.resx file. If you do not want your analyzer to be localize-able, you can use regular strings for Title and MessageFormat.
        // See https://github.com/dotnet/roslyn/blob/master/docs/analyzers/Localizing%20Analyzers.md for more on localization
        private static readonly LocalizableString Title             = new LocalizableResourceString(nameof(Resources.AnalyzerTitle), Resources.ResourceManager, typeof(Resources));
        private static readonly LocalizableString MessageFormat     = new LocalizableResourceString(nameof(Resources.AnalyzerMessageFormat), Resources.ResourceManager, typeof(Resources));
        private static readonly LocalizableString Description       = new LocalizableResourceString(nameof(Resources.AnalyzerDescription), Resources.ResourceManager, typeof(Resources));
        private const string Category                               = "XML";
        public const string DiagnosticId                            = "Vulnerability";
        
        private static DiagnosticDescriptor Rule = new DiagnosticDescriptor(DiagnosticId, Title, MessageFormat, Category, DiagnosticSeverity.Error, isEnabledByDefault: true, description: Description);
       
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get { return ImmutableArray.Create(Rule); } }

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(AnalyzeSyntax, SyntaxKind.InvocationExpression);
        }

        private static void AnalyzeSyntax(SyntaxNodeAnalysisContext context)
        {
            // TODO: Replace the following code with your own analysis, generating Diagnostic objects for any issues you find
            var symbol          = context.SemanticModel.GetSymbolInfo(context.Node);
            var namedTypeSymbol = symbol.Symbol as IMethodSymbol;
            bool isVulnerable   = false;

            //Find XMLDocument and checks if it is configured in a vulnerable manner         
            if (StaticAnalysisUtilites.IsClassAndMethod(namedTypeSymbol, _namespace, _methodName))
            {
                var referenceLocation           = context.Node.GetLocation();
                var deserializationInvocations  = StaticAnalysisUtilites.FindMemberInnvocation(referenceLocation, _dtdProcessing);
                var dtdProcessing               = StaticAnalysisUtilites.FindLocalAssignmentExpressionSyntax(referenceLocation, _dtdProcessing);

                isVulnerable = (deserializationInvocations == null || deserializationInvocations.Count() <= 0);
                isVulnerable &= (dtdProcessing == null || dtdProcessing.Right.IsKind(SyntaxKind.NullLiteralExpression));
            }

            if (isVulnerable)
            {
                var location = context.Node.GetLocation();
                var diagnostic = Diagnostic.Create(Rule, location, namedTypeSymbol.Name);

                context.ReportDiagnostic(diagnostic);
            }
        }
    }
}
