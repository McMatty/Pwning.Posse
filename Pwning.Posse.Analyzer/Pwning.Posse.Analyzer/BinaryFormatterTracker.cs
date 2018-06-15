using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Pwning.Posse.Common;
using System.Collections.Immutable;
using System.Linq;

namespace Pwning.Posse.Tracker
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class BinaryFormatterTracker : DiagnosticAnalyzer
    {
        private const string _namespace     = "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter";
        private const string _methodName    = "Deserialize";
        private const string _binderSetting = "Binder";

        // You can change these strings in the Resources.resx file. If you do not want your analyzer to be localize-able, you can use regular strings for Title and MessageFormat.
        // See https://github.com/dotnet/roslyn/blob/master/docs/analyzers/Localizing%20Analyzers.md for more on localization
        private static readonly LocalizableString Title             = new LocalizableResourceString(nameof(Resources.AnalyzerTitle), Resources.ResourceManager, typeof(Resources));
        private static readonly LocalizableString MessageFormat     = new LocalizableResourceString(nameof(Resources.AnalyzerMessageFormat), Resources.ResourceManager, typeof(Resources));
        private static readonly LocalizableString Description       = new LocalizableResourceString(nameof(Resources.AnalyzerDescription), Resources.ResourceManager, typeof(Resources));
        private const string Category                               = "Deserialization";
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

            //Find binaryformatter and checks if is configured in a vulnerable manner
            //TODO: Write code to determine if it is exploitable (Data flows from users to the formatter - file paths, data etc)
            if (namedTypeSymbol != null && namedTypeSymbol.Name.Equals(_methodName) && namedTypeSymbol.ReceiverType.ToString().Equals(_namespace))
            {
                var referenceLocation           = context.Node.GetLocation();
                var deserializationInvocations  = StaticAnalysisUtilites.FindMemberInnvocation(referenceLocation, _methodName);
                var binder                      = StaticAnalysisUtilites.FindAssignmentExpressionSyntax(referenceLocation, "Binder");

                isVulnerable = (deserializationInvocations != null && deserializationInvocations.Count() > 0);
                isVulnerable &=  (binder == null || binder.Right.IsKind(SyntaxKind.NullLiteralExpression));                
            }

            if (isVulnerable)
            {
                    var location    = context.Node.GetLocation();
                    var diagnostic  = Diagnostic.Create(Rule, location, namedTypeSymbol.Name);

                    context.ReportDiagnostic(diagnostic);
            }            
        }
    }
}
