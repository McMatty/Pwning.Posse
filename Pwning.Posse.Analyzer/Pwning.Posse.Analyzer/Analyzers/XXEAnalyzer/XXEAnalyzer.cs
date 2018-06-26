using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Pwning.Posse.Analyzer.Analyzers.XXEAnalyzer;
using Pwning.Posse.Common;
using System.Collections.Immutable;
using System.Linq;

namespace Pwning.Posse.Analyzer
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class XXEAnalyzer : DiagnosticAnalyzer
    {
        private static string _namespace            = "System.Xml.XmlDocument";
        private static string _methodName           = "LoadXml";
        private static string _xmlResolver          = "XmlResolver";
        private static string _baseXmlResolverClass = "XmlUrlResolver";

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

        private static bool VulnerablePropertySet(SyntaxNodeAnalysisContext context)
        {
            var isVulnerable = false;

            var referenceLocation       = context.Node.GetLocation();
            var xmlResolver             = StaticAnalysisUtilites.FindLocalAssignmentExpressionSyntax(referenceLocation, _xmlResolver);
            var dotNetVersion           = context.Compilation.ExternalReferences.LanguageToDotNetVersion();     
           
            isVulnerable = !(xmlResolver == null || xmlResolver.Right.IsKind(SyntaxKind.NullLiteralExpression));

            return isVulnerable;
        }

        private static bool VulnerableInlineConstructor(SyntaxNode xmlDocumentInstance, SyntaxNodeAnalysisContext context)
        {
            var isVulnerable = false;

            var declaration     = context.SemanticModel.GetSymbolInfo(xmlDocumentInstance).Symbol;
            var declarationNode = StaticAnalysisUtilites.FindDeclearationNode(declaration.Locations.First());
            isVulnerable        = StaticAnalysisUtilites.IsAssignedNewObjectInline(declarationNode, context, _xmlResolver, _baseXmlResolverClass);          
                 
            return isVulnerable;
        }

        private static void AnalyzeSyntax(SyntaxNodeAnalysisContext context)
        {          
            var symbol              = context.SemanticModel.GetSymbolInfo(context.Node);
            var namedTypeSymbol     = symbol.Symbol as IMethodSymbol;
            bool isVulnerable       = false;
            bool vulnerableInline   = false;

            //Find XMLDocument and checks if it is configured in a vulnerable manner         
            if (StaticAnalysisUtilites.IsClassAndMethod(namedTypeSymbol, _namespace, _methodName))
            {
                var dotNetVersion               = context.Compilation.ExternalReferences.LanguageToDotNetVersion();
                if (context.Node.IsKind(SyntaxKind.InvocationExpression))
                {
                    var expression  = context.Node as InvocationExpressionSyntax;
                    var declaration = StaticAnalysisUtilites.RetrieveMethodOwningObject(expression);
                    vulnerableInline    = VulnerableInlineConstructor(declaration, context);
                }              

                isVulnerable  = (dotNetVersion < DotNetVersion.DotNet4_6);
                isVulnerable |= VulnerablePropertySet(context) || vulnerableInline;

                if (isVulnerable)
                {
                    var location    = context.Node.GetLocation();
                    var diagnostic  = Diagnostic.Create(Rule, location, namedTypeSymbol.Name, dotNetVersion.ToString());

                    context.ReportDiagnostic(diagnostic);
                }
            }           
        }
    }
}
