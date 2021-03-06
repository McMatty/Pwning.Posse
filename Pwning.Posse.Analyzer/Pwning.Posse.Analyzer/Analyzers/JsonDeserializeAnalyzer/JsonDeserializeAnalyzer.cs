using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Pwning.Posse.Analyzer.Analyzers.JsonDeserializeAnalyzer;
using Pwning.Posse.Common;
using System;
using System.Collections.Immutable;
using System.Linq;

namespace Pwning.Posse.Analyzer
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class JsonDeserializeAnalyzer : DiagnosticAnalyzer
    {
        private const string _typeName                                  = "TypeNameHandling";
        private static readonly string[] _vulnerabletypeNameSettings    =  {"TypeNameHandling.Auto",  "TypeNameHandling.Objects", "TypeNameHandling.All"};       
        private const string _binderSetting                             = "SerializationBinder";
        private const string _serializerSettings                        = "JsonSerializerSettings";
        private const string _methodName                                = "DeserializeObject";
        private const string _namespace                                 = "Newtonsoft.Json.JsonConvert";
        private static string _binderInterface                          = "Newtonsoft.Json.Serialization.ISerializationBinder";

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

        //This will evaluate code created with an inline constructor to assigned properties for a JsonSerializerSettings
        //e.g Deserialize(payload, new JsonSerializerSettings(){TypeNameHandling = TypeNameHandling.Auto})
        //Will evaluate if the TypeNameHandling.Auto has been assigned which will make code vulnerable
        //Then evaluate if a type with the ISerializationBinder has been assigned to settings which will mitigate the risk if TypeNameHandling.Auto assigned
        private static bool VulnerableInlineConstructor(ExpressionSyntax settingsArgument, SyntaxNodeAnalysisContext context)
        {
            //Inline constructor         
            var isVulnerable = false;

            if (settingsArgument != null && settingsArgument.IsKind(SyntaxKind.ObjectCreationExpression))
            {
                var hasAutoTypeSetting  = StaticAnalysisUtilites.IsAssignedValue(settingsArgument, _typeName, _vulnerabletypeNameSettings);
                var hasSerialBinder     = StaticAnalysisUtilites.IsAssignedInterface(settingsArgument, context, _binderInterface);
                isVulnerable            = hasAutoTypeSetting && !hasSerialBinder;
            }

            return isVulnerable;
        }

        //This will evaluate code created with an inline constructor to assigned properties for a JsonSerializerSettings
        //e.g Deserialize(payload, new JsonSerializerSettings(){TypeNameHandling = TypeNameHandling.Auto})
        //Will evaluate if the TypeNameHandling.Auto has been assigned which will make code vulnerable
        //Then evaluate if a type with the ISerializationBinder has been assigned to settings which will mitigate the risk if TypeNameHandling.Auto assigned
        private static bool VulnerableFieldConstructor(ExpressionSyntax settingsArgument, SyntaxNodeAnalysisContext context)
        {
            //Inline constructor         
            var isVulnerable = false;

            if (settingsArgument != null && settingsArgument.IsKind(SyntaxKind.IdentifierName))
            {
                var declaration    = context.SemanticModel.GetSymbolInfo(settingsArgument).Symbol;
                var variableType   = StaticAnalysisUtilites.GetTypeFromDeclaration(declaration);

                if (variableType.Name.Equals(_serializerSettings))
                {
                    var location            = (declaration as IFieldSymbol).Locations.First();
                    var declearationNode    = StaticAnalysisUtilites.FindDeclearationNode(location);
                    var hasAutoTypeSetting  = StaticAnalysisUtilites.IsAssignedValue(declearationNode, _typeName, _vulnerabletypeNameSettings);
                    var hasSerialBinder     = StaticAnalysisUtilites.IsAssignedInterface(declearationNode, context, _binderInterface);
                    isVulnerable            = hasAutoTypeSetting && !hasSerialBinder;
                }
            }

            return isVulnerable;
        }

        //This will evaluate code created that has not used an inline constructor to assigned properties for a JsonSerializerSettings
        //e.g object.property = value;
        //Will evaluate if the TypeNameHandling.Auto has been assigned which will make code vulnerable
        //Then evaluate if a type with the ISerializationBinder has been assigned to settings which will mitigate the risk if TypeNameHandling.Auto assigned
        private static bool VulnerablePropertySet(ExpressionSyntax settingsArgument, SyntaxNodeAnalysisContext context)
        {
            var isVulnerable = false;

            if (settingsArgument != null && settingsArgument.IsKind(SyntaxKind.IdentifierName))
            {
                var localDeclaration    = context.SemanticModel.GetSymbolInfo(settingsArgument).Symbol;
                var variableType        = StaticAnalysisUtilites.GetTypeFromDeclaration(localDeclaration);

                if (variableType.Name.Equals(_serializerSettings))
                {
                    var location            = settingsArgument.GetLocation();
                    var typeHandlerSetting  = StaticAnalysisUtilites.FindLocalAssignmentExpressionSyntax(location, _typeName);
                    var binderSetting       = StaticAnalysisUtilites.FindLocalAssignmentExpressionSyntax(location, _binderSetting);
                    var hasAutoTypeSetting  = StaticAnalysisUtilites.IsAssignedValue(typeHandlerSetting, _typeName, _vulnerabletypeNameSettings);
                    var hasSerialBinder     = StaticAnalysisUtilites.IsAssignedInterface(binderSetting, context, _binderInterface);
                    isVulnerable            = hasAutoTypeSetting && !hasSerialBinder;
                }
            }

            return isVulnerable;
        }

        private static void AnalyzeSyntax(SyntaxNodeAnalysisContext context)
        {
            // TODO: Replace the following code with your own analysis, generating Diagnostic objects for any issues you find
            var symbol          = context.SemanticModel.GetSymbolInfo(context.Node);
            var namedTypeSymbol = symbol.Symbol as IMethodSymbol;

            // Find just those named type symbols with names containing lowercase letters.
            if (StaticAnalysisUtilites.IsClassAndMethod(namedTypeSymbol, _namespace, _methodName))
            {
                var isVulnerable            = false;
                var invocationExpression    = context.Node as InvocationExpressionSyntax;

                if (invocationExpression.ArgumentList.Arguments.Count.Equals(2))
                {
                    try
                    {
                        var settingsArgument = invocationExpression.ArgumentList.Arguments[1].Expression;
                        var declaration = context.SemanticModel.GetSymbolInfo(settingsArgument).Symbol;

                        //TODO: Setup a state object here for field types
                        switch (declaration.Kind)
                        {
                            case SymbolKind.Field:
                                isVulnerable = VulnerableFieldConstructor(settingsArgument, context);
                                break;
                            case SymbolKind.Method:
                            case SymbolKind.Local:
                                isVulnerable = VulnerableInlineConstructor(settingsArgument, context) || VulnerablePropertySet(settingsArgument, context);
                                break;
                        }
                    }
                    catch(Exception ex)
                    {
                        var exceptionMessage = ex.InnerException != null ? ex.InnerException.Message : ex.Message;                        
                        throw new Exception($"The error '{exceptionMessage}' occured while parsing {context.Node.SyntaxTree.FilePath}");
                    }
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
}
