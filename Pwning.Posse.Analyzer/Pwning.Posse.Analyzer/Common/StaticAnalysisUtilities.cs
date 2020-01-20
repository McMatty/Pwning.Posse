using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using System.Linq;

namespace Pwning.Posse.Common
{
    public static class StaticAnalysisUtilites
    {
        public static bool IsClassAndMethod(IMethodSymbol namedTypeSymbol, string @namespace, string method)
        {
            return namedTypeSymbol != null && namedTypeSymbol.Name.Equals(method) && namedTypeSymbol.ReceiverType.ToString().Equals(@namespace);
        }        

        //Checks for an expected assignment (only useful for enums which have a set of possible values)
        //Checks the left property is being assigned the expected propert on the right
        public static bool IsAssignedValue(SyntaxNode argument, string left, string[] right)
        {
            return argument.DescendantNodesAndSelf()
                            .OfType<AssignmentExpressionSyntax>()
                            .Any(x => x.Left.ToString().Contains(left) && right.Contains(x.Right.ToString()));
        }

        //Checks that argument being assigned is being assigned a class that implements the ISerializationBinder interface
        //TODO: Very brittle check - should be updated later
        public static bool IsAssignedInterface(SyntaxNode argument, SyntaxNodeAnalysisContext context, string interfaceName)
        {
            if (argument == null) return false;

            return argument.DescendantNodesAndSelf()
                            .OfType<AssignmentExpressionSyntax>()
                            .Any(x =>
                            {
                                var symbol = context.SemanticModel.GetSymbolInfo(x.Right).Symbol;
                                if (symbol == null) return false;

                                var symbolType = GetTypeFromDeclaration(symbol);
                                return symbolType.AllInterfaces.Any(@interface => @interface.OriginalDefinition.ToDisplayString().Equals(interfaceName));
                            });
        }

        //TODO: Very brittle check - should be updated later
        //Jesus - this feels wrong
        //Attempting to get the base class of the object being assigned
        public static bool IsAssignedNewObjectInline(SyntaxNode argument, SyntaxNodeAnalysisContext context, string propertyName, string baseClassName)
        {
            if (argument == null) return false;

            //Step 1 Take a node and look for an assignment. The initial argument should be an object creation as this purpose
            //is to find assignments in object initializers
            return argument.DescendantNodes().OfType<AssignmentExpressionSyntax>()
                                             .Any(x =>
                                             {
                                                 //Step2. Due the scatter gun method of search ensure that the property matches the target being searched for
                                                 var identifier = x.Left as IdentifierNameSyntax;
                                                 if (identifier == null || !identifier.Identifier.ToString().Equals(propertyName))
                                                 {
                                                     return false;
                                                 }

                                                 //Step3. The assignment should be an object creation (property assignment is already covered)
                                                 var objectCreation = x.Right as ObjectCreationExpressionSyntax;
                                                 var symbol         = context.SemanticModel.GetSymbolInfo(objectCreation.Type).Symbol;
                                                 if (symbol == null) return false;

                                                 //Step4 determine the class definition of the object being created.
                                                 //Then search the base classes for the type that is used to assign to the inline property
                                                 var classSyntax = symbol.DeclaringSyntaxReferences.First().GetSyntax() as ClassDeclarationSyntax;
                                                 return classSyntax.BaseList
                                                                 .Types
                                                                 .Any(baseClass => baseClass.ToString().Equals(baseClassName));
                                             });
        }

        public static ITypeSymbol GetTypeFromDeclaration(ISymbol variable)
        {
            ITypeSymbol type = null;
            switch (variable.Kind)
            {
                case SymbolKind.Field:
                    type = ((IFieldSymbol)variable).Type;
                    break;
                case SymbolKind.Local:
                    type = ((ILocalSymbol)variable).Type;
                    break;               
            }

            return type;
        }

        //This is supposed to be feed from a declaration value - so we only go up to the first blockSyntax as after that we will be out of scope
        //TODO: Harden to detect if the variable is passed out of scope - detect if a non declaration has been passed in
        public static InvocationExpressionSyntax[] FindMemberInnvocation(Location referenceLocation, string memberName)
        {
            var referenceNode = referenceLocation.SourceTree.GetRoot().FindNode(referenceLocation.SourceSpan);
            var memberAccess = referenceNode.Ancestors()
                                                .OfType<BlockSyntax>()
                                                .FirstOrDefault()
                                                ?.DescendantNodes()
                                                .OfType<MemberAccessExpressionSyntax>()
                                                .Where(x => x.Name.Identifier.Text.Equals(memberName))
                                                .Select(identifier => (InvocationExpressionSyntax)identifier.Parent)
                                                .ToArray();

            return memberAccess;
        }

        public static SyntaxNode RetrieveMethodOwningObject(InvocationExpressionSyntax invocation)
        {
            var expression = invocation.DescendantNodes().OfType<MemberAccessExpressionSyntax>().FirstOrDefault()?.Expression;
            if (expression == null) return null;
                
            return  FindDeclearationNode(expression.GetLocation());
        }

        public static SyntaxNode FindDeclearationNode(Location referenceLocation)
        {
            return referenceLocation.SourceTree.GetRoot().FindNode(referenceLocation.SourceSpan);
        }

        //TODO: Brittle - doesn't check the object making the call - can lead to false reuslts given rigth circumstances
        //This is for a local declaration value - so we only go up to the first blockSyntax as after that we will be out of scope
        //Step 2 Find MemberAccessExpression as this is working against the delcaration found
        //Step 3 Go down the tree to the identifer of the AccessExpression as validation that the property being looked for matches
        //Step 4 If a match is found select back up the tree the first AssignmentExpression. This is the value needed as the requirement is to check what is assigned in the right
        public static AssignmentExpressionSyntax FindLocalAssignmentExpressionSyntax(Location referenceLocation, string memberName)
        {
            var referenceNode = referenceLocation.SourceTree.GetRoot().FindNode(referenceLocation.SourceSpan);
            var memberAccess  = referenceNode.Ancestors().OfType<BlockSyntax>().FirstOrDefault()
                                                        ?.DescendantNodes().OfType<MemberAccessExpressionSyntax>()
                                                        .Where(x => x.Name.ToString().Equals(memberName))
                                                        .Select(y => y.Ancestors().OfType<AssignmentExpressionSyntax>()
                                                        .FirstOrDefault()).FirstOrDefault();

            return memberAccess;
        }         
    }
}
