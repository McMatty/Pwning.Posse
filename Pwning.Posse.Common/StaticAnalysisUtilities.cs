using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FindSymbols;
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
        public static bool IsAssignedValue(SyntaxNode argument, string left, string right)
        {
            return argument.DescendantNodesAndSelf()
                            .OfType<AssignmentExpressionSyntax>()
                            .Any(x => x.Left.ToString().Contains(left) && x.Right.ToString().Equals(right));
        }

        //Checks for an expected assignment (only useful for enums which have a set of possible values)
        //Checks the left property is being assigned the expected propert on the right
        public static bool IsAssignedValue(SyntaxNode argument, string left, string[] right)
        {
            return argument.DescendantNodesAndSelf()
                            .OfType<AssignmentExpressionSyntax>()
                            .Any(x => x.Left.ToString().Contains(left) && right.Contains(x.Right.ToString()));
        }

        public static Location GetLocation(ISymbol declaredSymbol, Solution solution)
        {
            var references = SymbolFinder.FindReferencesAsync(declaredSymbol, solution).Result;
            var location = references
                .FirstOrDefault()
                .Locations
                .FirstOrDefault().Location;

            return location;
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

        public static SyntaxNode FindDeclearationNode(Location referenceLocation)
        {
            return referenceLocation.SourceTree.GetRoot().FindNode(referenceLocation.SourceSpan);
        }

        //TODO: Remove this as ThisExpressionSyntax declaration check gives us the location
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

        //This is a class field value - so we only go up to the class declaration and work down
        //Step 2 Find ClassDeclarationSyntax as this is working against the delcaration found
        //Step 3 Go down the tree to the FieldDeclarationSyntax and begin inspecting this
        //Step 4 Go down from this branch to get the memberAccessExpression - then inspect the values of type and settings to make sure we have the right field
        //Step 5 If a match is found select back up the tree the first AssignmentExpression. This is the value needed as the requirement is to check what is assigned in the right
        public static AssignmentExpressionSyntax FindGlobalAssignmentExpressionSyntax(Location referenceLocation, string memberName)
        {
            var referenceNode = referenceLocation.SourceTree.GetRoot().FindNode(referenceLocation.SourceSpan);
            var memberAccess = referenceNode.Ancestors().OfType<ClassDeclarationSyntax>()
                                                        .FirstOrDefault()?.DescendantNodes().OfType<FieldDeclarationSyntax>().First();


            return null;// memberAccess;
        }        

        public static LocalDeclarationStatementSyntax FindLocalIdentifierDeclaration(IdentifierNameSyntax identifierName)
        {
            var block = identifierName.Ancestors()
                  .OfType<BlockSyntax>()
                  .First();

            return GetLocalDeclaration(block, identifierName.Identifier.Text);
        }

        public static LocalDeclarationStatementSyntax GetLocalDeclaration(BlockSyntax blockSyntax, string identifierString)
        {
            //This should be changed so it goes to the method declaration and then goes down the branches searching instead of bottom up
            var foundBlock = blockSyntax.DescendantNodes()
                                        .OfType<LocalDeclarationStatementSyntax>()
                                        .Where(x => x.Declaration.Variables.Where(v => v.Identifier.Text == identifierString).Count() > 0)
                                        .FirstOrDefault();

            if (foundBlock == null)
            {
                var parentBlock = blockSyntax.Ancestors()
                                            .OfType<BlockSyntax>()
                                            .FirstOrDefault();
                if (parentBlock != null)
                {
                    foundBlock = GetLocalDeclaration(parentBlock, identifierString);
                }
            }

            return foundBlock;
        }
    }
}
