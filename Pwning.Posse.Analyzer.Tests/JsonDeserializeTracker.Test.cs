using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using Pwning.Posse.Analyzer.Tests.TestHelper;
using Pwning.Posse.Tracker;

namespace Pwning.Posse.Analyzer.Tests
{
    [TestClass]
    public class JsonDeserializeTrackerTest : CodeFixVerifier
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
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using Newtonsoft.Json;

namespace ConsoleApplication1
{
    class TypeName
    {  
        static void  Main(string[] args)
        {
            GetDeserializedObject(""payload"");
        }

        public static void GetDeserializedObject(string payload)
        {
                var obj = JsonConvert.DeserializeObject<Object>(payload, new JsonSerializerSettings
                    {
                        TypeNameHandling = TypeNameHandling.None
                    }); 
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
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using Newtonsoft.Json;

namespace ConsoleApplication1
{
    class TypeName
    {  
        static void  Main(string[] args)
        {
            GetDeserializedObject(""payload"");
        }

        public static void GetDeserializedObject(string payload)
        {
                var obj = JsonConvert.DeserializeObject<Object>(payload, new JsonSerializerSettings
                    {
                        TypeNameHandling = TypeNameHandling.Auto
                    }); 
        }
    }
}";
            var expected = new DiagnosticResult
            {
                Id = "Vulnerability",
                Message = String.Format("JsonConvert is possibly vulnerable to a deserialization attack"),
                Severity = DiagnosticSeverity.Error,
                Locations =
                    new[] {
                            new DiagnosticResultLocation("Test0.cs", 21, 27)
                        }
            };

            VerifyCSharpDiagnostic(test, expected);
        }

        [TestMethod]
        public void VulnerableAutoAssignment_PropertyAssignment_ErrorDetected()
        {
            var test = @"
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using Newtonsoft.Json;

namespace ConsoleApplication1
{
    class TypeName
    {  
        static void  Main(string[] args)
        {
            GetDeserializedObject(""payload"");
        }

        public static void GetDeserializedObject(string payload)
        {
                var jSettings = new JsonSerializerSettings();
                jSettings.TypeNameHandling = TypeNameHandling.Auto;
                var obj = JsonConvert.DeserializeObject<Object>(payload, jSettings); 
        }
    }
}";
            var expected = new DiagnosticResult
            {
                Id = "Vulnerability",
                Message = String.Format("JsonConvert is possibly vulnerable to a deserialization attack"),
                Severity = DiagnosticSeverity.Error,
                Locations =
                    new[] {
                            new DiagnosticResultLocation("Test0.cs", 23, 27)
                        }
            };

            VerifyCSharpDiagnostic(test, expected);
        }

        [TestMethod]
        public void BinderMitigation_InlineConstructor_NoErrorDetected()
        {
            var test = @"
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;;

namespace ConsoleApplication1
{
    public class KnownTypesBinder : ISerializationBinder
    {
        public IList<Type> KnownTypes { get; set; }

        public Type BindToType(string assemblyName, string typeName)
        {
            return KnownTypes.SingleOrDefault(t => t.Name == typeName);
        }

        public void BindToName(Type serializedType, out string assemblyName, out string typeName)
        {
            assemblyName = null;
            typeName = serializedType.Name;
        }
    }

    public class Car
    {
        public string Maker { get; set; }
        public string Model { get; set; }
    }

    class TypeName
    {  
        static void  Main(string[] args)
        {
            GetDeserializedObject(""payload"");
        }

        public static void GetDeserializedObject(string payload)
        {
                KnownTypesBinder knownTypesBinder = new KnownTypesBinder
                {
                    KnownTypes = new List<Type> { typeof(Car) }
                };

                Car car = new Car
                {
                    Maker = ""Ford"",
                    Model = ""Explorer""
                };

                var jSettings = new JsonSerializerSettings();
                jSettings.TypeNameHandling = TypeNameHandling.Auto;
                jSettings.SerializationBinder = knownTypesBinder;
                var obj = JsonConvert.DeserializeObject<Object>(payload, jSettings);  
        }
    }
}";
            VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public void BinderMitigation_PropertyAssignment_NoErrorDetected()
        {
            var test = @"
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace ConsoleApplication1
{
    public class KnownTypesBinder : ISerializationBinder
    {
        public IList<Type> KnownTypes { get; set; }

        public Type BindToType(string assemblyName, string typeName)
        {
            return KnownTypes.SingleOrDefault(t => t.Name == typeName);
        }

        public void BindToName(Type serializedType, out string assemblyName, out string typeName)
        {
            assemblyName = null;
            typeName = serializedType.Name;
        }
    }

    public class Car
    {
        public string Maker { get; set; }
        public string Model { get; set; }
    }

    class TypeName
    {  
        static void  Main(string[] args)
        {
            GetDeserializedObject(""payload"");
        }

        public static void GetDeserializedObject(string payload)
        {
                KnownTypesBinder knownTypesBinder = new KnownTypesBinder
                {
                    KnownTypes = new List<Type> { typeof(Car) }
                };

                Car car = new Car
                {
                    Maker = ""Ford"",
                    Model = ""Explorer""
                };

        var obj = JsonConvert.DeserializeObject<Object>(payload, new JsonSerializerSettings
                    {
                        TypeNameHandling = TypeNameHandling.Auto,
                        SerializationBinder = knownTypesBinder
                    }); 
        }
    }
}";
            VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public void NoBinderMitigation_NullPropertyAssigned_ErrorDetected()
        {
            var test = @"
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace ConsoleApplication1
{
    public class KnownTypesBinder : ISerializationBinder
    {
        public IList<Type> KnownTypes { get; set; }

        public Type BindToType(string assemblyName, string typeName)
        {
            return KnownTypes.SingleOrDefault(t => t.Name == typeName);
        }

        public void BindToName(Type serializedType, out string assemblyName, out string typeName)
        {
            assemblyName = null;
            typeName = serializedType.Name;
        }
    }

    public class Car
    {
        public string Maker { get; set; }
        public string Model { get; set; }
    }

    class TypeName
    {  
        static void  Main(string[] args)
        {
            GetDeserializedObject(""payload"");
        }

        public static void GetDeserializedObject(string payload)
        {
                KnownTypesBinder knownTypesBinder = new KnownTypesBinder
                {
                    KnownTypes = new List<Type> { typeof(Car) }
                };

                Car car = new Car
                {
                    Maker = ""Ford"",
                    Model = ""Explorer""
                };

        var obj = JsonConvert.DeserializeObject<Object>(payload, new JsonSerializerSettings
                    {
                        TypeNameHandling = TypeNameHandling.Auto,
                        SerializationBinder = null
                    }); 
        }
    }
}";
            var expected = new DiagnosticResult
            {
                Id = "Vulnerability",
                Message = String.Format("JsonConvert  is possibly vulnerable to a deserialization attack"),
                Severity = DiagnosticSeverity.Error,
                Locations =
                   new[] {
                            new DiagnosticResultLocation("Test0.cs", 55, 19)
                       }
            };

            VerifyCSharpDiagnostic(test, expected);
        }

        protected override DiagnosticAnalyzer GetCSharpDiagnosticAnalyzer()
        {
            return new JsonDeserializeTracker();
        }
    }
}
