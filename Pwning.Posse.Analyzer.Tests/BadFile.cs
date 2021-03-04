using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using Newtonsoft.Json;
namespace ConsoleApplication1
{
    //Should find this vulnerability
    class TypeName
    {  
        static TypeName()
        {
            GetDeserializedObject("payload");
        }
        public static void GetDeserializedObject(string payload)
        {
                var obj = JsonConvert.DeserializeObject<Object>(payload, new JsonSerializerSettings
                    {
                        TypeNameHandling = TypeNameHandling.Auto
                    }); 
        }
    }
}
