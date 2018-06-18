using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.ServiceProcess;

namespace Pwning.Posse.CommandLine
{
    public class ServiceDetails
    {
        public string ServiceName;
        public string ServicePath;
        public string RunningAs;
    }

    public static class DotNetServiceUtilities
    {
        public static List<ServiceDetails> FindDotNetServices()
        {
            var dotNetServiceList = ServiceController.GetServices()
                     .Where(x => x.Status == ServiceControllerStatus.Running)
                     .Where(y => IsLocalSystemService(y))
                     .Select(svc => GetDotNetService(svc))
                     .Where(detail => detail != null)
                     .ToList();

            return dotNetServiceList;
        }

        static ServiceDetails GetDotNetService(ServiceController service)
        {
            ServiceDetails serviceDetails = null;
            using (var wmiService = new ManagementObject($"Win32_Service.Name='{service.ServiceName}'"))
            {
                wmiService.Get();

                var servicePath = wmiService["PathName"].ToString();
                var exePath = servicePath.Substring(0, servicePath.IndexOf(".exe") + 4);
                var isDotNet = DotNetAssemblyLocater.IsDotNetAssembly(exePath);

                if (isDotNet)
                {
                    serviceDetails = new ServiceDetails()
                    {
                        RunningAs = wmiService["StartName"].ToString(),
                        ServiceName = service.ServiceName,
                        ServicePath = wmiService["PathName"].ToString()
                    };
                }
            }

            return serviceDetails;
        }

        static bool IsLocalSystemService(ServiceController service)
        {
            bool isFiltered = false;
            using (var wmiService = new ManagementObject($"Win32_Service.Name='{service.ServiceName}'"))
            {
                wmiService.Get();
                var isSystem32 = false;

                try
                {
                    var servicePath         = wmiService["PathName"].ToString();
                    var serviceDirectory    = Path.GetDirectoryName(servicePath);
                    isSystem32              = serviceDirectory.ToLower().Contains(@"c:\windows\system32");
                }
                catch
                {
                    //TODO: Log exception - get real exception type
                    isSystem32 = true;
                }

                isFiltered = wmiService["StartName"] != null && wmiService["StartName"].ToString().Contains("LocalSystem") && !isSystem32;
            }

            return isFiltered;
        }

    }
}
