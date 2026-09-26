using Microsoft.Win32;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace xScanner.Core.ScanEngine.Scanners
{
    public class ServiceAndDriverScanner : IScanProvider
    {
        public string Id => "ServiceAndDriverScanner";
        public string DisplayName => "Windows Services & Kernel Drivers Scanner";
        public ScanScope Scope => ScanScope.Basic;

        public async Task ScanAsync(ScanResultContext context, CancellationToken cancellationToken)
        {
            context.SetProviderStatus(Id, ProviderExecutionStatus.Running, "Scanning Windows services and drivers from registry...");

            try
            {
                using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", false);
                if (servicesKey != null)
                {
                    foreach (var serviceName in servicesKey.GetSubKeyNames())
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        context.ScannedServices++;

                        try
                        {
                            using var sKey = servicesKey.OpenSubKey(serviceName, false);
                            if (sKey != null)
                            {
                                var imagePath = sKey.GetValue("ImagePath")?.ToString() ?? string.Empty;
                                if (!string.IsNullOrEmpty(imagePath) && IsUserWritablePath(imagePath))
                                {
                                    context.AddFinding(new ScanFinding
                                    {
                                        ProviderId = Id,
                                        Category = "Service Security",
                                        Title = $"Suspicious Service Binary Path: {serviceName}",
                                        Description = $"Service executable path points to a user-writable or unusual directory: {imagePath}",
                                        Path = imagePath,
                                        RegistryPath = $"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{serviceName}",
                                        Severity = FindingSeverity.High,
                                        Confidence = FindingConfidence.Medium,
                                        Type = FindingType.Service,
                                        IsActionable = true
                                    });
                                }
                            }
                        }
                        catch
                        {
                            context.AddAccessDenied($"Service {serviceName}");
                        }
                    }
                }

                context.SetProviderStatus(Id, ProviderExecutionStatus.Completed, $"Scanned {context.ScannedServices} services successfully.");
            }
            catch (Exception ex)
            {
                context.SetProviderStatus(Id, ProviderExecutionStatus.Failed, ex.Message);
                context.AddError($"ServiceAndDriverScanner error: {ex.Message}");
            }

            await Task.CompletedTask;
        }

        private bool IsUserWritablePath(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            string cleanPath = path.Trim('"', ' ');
            int commaIdx = cleanPath.IndexOf(',');
            if (commaIdx > 0) cleanPath = cleanPath.Substring(0, commaIdx);

            var lower = cleanPath.ToLowerInvariant();
            return lower.Contains("\\temp\\") ||
                   lower.Contains("\\appdata\\") ||
                   lower.Contains("\\downloads\\") ||
                   lower.Contains("\\desktop\\");
        }
    }
}
