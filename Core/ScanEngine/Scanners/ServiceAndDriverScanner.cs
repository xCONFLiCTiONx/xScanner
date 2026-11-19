using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.IO;
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
            context.SetProviderStatus(Id, ProviderExecutionStatus.Running, "Scanning Windows services and kernel drivers from registry...");
            var sw = Stopwatch.StartNew();
            int servicesEnumerated = 0;
            int serviceBinariesChecked = 0;
            int kernelDriversEnumerated = 0;
            int driverBinariesChecked = 0;
            int accessDeniedCount = 0;
            int suspiciousCount = 0;

            try
            {
                // 1. Services & Drivers from HKLM\SYSTEM\CurrentControlSet\Services
                using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", false);
                if (servicesKey != null)
                {
                    foreach (var serviceName in servicesKey.GetSubKeyNames())
                    {
                        cancellationToken.ThrowIfCancellationRequested();

                        try
                        {
                            using var sKey = servicesKey.OpenSubKey(serviceName, false);
                            if (sKey != null)
                            {
                                int serviceType = Convert.ToInt32(sKey.GetValue("Type", 1));
                                // ServiceType 1 = Kernel Driver (1), File System Driver (2), Adapter (4), Recognizer Driver (8), Win32 Own Process (16), Win32 Share Process (32)
                                bool isDriver = (serviceType & 1) == 1 || (serviceType & 2) == 2 || (serviceType & 8) == 8;

                                if (isDriver)
                                {
                                    kernelDriversEnumerated++;
                                }
                                else
                                {
                                    servicesEnumerated++;
                                    context.ScannedServices++;
                                }

                                var imagePath = sKey.GetValue("ImagePath")?.ToString() ?? string.Empty;
                                if (!string.IsNullOrEmpty(imagePath))
                                {
                                    if (isDriver) driverBinariesChecked++;
                                    else serviceBinariesChecked++;

                                    if (IsUserWritablePath(imagePath))
                                    {
                                        suspiciousCount++;
                                        context.AddFinding(new ScanFinding
                                        {
                                            ProviderId = Id,
                                            Category = isDriver ? "Driver Security" : "Service Security",
                                            Title = $"Suspicious {(isDriver ? "Driver" : "Service")} Binary Path: {serviceName}",
                                            Description = $"Binary path points to a user-writable or unusual directory: {imagePath}",
                                            Path = imagePath,
                                            RegistryPath = $"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{serviceName}",
                                            Severity = FindingSeverity.High,
                                            Confidence = FindingConfidence.Medium,
                                            Type = isDriver ? FindingType.Driver : FindingType.Service,
                                            IsActionable = true
                                        });
                                    }
                                }
                            }
                        }
                        catch
                        {
                            accessDeniedCount++;
                            context.AddAccessDenied($"Service/Driver {serviceName}");
                        }
                    }
                }

                // 2. Also check C:\Windows\System32\drivers folder
                string driversDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers");
                if (Directory.Exists(driversDir))
                {
                    try
                    {
                        foreach (var driverFile in Directory.GetFiles(driversDir, "*.sys"))
                        {
                            cancellationToken.ThrowIfCancellationRequested();
                            kernelDriversEnumerated++;
                        }
                    }
                    catch
                    {
                        accessDeniedCount++;
                    }
                }

                sw.Stop();
                context.SetProviderStatus(Id, ProviderExecutionStatus.Completed,
                    $"Provider completed: {DisplayName}\n" +
                    $"Services enumerated: {servicesEnumerated}\n" +
                    $"Service binaries checked: {serviceBinariesChecked}\n" +
                    $"Kernel drivers enumerated: {kernelDriversEnumerated}\n" +
                    $"Driver binaries checked: {driverBinariesChecked}\n" +
                    $"Access denied: {accessDeniedCount}\n" +
                    $"Suspicious: {suspiciousCount}\n" +
                    $"Duration: {sw.ElapsedMilliseconds / 1000.0:F1}s");
            }
            catch (Exception ex)
            {
                sw.Stop();
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
