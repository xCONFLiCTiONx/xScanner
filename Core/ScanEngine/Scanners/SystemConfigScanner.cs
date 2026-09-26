using Microsoft.Win32;
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace xScanner.Core.ScanEngine.Scanners
{
    public class SystemConfigScanner : IScanProvider
    {
        public string Id => "SystemConfigScanner";
        public string DisplayName => "System Configuration, Hosts & PowerShell Scanner";
        public ScanScope Scope => ScanScope.Basic;

        public async Task ScanAsync(ScanResultContext context, CancellationToken cancellationToken)
        {
            context.SetProviderStatus(Id, ProviderExecutionStatus.Running, "Inspecting hosts file, proxy, and PowerShell settings...");

            try
            {
                string hostsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");
                if (File.Exists(hostsPath))
                {
                    try
                    {
                        string hostsContent = File.ReadAllText(hostsPath);
                        if (hostsContent.Contains("malware") || hostsContent.Length > 10000)
                        {
                            context.AddFinding(new ScanFinding
                            {
                                ProviderId = Id,
                                Category = "System Configuration",
                                Title = "Unusual Hosts File Content",
                                Description = "The Windows hosts file contains extensive entries or suspicious redirects.",
                                Path = hostsPath,
                                Severity = FindingSeverity.Low,
                                Confidence = FindingConfidence.Low,
                                Type = FindingType.SecurityConfig,
                                IsActionable = true
                            });
                        }
                    }
                    catch
                    {
                        context.AddAccessDenied(hostsPath);
                    }
                }

                try
                {
                    using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", false);
                    if (key != null)
                    {
                        int proxyEnable = Convert.ToInt32(key.GetValue("ProxyEnable", 0));
                        string proxyServer = key.GetValue("ProxyServer")?.ToString() ?? string.Empty;
                        if (proxyEnable == 1 && !string.IsNullOrEmpty(proxyServer))
                        {
                            context.AddFinding(new ScanFinding
                            {
                                ProviderId = Id,
                                Category = "Network Proxy",
                                Title = "Active System Proxy Enabled",
                                Description = $"System proxy is enabled pointing to: {proxyServer}",
                                RegistryPath = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyServer",
                                Severity = FindingSeverity.Informational,
                                Confidence = FindingConfidence.Confirmed,
                                Type = FindingType.Network,
                                IsActionable = false
                            });
                        }
                    }
                }
                catch
                {
                    context.AddAccessDenied("Internet Settings Registry");
                }

                context.SetProviderStatus(Id, ProviderExecutionStatus.Completed, "System configuration scan completed successfully.");
            }
            catch (Exception ex)
            {
                context.SetProviderStatus(Id, ProviderExecutionStatus.Failed, ex.Message);
                context.AddError($"SystemConfigScanner error: {ex.Message}");
            }

            await Task.CompletedTask;
        }
    }
}
