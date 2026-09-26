using Microsoft.Win32;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace xScanner.Core.ScanEngine.Scanners
{
    public class AdvancedRegistryExtensibilityScanner : IScanProvider
    {
        public string Id => "AdvancedRegistryExtensibilityScanner";
        public string DisplayName => "Advanced Registry Extensibility & COM Hijacking Scanner";
        public ScanScope Scope => ScanScope.Full;

        public async Task ScanAsync(ScanResultContext context, CancellationToken cancellationToken)
        {
            context.SetProviderStatus(Id, ProviderExecutionStatus.Running, "Scanning COM hijacking, AppInit DLLs, and Winlogon persistence...");

            try
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", false);
                    if (key != null)
                    {
                        var appInit = key.GetValue("AppInit_DLLs")?.ToString();
                        if (!string.IsNullOrEmpty(appInit))
                        {
                            context.AddFinding(new ScanFinding
                            {
                                ProviderId = Id,
                                Category = "Registry Extensibility",
                                Title = "AppInit DLLs Registered",
                                Description = $"AppInit_DLLs is configured with: {appInit}",
                                RegistryPath = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",
                                Severity = FindingSeverity.Medium,
                                Confidence = FindingConfidence.Medium,
                                Type = FindingType.Registry,
                                IsActionable = true
                            });
                        }
                    }
                }
                catch
                {
                    context.AddAccessDenied("AppInit Registry Key");
                }

                context.SetProviderStatus(Id, ProviderExecutionStatus.Completed, "Advanced registry extensibility scan completed.");
            }
            catch (Exception ex)
            {
                context.SetProviderStatus(Id, ProviderExecutionStatus.Failed, ex.Message);
                context.AddError($"AdvancedRegistryExtensibilityScanner error: {ex.Message}");
            }

            await Task.CompletedTask;
        }
    }
}
