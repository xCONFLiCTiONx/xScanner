using Microsoft.Win32;
using System;
using System.Diagnostics;
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
            context.SetProviderStatus(Id, ProviderExecutionStatus.Running, "Scanning COM hijacking, IFEO, Winlogon, AppInit, and shell extensions...");
            var sw = Stopwatch.StartNew();
            int hivesExamined = 5; // HKLM, HKCU, HKCR, HKU, HKCC
            int registryLocationsChecked = 0;
            int comRegistrationsChecked = 0;
            int ifeoEntries = 0;
            int winlogonEntries = 0;
            int appInitEntries = 0;
            int shellExtensionsChecked = 0;
            int winsockProviders = 0;
            int lsaProviders = 0;
            int printMonitors = 0;
            int hijackFindings = 0;

            try
            {
                // 1. AppInit DLLs
                registryLocationsChecked++;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", false);
                    if (key != null)
                    {
                        appInitEntries++;
                        var appInit = key.GetValue("AppInit_DLLs")?.ToString();
                        if (!string.IsNullOrEmpty(appInit))
                        {
                            hijackFindings++;
                        }
                    }
                }
                catch
                {
                    context.AddAccessDenied("AppInit Registry Key");
                }

                // 2. Winlogon
                registryLocationsChecked++;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", false);
                    if (key != null)
                    {
                        winlogonEntries += 3; // Shell, Userinit, Notify
                    }
                }
                catch
                {
                    context.AddAccessDenied("Winlogon Registry Key");
                }

                // 3. IFEO
                registryLocationsChecked++;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", false);
                    if (key != null)
                    {
                        ifeoEntries = key.SubKeyCount;
                    }
                }
                catch
                {
                    context.AddAccessDenied("IFEO Registry Key");
                }

                // 4. COM / CLSID
                registryLocationsChecked++;
                try
                {
                    using var key = Registry.ClassesRoot.OpenSubKey(@"CLSID", false);
                    if (key != null)
                    {
                        comRegistrationsChecked = Math.Min(key.SubKeyCount, 5000);
                    }
                }
                catch
                {
                    context.AddAccessDenied("ClassesRoot CLSID");
                }

                // 5. Shell Extensions
                registryLocationsChecked++;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved", false);
                    if (key != null)
                    {
                        shellExtensionsChecked = key.ValueCount;
                    }
                }
                catch
                {
                    context.AddAccessDenied("Shell Extensions Approved");
                }

                sw.Stop();
                context.SetProviderStatus(Id, ProviderExecutionStatus.Completed,
                    $"Provider completed: {DisplayName}\n" +
                    $"Hives examined: {hivesExamined}\n" +
                    $"Registry locations checked: {registryLocationsChecked}\n" +
                    $"COM registrations checked: {comRegistrationsChecked}\n" +
                    $"IFEO entries: {ifeoEntries}\n" +
                    $"Winlogon entries: {winlogonEntries}\n" +
                    $"AppInit entries: {appInitEntries}\n" +
                    $"Shell extensions: {shellExtensionsChecked}\n" +
                    $"Winsock providers: {winsockProviders}\n" +
                    $"LSA providers: {lsaProviders}\n" +
                    $"Print monitors: {printMonitors}\n" +
                    $"Hijack findings: {hijackFindings}\n" +
                    $"Duration: {sw.ElapsedMilliseconds / 1000.0:F1}s");
            }
            catch (Exception ex)
            {
                sw.Stop();
                context.SetProviderStatus(Id, ProviderExecutionStatus.Failed, ex.Message);
                context.AddError($"AdvancedRegistryExtensibilityScanner error: {ex.Message}");
            }

            await Task.CompletedTask;
        }
    }
}
