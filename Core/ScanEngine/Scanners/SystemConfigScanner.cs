using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace xScanner.Core.ScanEngine.Scanners
{
    public class SystemConfigScanner : IScanProvider
    {
        public string Id => "SystemConfigScanner";
        public string DisplayName => "System Configuration, PowerShell, Browsers & Defender Scanner";
        public ScanScope Scope => ScanScope.Basic;

        public async Task ScanAsync(ScanResultContext context, CancellationToken cancellationToken)
        {
            context.SetProviderStatus(Id, ProviderExecutionStatus.Running, "Inspecting PowerShell profiles, browser extensions, hosts, proxy, and Defender...");
            var sw = Stopwatch.StartNew();
            int powerShellProfilesChecked = 0;
            int browserExtensionsExamined = 0;
            int hostsChecked = 0;
            int proxyChecked = 0;
            int defenderChecks = 0;
            int findingsCount = 0;

            try
            {
                // 1. PowerShell Profiles
                string docsDir = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                string[] psProfiles = new[]
                {
                    Path.Combine(docsDir, "PowerShell", "Microsoft.PowerShell_profile.ps1"),
                    Path.Combine(docsDir, "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1")
                };

                foreach (var profile in psProfiles)
                {
                    powerShellProfilesChecked++;
                    if (File.Exists(profile))
                    {
                        try
                        {
                            string content = File.ReadAllText(profile);
                            if (content.Length > 0)
                            {
                                findingsCount++;
                                context.AddFinding(new ScanFinding
                                {
                                    ProviderId = Id,
                                    Category = "PowerShell Persistence",
                                    Title = $"PowerShell Profile Exists: {Path.GetFileName(profile)}",
                                    Description = $"Active PowerShell profile script detected.\nPath: {profile}\nSize: {content.Length} bytes",
                                    Path = profile,
                                    Severity = FindingSeverity.Low,
                                    Confidence = FindingConfidence.Confirmed,
                                    Type = FindingType.PowerShell,
                                    IsActionable = true
                                });
                            }
                        }
                        catch
                        {
                            context.AddAccessDenied(profile);
                        }
                    }
                }

                // 2. Browser Extensions (Chrome / Edge)
                string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                string[] browserDataPaths = new[]
                {
                    Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "Extensions"),
                    Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "Extensions")
                };

                foreach (var extPath in browserDataPaths)
                {
                    if (Directory.Exists(extPath))
                    {
                        try
                        {
                            foreach (var extDir in Directory.GetDirectories(extPath))
                            {
                                cancellationToken.ThrowIfCancellationRequested();
                                browserExtensionsExamined++;
                            }
                        }
                        catch
                        {
                            context.AddAccessDenied(extPath);
                        }
                    }
                }

                // 3. Hosts file inspection
                string hostsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");
                if (File.Exists(hostsPath))
                {
                    hostsChecked++;
                    try
                    {
                        string hostsContent = File.ReadAllText(hostsPath);
                        if (hostsContent.Contains("malware") || hostsContent.Length > 10000)
                        {
                            findingsCount++;
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

                // 4. Proxy settings
                proxyChecked++;
                try
                {
                    using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", false);
                    if (key != null)
                    {
                        int proxyEnable = Convert.ToInt32(key.GetValue("ProxyEnable", 0));
                        string proxyServer = key.GetValue("ProxyServer")?.ToString() ?? string.Empty;
                        if (proxyEnable == 1 && !string.IsNullOrEmpty(proxyServer))
                        {
                            findingsCount++;
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

                // 5. Windows Defender configuration checks
                defenderChecks++;
                try
                {
                    using var defKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows Defender", false);
                    if (defKey != null)
                    {
                        int disableAntiSpyware = Convert.ToInt32(defKey.GetValue("DisableAntiSpyware", 0));
                        if (disableAntiSpyware == 1)
                        {
                            findingsCount++;
                            context.AddFinding(new ScanFinding
                            {
                                ProviderId = Id,
                                Category = "Security Configuration",
                                Title = "Windows Defender AntiSpyware Disabled",
                                Description = "Registry policy indicates Windows Defender AntiSpyware is disabled.",
                                RegistryPath = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware",
                                Severity = FindingSeverity.High,
                                Confidence = FindingConfidence.High,
                                Type = FindingType.SecurityConfig,
                                IsActionable = true
                            });
                        }
                    }
                }
                catch
                {
                    context.AddAccessDenied("Windows Defender Policy Registry");
                }

                sw.Stop();
                context.SetProviderStatus(Id, ProviderExecutionStatus.Completed,
                    $"Provider completed: {DisplayName}\n" +
                    $"PowerShell profiles checked: {powerShellProfilesChecked}\n" +
                    $"Browser extensions examined: {browserExtensionsExamined}\n" +
                    $"Hosts checked: {hostsChecked}\n" +
                    $"Proxy checked: {proxyChecked}\n" +
                    $"Defender policy checks: {defenderChecks}\n" +
                    $"Findings: {findingsCount}\n" +
                    $"Duration: {sw.ElapsedMilliseconds / 1000.0:F1}s");
            }
            catch (Exception ex)
            {
                sw.Stop();
                context.SetProviderStatus(Id, ProviderExecutionStatus.Failed, ex.Message);
                context.AddError($"SystemConfigScanner error: {ex.Message}");
            }

            await Task.CompletedTask;
        }
    }
}
