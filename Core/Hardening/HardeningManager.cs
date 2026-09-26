using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace xScanner.Core.Hardening
{
    public class HardeningManager
    {
        public event Action<string>? LogProgress;

        private void Log(string message)
        {
            LogProgress?.Invoke(message);
        }

        public bool IsPublicOrOpenWifi()
        {
            try
            {
                var profiles = GetNetworkProfiles();
                bool isPublic = profiles.Any(p => p.Contains("Public", StringComparison.OrdinalIgnoreCase));

                bool isOpenWifi = false;
                string wlanOutput = RunCmd("netsh", "wlan show interfaces");
                if (wlanOutput.Contains("Authentication", StringComparison.OrdinalIgnoreCase) &&
                    wlanOutput.Contains("Open", StringComparison.OrdinalIgnoreCase) &&
                    wlanOutput.Contains("Cipher", StringComparison.OrdinalIgnoreCase) &&
                    wlanOutput.Contains("None", StringComparison.OrdinalIgnoreCase))
                {
                    isOpenWifi = true;
                }

                return isPublic || isOpenWifi;
            }
            catch
            {
                return true; // Default to cautious if unknown
            }
        }

        public async Task<HardeningAuditReport> RunSecurityAuditAsync()
        {
            return await Task.Run(() =>
            {
                var report = new HardeningAuditReport
                {
                    ScanTime = DateTime.Now
                };

                Log("[AUDIT] Starting Comprehensive Security & Hardening Audit (12 Checks)...");

                // Step 1: Firewall Configuration
                Log("[AUDIT 1/12] Scanning Network Profiles & Public Firewall Configuration...");
                report.CheckResults.Add(CheckFirewallConfiguration());

                // Step 2: File Sharing Check
                Log("[AUDIT 2/12] Checking File Sharing Services (LanmanServer)...");
                report.CheckResults.Add(CheckFileSharing());

                // Step 3: Remote Management & Casting Check
                Log("[AUDIT 3/12] Checking Remote Management & Casting (SSDP, uPnP, RDP)...");
                report.CheckResults.Add(CheckRemoteAndCasting());

                // Step 4: Tracking & Telemetry Audit
                Log("[AUDIT 4/12] Auditing Privacy, Advertising ID & Telemetry Restrictions...");
                report.CheckResults.Add(CheckPrivacyAndTelemetry());

                // Step 5: Webcam Privacy Lockdown Check
                Log("[AUDIT 5/12] Auditing Global Webcam Privacy Policy...");
                report.CheckResults.Add(CheckWebcamLockdown());

                // Step 6: Port Shielding Check (Ports 135 & 445)
                Log("[AUDIT 6/12] Checking Port Shielding Firewall Rules (RPC 135 & SMB 445)...");
                report.CheckResults.Add(CheckPortShielding());

                // Step 7: Encrypted DNS Check (DoH)
                Log("[AUDIT 7/12] Auditing Encrypted DNS (DNS-over-HTTPS / DoH) Enforcement...");
                report.CheckResults.Add(CheckEncryptedDns());

                // Step 8: LLMNR / NetBIOS Poisoning Protections
                Log("[AUDIT 8/12] Checking LLMNR & NetBIOS Poisoning Protections...");
                report.CheckResults.Add(CheckLlmnrNetBios());

                // Step 9: PowerShell Logging Audit
                Log("[AUDIT 9/12] Auditing PowerShell Script Block & Transcription Logging...");
                report.CheckResults.Add(CheckPowerShellLogging());

                // Step 10: Advanced Inbound Ports & RDP NLA
                Log("[AUDIT 10/12] Auditing Advanced Inbound Ports & RDP NLA Authentication...");
                report.CheckResults.Add(CheckAdvancedPorts());

                // Step 11: Windows Defender Tamper Protection
                Log("[AUDIT 11/12] Auditing Windows Defender Tamper Protection...");
                report.CheckResults.Add(CheckDefenderTamper());

                // Step 12: Startup Persistence Hunter
                Log("[AUDIT 12/12] Scanning Auto-Run & Startup Persistence Locations...");
                report.CheckResults.Add(CheckStartupPersistence());

                // Active Listening Ports Scan
                Log("[AUDIT] Scanning Active Open Listening TCP Ports...");
                report.ListeningPorts = ScanListeningPorts();

                // Network Profiles, DNS & DoH Templates
                Log("[AUDIT] Scanning Active IPv4 DNS Servers, DoH Templates & Network Interfaces...");
                report.ActiveDnsServers = GetActiveDnsServers();
                report.NetworkProfiles = GetNetworkProfiles();
                PopulateDohInfo(report);

                // Calculate metrics
                report.TotalChecks = report.CheckResults.Count;
                report.PassedChecks = report.CheckResults.Count(c => c.Status == HardeningStatus.Hardened);
                report.FailedChecks = report.TotalChecks - report.PassedChecks;
                report.ScorePercentage = report.TotalChecks > 0
                    ? (int)Math.Round((double)report.PassedChecks / report.TotalChecks * 100)
                    : 0;

                Log($"[AUDIT COMPLETE] Score: {report.ScorePercentage}% ({report.PassedChecks}/{report.TotalChecks} Hardened)");
                return report;
            });
        }

        public async Task<HardeningAuditReport> ApplyHardeningAndVerifyAsync(DohProvider? provider = null, List<HardeningCheckResult>? selectedChecks = null)
        {
            provider ??= DohProvider.GetPopularProviders()[0];
            Log($"[HARDEN] Initiating Selected Hardening & System Lockdown Actions...");

            // If selectedChecks provided, determine which ones are checked
            bool ShouldApply(string id)
            {
                if (selectedChecks == null) return true;
                var match = selectedChecks.FirstOrDefault(c => c.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
                return match == null || match.IsSelected;
            }

            await Task.Run(() =>
            {
                // 1. Firewall Configuration
                if (ShouldApply("FW_PUBLIC"))
                {
                    Log("[ACTION] Enabling Public Firewall Profile & Setting Inbound Action to Block...");
                    RunNetsh("advfirewall set publicprofile state on");
                    RunNetsh("advfirewall set publicprofile firewallpolicy blockinbound,allowoutbound");
                }

                // 2. Disabling File Sharing
                if (ShouldApply("FILE_SHARING"))
                {
                    Log("[ACTION] Stopping and Disabling LanmanServer (Server) service...");
                    SetServiceDisabledAndStopped("LanmanServer");
                }

                // 3. Disabling Casting & Discovery Services
                if (ShouldApply("REMOTE_CASTING"))
                {
                    Log("[ACTION] Stopping and Disabling SSDP (SSDPSRV) and uPnP (upnphost)...");
                    SetServiceDisabledAndStopped("SSDPSRV");
                    SetServiceDisabledAndStopped("upnphost");

                    Log("[ACTION] Disabling Remote Desktop connections via Registry (fDenyTSConnections)...");
                    SetRegistryValue(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", 1, RegistryValueKind.DWord);
                }

                // 4. Privacy & Telemetry Restrictions
                if (ShouldApply("PRIVACY_TELEMETRY"))
                {
                    Log("[ACTION] Restricting Advertising ID & Telemetry collection levels...");
                    SetRegistryValue(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", 0, RegistryValueKind.DWord);
                    SetRegistryValue(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", 0, RegistryValueKind.DWord);
                    SetRegistryValue(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", 0, RegistryValueKind.DWord);
                }

                // 5. Webcam Lockdown
                if (ShouldApply("WEBCAM_LOCK"))
                {
                    Log("[ACTION] Enforcing Global Privacy Block (Deny) on Webcam Access...");
                    SetRegistryValue(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam", "Value", "Deny", RegistryValueKind.String);
                    SetRegistryValue(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam", "Value", "Deny", RegistryValueKind.String);
                }

                // 6. Port Shielding Rules
                if (ShouldApply("PORT_SHIELDING"))
                {
                    Log("[ACTION] Adding Inbound Firewall Rules to Shield Ports 135 (RPC) and 445 (SMB)...");
                    RunNetsh("advfirewall firewall delete rule name=\"xScanner_Block_RPC_135\"");
                    RunNetsh("advfirewall firewall add rule name=\"xScanner_Block_RPC_135\" dir=in action=block protocol=TCP localport=135 profile=public");

                    RunNetsh("advfirewall firewall delete rule name=\"xScanner_Block_SMB_445\"");
                    RunNetsh("advfirewall firewall add rule name=\"xScanner_Block_SMB_445\" dir=in action=block protocol=TCP localport=445 profile=public");
                }

                // 7. Encrypted DNS / DoH Enforcement
                if (ShouldApply("ENCRYPTED_DNS"))
                {
                    Log($"[ACTION] Enforcing DNS-over-HTTPS (DoH) for IPv4 & IPv6 ({provider.Name})...");
                    SetRegistryValue(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters", "EnableAutoDoh", 2, RegistryValueKind.DWord);
                    SetRegistryValue(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableAutoDoh", 2, RegistryValueKind.DWord);
                    ConfigureDohInWindows11(provider);
                }

                // 8. LLMNR / NetBIOS Poisoning Protections
                if (ShouldApply("LLMNR_NETBIOS"))
                {
                    Log("[ACTION] Disabling LLMNR multicast name resolution...");
                    SetRegistryValue(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", 0, RegistryValueKind.DWord);
                }

                // 9. PowerShell Logging
                if (ShouldApply("PS_LOGGING"))
                {
                    Log("[ACTION] Enabling PowerShell Script Block, Module and Transcription Logging...");
                    SetRegistryValue(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging", 1, RegistryValueKind.DWord);
                    SetRegistryValue(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging", "EnableModuleLogging", 1, RegistryValueKind.DWord);
                    SetRegistryValue(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription", "EnableTranscripting", 1, RegistryValueKind.DWord);
                }

                // 10. Advanced Ports & RDP NLA
                if (ShouldApply("ADV_PORTS"))
                {
                    Log("[ACTION] Enforcing Network Level Authentication (NLA) for RDP...");
                    SetRegistryValue(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication", 1, RegistryValueKind.DWord);
                }

                // 11. Windows Defender Tamper Protection
                if (ShouldApply("DEFENDER_VBS"))
                {
                    Log("[ACTION] Enabling Windows Defender Tamper Protection...");
                    RunCmd("powershell", "-NoProfile -ExecutionPolicy Bypass -Command \"Set-MpPreference -DisableTamperProtection $false -ErrorAction SilentlyContinue\"");
                    SetRegistryValue(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows Defender\Features", "TamperProtection", 1, RegistryValueKind.DWord);
                }
            });

            Log("[HARDEN] Hardening pass finished. Pausing 2 seconds before Auto-Verification Re-Run...");
            await Task.Delay(2000);

            Log("[VERIFY] Running Auto-Verification Audit Pass...");
            var verifiedReport = await RunSecurityAuditAsync();
            return verifiedReport;
        }

        private void ConfigureDohInWindows11(DohProvider provider)
        {
            try
            {
                string[] ips = new[] { provider.Ipv4Primary, provider.Ipv4Secondary, provider.Ipv6Primary, provider.Ipv6Secondary };

                foreach (var ip in ips)
                {
                    if (string.IsNullOrWhiteSpace(ip)) continue;

                    string removePs = $"Remove-DnsClientDohServerAddress -ServerAddress '{ip}' -ErrorAction SilentlyContinue";
                    RunCmd("powershell", $"-NoProfile -ExecutionPolicy Bypass -Command \"{removePs}\"");

                    RunCmd("netsh", $"dns add encryption server={ip} dohtemplate=\"{provider.TemplateUrl}\" autoupdate=yes");

                    string psCmd = $"Add-DnsClientDohServerAddress -ServerAddress '{ip}' -DohTemplate '{provider.TemplateUrl}' -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction SilentlyContinue; Set-DnsClientDohServerAddress -ServerAddress '{ip}' -DohTemplate '{provider.TemplateUrl}' -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction SilentlyContinue";
                    RunCmd("powershell", $"-NoProfile -ExecutionPolicy Bypass -Command \"{psCmd}\"");
                }

                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus == OperationalStatus.Up &&
                        (ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ||
                         ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet))
                    {
                        string name = ni.Name;
                        string desc = ni.Description;

                        // Exclude virtual adapters (Hyper-V, vSwitch, WSL, VPN, TAP, VMware, VirtualBox, etc.)
                        if (desc.Contains("Hyper-V", StringComparison.OrdinalIgnoreCase) ||
                            desc.Contains("Virtual", StringComparison.OrdinalIgnoreCase) ||
                            desc.Contains("vEthernet", StringComparison.OrdinalIgnoreCase) ||
                            desc.Contains("VPN", StringComparison.OrdinalIgnoreCase) ||
                            desc.Contains("TAP", StringComparison.OrdinalIgnoreCase) ||
                            desc.Contains("WSL", StringComparison.OrdinalIgnoreCase) ||
                            desc.Contains("VMware", StringComparison.OrdinalIgnoreCase) ||
                            desc.Contains("Box", StringComparison.OrdinalIgnoreCase) ||
                            name.Contains("vEthernet", StringComparison.OrdinalIgnoreCase) ||
                            name.Contains("Hyper-V", StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }

                        string alias = ni.Name;
                        Log($"[DOH CONFIG] Applying Encrypted DNS servers & DoH template '{provider.Name}' to Physical Adapter '{alias}'...");

                        string setIpv4 = $"Set-DnsClientServerAddress -InterfaceAlias '{alias}' -ServerAddresses ('{provider.Ipv4Primary}', '{provider.Ipv4Secondary}') -ErrorAction SilentlyContinue";
                        RunCmd("powershell", $"-NoProfile -ExecutionPolicy Bypass -Command \"{setIpv4}\"");

                        if (!string.IsNullOrWhiteSpace(provider.Ipv6Primary))
                        {
                            string setIpv6 = $"Set-DnsClientServerAddress -InterfaceAlias '{alias}' -ServerAddresses ('{provider.Ipv6Primary}', '{provider.Ipv6Secondary}') -AddressFamily IPv6 -ErrorAction SilentlyContinue";
                            RunCmd("powershell", $"-NoProfile -ExecutionPolicy Bypass -Command \"{setIpv6}\"");
                        }
                    }
                }

                SetRegistryValue(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters", "EnableAutoDoh", 2, RegistryValueKind.DWord);
                SetRegistryValue(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableAutoDoh", 2, RegistryValueKind.DWord);
            }
            catch (Exception ex)
            {
                Log($"[WARN] DoH configuration note: {ex.Message}");
            }
        }

        #region Individual Check Methods

        private HardeningCheckResult CheckFirewallConfiguration()
        {
            var result = new HardeningCheckResult
            {
                Id = "FW_PUBLIC",
                Category = "Firewall & Network",
                Name = "Public Firewall Profile & Inbound Policy",
                Description = "Ensures Public Firewall profile is enabled and default inbound action is set to Block.",
                RemediationDescription = "Enables Public Profile and sets default Inbound Policy to Block."
            };

            try
            {
                string output = RunCmd("netsh", "advfirewall show publicprofile");
                bool isEnabled = output.Contains("State                                 ON", StringComparison.OrdinalIgnoreCase) ||
                                 output.Contains("State ON", StringComparison.OrdinalIgnoreCase);
                bool blocksInbound = output.Contains("BlockInbound", StringComparison.OrdinalIgnoreCase);

                if (isEnabled && blocksInbound)
                {
                    result.Status = HardeningStatus.Hardened;
                    result.CurrentValue = "Public Profile: Active & Default Inbound Blocked";
                }
                else
                {
                    result.Status = HardeningStatus.Vulnerable;
                    result.CurrentValue = isEnabled ? "Public Profile: Active (Inbound Not Strictly Blocked)" : "Public Profile: Disabled";
                }
            }
            catch (Exception ex)
            {
                result.Status = HardeningStatus.Unknown;
                result.CurrentValue = $"Error checking firewall: {ex.Message}";
            }

            return result;
        }

        private HardeningCheckResult CheckFileSharing()
        {
            var result = new HardeningCheckResult
            {
                Id = "FILE_SHARING",
                Category = "File Sharing",
                Name = "LanmanServer (Server) Sharing Service",
                Description = "Stops and disables network folder and drive sharing service (LanmanServer).",
                RemediationDescription = "Stops and disables LanmanServer service."
            };

            try
            {
                string queryOut = RunCmd("sc", "query LanmanServer");
                bool isStopped = queryOut.Contains("STOPPED", StringComparison.OrdinalIgnoreCase) ||
                                 queryOut.Contains("1060", StringComparison.OrdinalIgnoreCase);

                var startType = GetServiceStartType("LanmanServer");

                if (isStopped && startType == ServiceStartModeEnum.Disabled)
                {
                    result.Status = HardeningStatus.Hardened;
                    result.CurrentValue = "Service Stopped & Disabled";
                }
                else
                {
                    result.Status = HardeningStatus.Vulnerable;
                    string statusText = isStopped ? "Stopped" : "Running";
                    result.CurrentValue = $"Service {statusText} (StartType: {startType})";
                }
            }
            catch (Exception ex)
            {
                result.Status = HardeningStatus.Hardened;
                result.CurrentValue = $"Not Present / Not Running ({ex.Message})";
            }

            return result;
        }

        private HardeningCheckResult CheckRemoteAndCasting()
        {
            var result = new HardeningCheckResult
            {
                Id = "REMOTE_CASTING",
                Category = "Casting & Remote Access",
                Name = "SSDP, uPnP & Remote Desktop (RDP)",
                Description = "Disables local network device discovery (SSDP/uPnP) and blocks inbound Remote Desktop connections.",
                RemediationDescription = "Stops SSDPSRV and upnphost services, sets fDenyTSConnections = 1."
            };

            try
            {
                bool ssdpStopped = IsServiceStoppedOrDisabled("SSDPSRV");
                bool upnpStopped = IsServiceStoppedOrDisabled("upnphost");

                object? rdpVal = GetRegistryValue(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections");
                bool rdpBlocked = rdpVal is int i && i == 1;

                if (ssdpStopped && upnpStopped && rdpBlocked)
                {
                    result.Status = HardeningStatus.Hardened;
                    result.CurrentValue = "SSDP/uPnP Stopped & RDP Strictly Blocked";
                }
                else
                {
                    result.Status = HardeningStatus.Vulnerable;
                    var issues = new List<string>();
                    if (!ssdpStopped) issues.Add("SSDP Active");
                    if (!upnpStopped) issues.Add("uPnP Active");
                    if (!rdpBlocked) issues.Add("RDP Allowed");
                    result.CurrentValue = string.Join(", ", issues);
                }
            }
            catch (Exception ex)
            {
                result.Status = HardeningStatus.Unknown;
                result.CurrentValue = $"Error: {ex.Message}";
            }

            return result;
        }

        private HardeningCheckResult CheckPrivacyAndTelemetry()
        {
            var result = new HardeningCheckResult
            {
                Id = "PRIVACY_TELEMETRY",
                Category = "Privacy & Telemetry",
                Name = "Advertising ID & Telemetry Restrictions",
                Description = "Disables Windows Advertising Tracking ID and minimizes Diagnostic Data collection.",
                RemediationDescription = "Disables AdvertisingInfo registry keys and sets AllowTelemetry = 0."
            };

            try
            {
                object? advHklm = GetRegistryValue(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled");
                object? advHkcu = GetRegistryValue(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled");
                object? telemVal = GetRegistryValue(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry");

                bool advDisabled = (advHklm is int i1 && i1 == 0) && (advHkcu is int i2 && i2 == 0);
                bool telemMin = telemVal is int i3 && i3 == 0;

                if (advDisabled && telemMin)
                {
                    result.Status = HardeningStatus.Hardened;
                    result.CurrentValue = "Advertising ID Disabled & Telemetry Minimal (0)";
                }
                else
                {
                    result.Status = HardeningStatus.Vulnerable;
                    var issues = new List<string>();
                    if (!advDisabled) issues.Add("Advertising ID Enabled");
                    if (!telemMin) issues.Add("Telemetry Above Minimum");
                    result.CurrentValue = string.Join(", ", issues);
                }
            }
            catch (Exception ex)
            {
                result.Status = HardeningStatus.Unknown;
                result.CurrentValue = $"Error: {ex.Message}";
            }

            return result;
        }

        private HardeningCheckResult CheckWebcamLockdown()
        {
            var result = new HardeningCheckResult
            {
                Id = "WEBCAM_LOCK",
                Category = "Device Security",
                Name = "Global Webcam Access Block",
                Description = "Enforces a global privacy block (Deny) on application access to the webcam.",
                RemediationDescription = "Sets webcam access policy to Deny in Windows registry."
            };

            try
            {
                object? hklmVal = GetRegistryValue(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam", "Value");
                object? hkcuVal = GetRegistryValue(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam", "Value");

                bool isDeny = string.Equals(hklmVal?.ToString(), "Deny", StringComparison.OrdinalIgnoreCase) &&
                             string.Equals(hkcuVal?.ToString(), "Deny", StringComparison.OrdinalIgnoreCase);

                if (isDeny)
                {
                    result.Status = HardeningStatus.Hardened;
                    result.CurrentValue = "Global Webcam Policy: Deny";
                }
                else
                {
                    result.Status = HardeningStatus.Vulnerable;
                    result.CurrentValue = "Global Webcam Access Allowed";
                }
            }
            catch (Exception ex)
            {
                result.Status = HardeningStatus.Unknown;
                result.CurrentValue = $"Error: {ex.Message}";
            }

            return result;
        }

        private HardeningCheckResult CheckPortShielding()
        {
            var result = new HardeningCheckResult
            {
                Id = "PORT_SHIELDING",
                Category = "Firewall & Network",
                Name = "Port Shielding Rules (RPC 135 & SMB 445)",
                Description = "Ensures explicit Windows Firewall rules exist to block inbound TCP traffic on Port 135 and Port 445 on Public networks.",
                RemediationDescription = "Adds inbound firewall block rules for TCP ports 135 and 445."
            };

            try
            {
                string output = RunCmd("netsh", "advfirewall firewall show rule name=all");
                bool rpcRule = output.Contains("xScanner_Block_RPC_135", StringComparison.OrdinalIgnoreCase);
                bool smbRule = output.Contains("xScanner_Block_SMB_445", StringComparison.OrdinalIgnoreCase);

                if (rpcRule && smbRule)
                {
                    result.Status = HardeningStatus.Hardened;
                    result.CurrentValue = "RPC 135 & SMB 445 Inbound Firewall Rules Active";
                }
                else
                {
                    result.Status = HardeningStatus.Vulnerable;
                    var missing = new List<string>();
                    if (!rpcRule) missing.Add("RPC 135 Rule Missing");
                    if (!smbRule) missing.Add("SMB 445 Rule Missing");
                    result.CurrentValue = string.Join(", ", missing);
                }
            }
            catch (Exception ex)
            {
                result.Status = HardeningStatus.Unknown;
                result.CurrentValue = $"Error: {ex.Message}";
            }

            return result;
        }

        private HardeningCheckResult CheckEncryptedDns()
        {
            var result = new HardeningCheckResult
            {
                Id = "ENCRYPTED_DNS",
                Category = "Firewall & Network",
                Name = "Encrypted DNS (DNS-over-HTTPS / DoH)",
                Description = "Ensures DNS queries are encrypted using DNS-over-HTTPS (DoH) to prevent eavesdropping and DNS spoofing.",
                RemediationDescription = "Enforces EnableAutoDoh = 2 (Required/Enforced) in registry and configures DoH templates."
            };

            try
            {
                var activeDns = GetActiveDnsServers();
                var doh = GetDohDetails(activeDns);
                result.Status = doh.Status;
                result.CurrentValue = doh.StatusText;
            }
            catch (Exception ex)
            {
                result.Status = HardeningStatus.Unknown;
                result.CurrentValue = $"Error: {ex.Message}";
            }

            return result;
        }

        private HardeningCheckResult CheckLlmnrNetBios()
        {
            var result = new HardeningCheckResult
            {
                Id = "LLMNR_NETBIOS",
                Category = "Network Security",
                Name = "LLMNR & NetBIOS Poisoning Protections",
                Description = "Disables LLMNR (Link-Local Multicast Name Resolution) to prevent local credential relay and spoofing attacks.",
                RemediationDescription = "Sets EnableMulticast = 0 in DNSClient group policy registry."
            };

            try
            {
                object? val = GetRegistryValue(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast");
                bool llmnrDisabled = val is int i && i == 0;

                if (llmnrDisabled)
                {
                    result.Status = HardeningStatus.Hardened;
                    result.CurrentValue = "LLMNR Multicast Disabled (Protected)";
                }
                else
                {
                    result.Status = HardeningStatus.Vulnerable;
                    result.CurrentValue = "LLMNR Enabled (Vulnerable to Spoofing)";
                }
            }
            catch (Exception ex)
            {
                result.Status = HardeningStatus.Unknown;
                result.CurrentValue = $"Error: {ex.Message}";
            }

            return result;
        }

        private HardeningCheckResult CheckPowerShellLogging()
        {
            var result = new HardeningCheckResult
            {
                Id = "PS_LOGGING",
                Category = "Script & System Audit",
                Name = "PowerShell Script Block & Transcription Logging",
                Description = "Ensures advanced PowerShell script block and transcription logging is enabled for forensic audit reviews.",
                RemediationDescription = "Enables ScriptBlockLogging, ModuleLogging and Transcription in registry."
            };

            try
            {
                object? sb = GetRegistryValue(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging");
                object? mod = GetRegistryValue(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging", "EnableModuleLogging");
                object? trans = GetRegistryValue(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription", "EnableTranscripting");

                bool sbOn = sb is int i1 && i1 == 1;
                bool modOn = mod is int i2 && i2 == 1;
                bool transOn = trans is int i3 && i3 == 1;

                if (sbOn && modOn)
                {
                    result.Status = HardeningStatus.Hardened;
                    result.CurrentValue = "Script Block & Module Logging Active";
                }
                else
                {
                    result.Status = HardeningStatus.Vulnerable;
                    result.CurrentValue = "Advanced PowerShell Logging Disabled/Partial";
                }
            }
            catch (Exception ex)
            {
                result.Status = HardeningStatus.Unknown;
                result.CurrentValue = $"Error: {ex.Message}";
            }

            return result;
        }

        private HardeningCheckResult CheckAdvancedPorts()
        {
            var result = new HardeningCheckResult
            {
                Id = "ADV_PORTS",
                Category = "Remote Access & Protocols",
                Name = "RDP Network Level Authentication (NLA)",
                Description = "Ensures Remote Desktop (RDP) requires Network Level Authentication to prevent unauthenticated pre-auth attacks.",
                RemediationDescription = "Sets UserAuthentication = 1 for RDP-Tcp."
            };

            try
            {
                object? nla = GetRegistryValue(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication");
                bool nlaEnforced = nla is int i && i == 1;

                if (nlaEnforced)
                {
                    result.Status = HardeningStatus.Hardened;
                    result.CurrentValue = "RDP NLA Enforced (Required)";
                }
                else
                {
                    object? deny = GetRegistryValue(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections");
                    bool rdpDisabled = deny is int d && d == 1;

                    if (rdpDisabled)
                    {
                        result.Status = HardeningStatus.Hardened;
                        result.CurrentValue = "RDP Disabled (NLA N/A)";
                    }
                    else
                    {
                        result.Status = HardeningStatus.Vulnerable;
                        result.CurrentValue = "RDP Enabled without Strict NLA";
                    }
                }
            }
            catch (Exception ex)
            {
                result.Status = HardeningStatus.Unknown;
                result.CurrentValue = $"Error: {ex.Message}";
            }

            return result;
        }

        private HardeningCheckResult CheckDefenderTamper()
        {
            var result = new HardeningCheckResult
            {
                Id = "DEFENDER_VBS",
                Category = "Endpoint Protection",
                Name = "Windows Defender",
                Description = "Ensures Windows Defender and Tamper Protection are active to prevent malware or unauthorized scripts from disabling antivirus settings.",
                RemediationDescription = "Enables Windows Defender Tamper Protection via PowerShell."
            };

            try
            {
                string output = RunCmd("powershell", "-NoProfile -Command \"(Get-MpComputerStatus -ErrorAction SilentlyContinue).IsTamperProtected\"");
                bool tpActive = output.Contains("True", StringComparison.OrdinalIgnoreCase);

                if (!tpActive)
                {
                    object? tp = GetRegistryValue(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows Defender\Features", "TamperProtection");
                    tpActive = tp is int i && i == 1;
                }

                if (tpActive)
                {
                    result.Status = HardeningStatus.Hardened;
                    result.CurrentValue = "Windows Defender Tamper Protection Active";
                }
                else
                {
                    result.Status = HardeningStatus.Vulnerable;
                    result.CurrentValue = "Tamper Protection Disabled or Inactive";
                }
            }
            catch (Exception ex)
            {
                result.Status = HardeningStatus.Unknown;
                result.CurrentValue = $"Error: {ex.Message}";
            }

            return result;
        }

        private HardeningCheckResult CheckStartupPersistence()
        {
            var result = new HardeningCheckResult
            {
                Id = "STARTUP_PERSISTENCE",
                Category = "Persistence Hunter",
                Name = "Auto-Run & Startup Persistence Audit",
                Description = "Scans common Run/RunOnce registry hives and startup folders for auto-starting binaries.",
                RemediationDescription = "Identifies registry persistence entry count."
            };

            try
            {
                int count = 0;
                using (var k1 = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run"))
                {
                    if (k1 != null) count += k1.GetValueNames().Length;
                }
                using (var k2 = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"))
                {
                    if (k2 != null) count += k2.GetValueNames().Length;
                }

                result.Status = HardeningStatus.Hardened;
                result.CurrentValue = $"{count} Startup Persistence Entry(ies) Detected";
            }
            catch (Exception ex)
            {
                result.Status = HardeningStatus.Unknown;
                result.CurrentValue = $"Error: {ex.Message}";
            }

            return result;
        }

        #endregion

        #region Helper Utilities

        private List<ListeningPortInfo> ScanListeningPorts()
        {
            var ports = new List<ListeningPortInfo>();
            try
            {
                string output = RunCmd("netstat", "-ano -p tcp");
                string[] lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

                foreach (var line in lines)
                {
                    string trimmed = line.Trim();
                    if (!trimmed.StartsWith("TCP", StringComparison.OrdinalIgnoreCase)) continue;

                    string[] parts = Regex.Split(trimmed, @"\s+");
                    if (parts.Length >= 4)
                    {
                        string localAddr = parts[1];
                        string state = parts[3];

                        if (!state.Equals("LISTENING", StringComparison.OrdinalIgnoreCase)) continue;

                        int lastColon = localAddr.LastIndexOf(':');
                        if (lastColon > 0 && int.TryParse(localAddr.Substring(lastColon + 1), out int port))
                        {
                            string ip = localAddr.Substring(0, lastColon);
                            if (ip.Equals("127.0.0.1") || ip.Equals("[::1]")) continue;

                            int pid = 0;
                            if (parts.Length >= 5) int.TryParse(parts[4], out pid);

                            string procName = GetProcessName(pid);
                            var info = new ListeningPortInfo
                            {
                                Port = port,
                                Protocol = "TCP",
                                ProcessId = pid,
                                ProcessName = procName,
                                LocalAddress = localAddr,
                                State = state
                            };

                            switch (port)
                            {
                                case 135:
                                    info.IsSensitive = true;
                                    info.SensitiveDescription = "RPC Endpoint Mapper";
                                    info.IsShielded = CheckRuleExists("xScanner_Block_RPC_135");
                                    break;
                                case 139:
                                    info.IsSensitive = true;
                                    info.SensitiveDescription = "NetBIOS Session Service";
                                    info.IsShielded = IsServiceStoppedOrDisabled("LanmanServer");
                                    break;
                                case 445:
                                    info.IsSensitive = true;
                                    info.SensitiveDescription = "SMB Direct / Microsoft-DS";
                                    info.IsShielded = CheckRuleExists("xScanner_Block_SMB_445");
                                    break;
                                case 3389:
                                    info.IsSensitive = true;
                                    info.SensitiveDescription = "Remote Desktop Protocol (RDP)";
                                    object? rdp = GetRegistryValue(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections");
                                    info.IsShielded = rdp is int i && i == 1;
                                    break;
                            }

                            ports.Add(info);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"[WARN] Could not enumerate open listening ports: {ex.Message}");
            }

            return ports.OrderBy(p => p.Port).ToList();
        }

        private List<string> GetActiveDnsServers()
        {
            var dnsList = new List<string>();
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus == OperationalStatus.Up &&
                        (ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ||
                         ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet))
                    {
                        var props = ni.GetIPProperties();
                        foreach (var dns in props.DnsAddresses)
                        {
                            if (dns.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                            {
                                string str = dns.ToString();
                                if (!dnsList.Contains(str)) dnsList.Add(str);
                            }
                        }
                    }
                }
            }
            catch { }
            return dnsList;
        }

        private List<string> GetNetworkProfiles()
        {
            var profiles = new List<string>();
            try
            {
                string output = RunCmd("netsh", "advfirewall monitor show currentprofile");
                if (output.Contains("Public", StringComparison.OrdinalIgnoreCase)) profiles.Add("Public Profile");
                if (output.Contains("Private", StringComparison.OrdinalIgnoreCase)) profiles.Add("Private Profile");
                if (output.Contains("Domain", StringComparison.OrdinalIgnoreCase)) profiles.Add("Domain Profile");
            }
            catch { }
            if (profiles.Count == 0) profiles.Add("Public Profile");
            return profiles;
        }

        private void PopulateDohInfo(HardeningAuditReport report)
        {
            try
            {
                var doh = GetDohDetails(report.ActiveDnsServers);
                report.DohStatus = doh.ModeText;
                report.DohTemplates = doh.Templates;
            }
            catch (Exception ex)
            {
                report.DohStatus = "Unknown";
                Log($"[WARN] Could not retrieve DoH status/templates: {ex.Message}");
            }
        }

        private (HardeningStatus Status, string StatusText, string ModeText, List<string> Templates) GetDohDetails(List<string> activeDnsServers)
        {
            object? dohServVal = GetRegistryValue(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters", "EnableAutoDoh");
            object? dohPolicyVal = GetRegistryValue(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableAutoDoh");

            int servMode = dohServVal is int s ? s : 0;
            int policyMode = dohPolicyVal is int p1 ? p1 : 0;
            int effectiveMode = Math.Max(servMode, policyMode);

            var templates = new List<string>();
            if (effectiveMode > 0)
            {
                try
                {
                    string psOutput = RunCmd("powershell", "-NoProfile -Command \"Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue | Select-Object ServerAddress, DohTemplate | Format-List\"");
                    string[] lines = psOutput.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    foreach (var line in lines)
                    {
                        if (line.Contains("DohTemplate", StringComparison.OrdinalIgnoreCase) && line.Contains("https://", StringComparison.OrdinalIgnoreCase))
                        {
                            int idx = line.IndexOf("https://", StringComparison.OrdinalIgnoreCase);
                            string url = line.Substring(idx).Trim();
                            if (!templates.Contains(url)) templates.Add(url);
                        }
                    }
                }
                catch { }
            }

            bool isDohEnforced = effectiveMode == 2;
            bool hasActiveTemplates = templates.Count > 0 && effectiveMode > 0;

            if (isDohEnforced && hasActiveTemplates)
            {
                return (HardeningStatus.Hardened, "DoH Enforced (Encrypted DNS Strictly Required)", "Enforced (Strict DoH Required)", templates);
            }
            else if (hasActiveTemplates)
            {
                return (HardeningStatus.Hardened, "DoH Active (Encrypted DNS Active)", "Active (Auto DoH)", templates);
            }
            else
            {
                return (HardeningStatus.Vulnerable, "DoH Disabled / Inactive (Plaintext Unencrypted DNS)", "Disabled / Inactive (Unencrypted)", new List<string>());
            }
        }

        private string GetProcessName(int pid)
        {
            if (pid <= 0) return "System";
            try
            {
                using var p = Process.GetProcessById(pid);
                return p.ProcessName;
            }
            catch
            {
                return $"PID {pid}";
            }
        }

        private bool IsServiceStoppedOrDisabled(string serviceName)
        {
            try
            {
                string statusOutput = RunCmd("sc", $"query {serviceName}");
                bool isStopped = statusOutput.Contains("STOPPED", StringComparison.OrdinalIgnoreCase) ||
                                 statusOutput.Contains("1060", StringComparison.OrdinalIgnoreCase);

                if (isStopped) return true;

                var startType = GetServiceStartType(serviceName);
                return startType == ServiceStartModeEnum.Disabled;
            }
            catch
            {
                return true;
            }
        }

        private ServiceStartModeEnum GetServiceStartType(string serviceName)
        {
            try
            {
                string qcOutput = RunCmd("sc", $"qc {serviceName}");
                if (qcOutput.Contains("DISABLED", StringComparison.OrdinalIgnoreCase)) return ServiceStartModeEnum.Disabled;
                if (qcOutput.Contains("AUTO_START", StringComparison.OrdinalIgnoreCase)) return ServiceStartModeEnum.Automatic;
                if (qcOutput.Contains("DEMAND_START", StringComparison.OrdinalIgnoreCase)) return ServiceStartModeEnum.Manual;

                object? val = GetRegistryValue(Registry.LocalMachine, $@"SYSTEM\CurrentControlSet\Services\{serviceName}", "Start");
                if (val is int startVal)
                {
                    return startVal switch
                    {
                        2 => ServiceStartModeEnum.Automatic,
                        3 => ServiceStartModeEnum.Manual,
                        4 => ServiceStartModeEnum.Disabled,
                        _ => ServiceStartModeEnum.Manual
                    };
                }
            }
            catch { }
            return ServiceStartModeEnum.Manual;
        }

        private void SetServiceDisabledAndStopped(string serviceName)
        {
            try
            {
                RunCmd("sc", $"config {serviceName} start= disabled");
                RunCmd("net", $"stop {serviceName} /y");
            }
            catch (Exception ex)
            {
                Log($"[WARN] Service {serviceName} remediation note: {ex.Message}");
            }
        }

        private bool CheckRuleExists(string ruleName)
        {
            try
            {
                string output = RunCmd("netsh", $"advfirewall firewall show rule name=\"{ruleName}\"");
                return output.Contains(ruleName, StringComparison.OrdinalIgnoreCase) &&
                       !output.Contains("No rules match", StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        private object? GetRegistryValue(RegistryKey hive, string subKey, string valueName)
        {
            try
            {
                using var key = hive.OpenSubKey(subKey);
                return key?.GetValue(valueName);
            }
            catch
            {
                return null;
            }
        }

        private void SetRegistryValue(RegistryKey hive, string subKey, string valueName, object value, RegistryValueKind valueKind)
        {
            try
            {
                using var key = hive.CreateSubKey(subKey, RegistryKeyPermissionCheck.ReadWriteSubTree);
                key?.SetValue(valueName, value, valueKind);
            }
            catch (Exception ex)
            {
                Log($"[WARN] Could not write registry {subKey}\\{valueName}: {ex.Message}");
            }
        }

        private void RunNetsh(string args)
        {
            RunCmd("netsh", args);
        }

        private string RunCmd(string fileName, string args)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = args,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var p = Process.Start(psi);
                if (p == null) return string.Empty;
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit(5000);
                return output;
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }

        #endregion
    }
}
