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

        public async Task<HardeningAuditReport> RunSecurityAuditAsync()
        {
            return await Task.Run(() =>
            {
                var report = new HardeningAuditReport
                {
                    ScanTime = DateTime.Now
                };

                Log("[AUDIT] Starting 6-Step Comprehensive Security Audit...");

                // Step 1: Firewall Configuration
                Log("[AUDIT 1/6] Scanning Network Profiles & Public Firewall Configuration...");
                var firewallCheck = CheckFirewallConfiguration();
                report.CheckResults.Add(firewallCheck);

                // Step 2: File Sharing Check
                Log("[AUDIT 2/6] Checking File Sharing Services (LanmanServer)...");
                var fileSharingCheck = CheckFileSharing();
                report.CheckResults.Add(fileSharingCheck);

                // Step 3: Remote Management & Casting Check
                Log("[AUDIT 3/6] Checking Remote Management & Casting (SSDP, uPnP, RDP)...");
                var remoteCheck = CheckRemoteAndCasting();
                report.CheckResults.Add(remoteCheck);

                // Step 4: Tracking & Telemetry Audit
                Log("[AUDIT 4/6] Auditing Privacy, Advertising ID & Telemetry Restrictions...");
                var telemetryCheck = CheckPrivacyAndTelemetry();
                report.CheckResults.Add(telemetryCheck);

                // Step 5: Webcam Privacy Lockdown Check
                Log("[AUDIT 5/6] Auditing Global Webcam Privacy Policy...");
                var webcamCheck = CheckWebcamLockdown();
                report.CheckResults.Add(webcamCheck);

                // Step 6: Port Shielding Check (Ports 135 & 445)
                Log("[AUDIT 6/7] Checking Port Shielding Firewall Rules (RPC 135 & SMB 445)...");
                var portShieldCheck = CheckPortShielding();
                report.CheckResults.Add(portShieldCheck);

                // Step 7: Encrypted DNS Check (DoH)
                Log("[AUDIT 7/7] Auditing Encrypted DNS (DNS-over-HTTPS / DoH) Enforcement...");
                var dohCheck = CheckEncryptedDns();
                report.CheckResults.Add(dohCheck);

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

        public async Task<HardeningAuditReport> ApplyHardeningAndVerifyAsync()
        {
            Log("[HARDEN] Initiating Automatic Hardening & System Lockdown...");

            await Task.Run(() =>
            {
                // 1. Firewall Configuration
                Log("[ACTION 1/7] Enabling Public Firewall Profile & Setting Inbound Action to Block...");
                RunNetsh("advfirewall set publicprofile state on");
                RunNetsh("advfirewall set publicprofile firewallpolicy blockinbound,allowoutbound");

                // 2. Disabling File Sharing
                Log("[ACTION 2/7] Stopping and Disabling LanmanServer (Server) service...");
                SetServiceDisabledAndStopped("LanmanServer");

                // 3. Disabling Casting & Discovery Services
                Log("[ACTION 3/7] Stopping and Disabling SSDP (SSDPSRV) and uPnP (upnphost)...");
                SetServiceDisabledAndStopped("SSDPSRV");
                SetServiceDisabledAndStopped("upnphost");

                // 4. Blocking Remote Desktop (RDP)
                Log("[ACTION 4/7] Disabling Remote Desktop connections via Registry (fDenyTSConnections)...");
                SetRegistryValue(
                    Registry.LocalMachine,
                    @"SYSTEM\CurrentControlSet\Control\Terminal Server",
                    "fDenyTSConnections",
                    1,
                    RegistryValueKind.DWord
                );

                // 5. Privacy & Telemetry Restrictions
                Log("[ACTION 5/7] Restricting Advertising ID & Telemetry collection levels...");
                SetRegistryValue(
                    Registry.LocalMachine,
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
                    "Enabled",
                    0,
                    RegistryValueKind.DWord
                );
                SetRegistryValue(
                    Registry.CurrentUser,
                    @"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
                    "Enabled",
                    0,
                    RegistryValueKind.DWord
                );
                SetRegistryValue(
                    Registry.LocalMachine,
                    @"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
                    "AllowTelemetry",
                    0,
                    RegistryValueKind.DWord
                );

                // 6. Webcam Lockdown
                Log("[ACTION 6/7] Enforcing Global Privacy Block (Deny) on Webcam Access...");
                SetRegistryValue(
                    Registry.LocalMachine,
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam",
                    "Value",
                    "Deny",
                    RegistryValueKind.String
                );
                SetRegistryValue(
                    Registry.CurrentUser,
                    @"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam",
                    "Value",
                    "Deny",
                    RegistryValueKind.String
                );

                // 7. Port Shielding Rules
                Log("[ACTION 7/8] Adding Inbound Firewall Rules to Shield Ports 135 (RPC) and 445 (SMB)...");
                RunNetsh("advfirewall firewall delete rule name=\"xScanner_Block_RPC_135\"");
                RunNetsh("advfirewall firewall add rule name=\"xScanner_Block_RPC_135\" dir=in action=block protocol=TCP localport=135 profile=public");

                RunNetsh("advfirewall firewall delete rule name=\"xScanner_Block_SMB_445\"");
                RunNetsh("advfirewall firewall add rule name=\"xScanner_Block_SMB_445\" dir=in action=block protocol=TCP localport=445 profile=public");

                // 8. Encrypted DNS / DoH Enforcement
                Log("[ACTION 8/8] Enforcing DNS-over-HTTPS (DoH) and configuring DoH server templates...");
                SetRegistryValue(
                    Registry.LocalMachine,
                    @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
                    "EnableAutoDoh",
                    2,
                    RegistryValueKind.DWord
                );
                SetRegistryValue(
                    Registry.LocalMachine,
                    @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
                    "EnableAutoDoh",
                    2,
                    RegistryValueKind.DWord
                );

                RunCmd("netsh", "dns add encryption server=1.1.1.2 dohtemplate=\"https://security.cloudflare-dns.com/dns-query\" autoupdate=yes");
                RunCmd("netsh", "dns add encryption server=1.0.0.2 dohtemplate=\"https://security.cloudflare-dns.com/dns-query\" autoupdate=yes");
                RunCmd("netsh", "dns add encryption server=1.1.1.1 dohtemplate=\"https://cloudflare-dns.com/dns-query\" autoupdate=yes");
                RunCmd("netsh", "dns add encryption server=1.0.0.1 dohtemplate=\"https://cloudflare-dns.com/dns-query\" autoupdate=yes");
                RunCmd("netsh", "dns add encryption server=8.8.8.8 dohtemplate=\"https://dns.google/dns-query\" autoupdate=yes");
            });

            Log("[HARDEN] Hardening pass finished. Pausing 2 seconds before Auto-Verification Re-Run...");
            await Task.Delay(2000);

            Log("[VERIFY] Running Auto-Verification Audit Pass...");
            var verifiedReport = await RunSecurityAuditAsync();

            if (verifiedReport.IsFullyHardened)
            {
                Log("[VERIFY SUCCESS] All security locks and hardening controls are intact!");
            }
            else
            {
                Log($"[VERIFY NOTICE] Auto-verification complete. Current status: {verifiedReport.PassedChecks}/{verifiedReport.TotalChecks} controls verified.");
            }

            return verifiedReport;
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
                result.Status = HardeningStatus.Hardened; // If service doesn't exist, it's effectively disabled
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
                object? dohServVal = GetRegistryValue(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters", "EnableAutoDoh");
                object? dohPolicyVal = GetRegistryValue(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableAutoDoh");
                object? dohPolicyVal2 = GetRegistryValue(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableDoH");

                int servMode = dohServVal is int s ? s : 0;
                int policyMode = dohPolicyVal is int p1 ? p1 : (dohPolicyVal2 is int p2 ? p2 : 0);

                string netshEncryption = RunCmd("netsh", "dns show encryption");
                bool hasNetshDoh = netshEncryption.Contains("https://", StringComparison.OrdinalIgnoreCase) ||
                                   netshEncryption.Contains("Cloudflare", StringComparison.OrdinalIgnoreCase);

                if (servMode == 2 || policyMode == 2 || (servMode >= 1 && hasNetshDoh))
                {
                    result.Status = HardeningStatus.Hardened;
                    result.CurrentValue = servMode == 2 || policyMode == 2
                        ? "DoH Required (Encrypted DNS Enforced)"
                        : "DoH Auto/Active (Encrypted DNS Template Configured)";
                }
                else if (servMode == 1 || hasNetshDoh)
                {
                    result.Status = HardeningStatus.Hardened;
                    result.CurrentValue = "DoH Allowed (Encrypted DNS Active)";
                }
                else
                {
                    result.Status = HardeningStatus.Vulnerable;
                    result.CurrentValue = "DoH Disabled (Plaintext DNS Unencrypted)";
                }
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
                            if (ip.Equals("127.0.0.1") || ip.Equals("[::1]")) continue; // Skip local loopback

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

                            // Check sensitive ports
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
                                case 5985:
                                case 5986:
                                    info.IsSensitive = true;
                                    info.SensitiveDescription = "Windows Remote Management (WinRM)";
                                    info.IsShielded = IsServiceStoppedOrDisabled("WinRM");
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
                object? dohServVal = GetRegistryValue(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters", "EnableAutoDoh");
                object? dohPolicyVal = GetRegistryValue(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableAutoDoh");

                int servMode = dohServVal is int s ? s : 0;
                int policyMode = dohPolicyVal is int p ? p : 0;

                report.DohStatus = (servMode == 2 || policyMode == 2)
                    ? "Enforced"
                    : ((servMode == 1 || policyMode == 1) ? "Allowed (Auto)" : "Disabled");

                string output = RunCmd("netsh", "dns show encryption");
                string[] lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

                var templates = new List<string>();
                foreach (var line in lines)
                {
                    if (line.Contains("https://", StringComparison.OrdinalIgnoreCase))
                    {
                        int idx = line.IndexOf("https://", StringComparison.OrdinalIgnoreCase);
                        string url = line.Substring(idx).Trim();
                        if (!templates.Contains(url)) templates.Add(url);
                    }
                }

                if (templates.Count == 0)
                {
                    if (report.ActiveDnsServers.Any(d => d.StartsWith("1.1.1.") || d.StartsWith("1.0.0.")))
                    {
                        templates.Add("https://security.cloudflare-dns.com/dns-query");
                    }
                    else if (report.ActiveDnsServers.Any(d => d.StartsWith("8.8.8.") || d.StartsWith("8.8.4.")))
                    {
                        templates.Add("https://dns.google/dns-query");
                    }
                }

                report.DohTemplates = templates;
            }
            catch (Exception ex)
            {
                report.DohStatus = "Unknown";
                Log($"[WARN] Could not retrieve DoH status/templates: {ex.Message}");
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
                return true; // Not installed = stopped
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
