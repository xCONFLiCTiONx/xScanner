using System;
using System.Collections.Generic;

namespace xScanner.Core.Hardening
{
    public enum HardeningStatus
    {
        Hardened,
        Vulnerable,
        Warning,
        Unknown
    }

    public enum ServiceStartModeEnum
    {
        Automatic,
        Manual,
        Disabled,
        Unknown
    }

    public class DohProvider
    {
        public string Name { get; set; } = string.Empty;
        public string Ipv4Primary { get; set; } = string.Empty;
        public string Ipv4Secondary { get; set; } = string.Empty;
        public string Ipv6Primary { get; set; } = string.Empty;
        public string Ipv6Secondary { get; set; } = string.Empty;
        public string TemplateUrl { get; set; } = string.Empty;

        public override string ToString() => Name;

        public static List<DohProvider> GetPopularProviders()
        {
            return new List<DohProvider>
            {
                new DohProvider
                {
                    Name = "Cloudflare Security (1.1.1.2 - Malware Blocking)",
                    Ipv4Primary = "1.1.1.2",
                    Ipv4Secondary = "1.0.0.2",
                    Ipv6Primary = "2606:4700:4700::1112",
                    Ipv6Secondary = "2606:4700:4700::1002",
                    TemplateUrl = "https://security.cloudflare-dns.com/dns-query"
                },
                new DohProvider
                {
                    Name = "Cloudflare Standard (1.1.1.1 - High Speed)",
                    Ipv4Primary = "1.1.1.1",
                    Ipv4Secondary = "1.0.0.1",
                    Ipv6Primary = "2606:4700:4700::1111",
                    Ipv6Secondary = "2606:4700:4700::1001",
                    TemplateUrl = "https://cloudflare-dns.com/dns-query"
                },
                new DohProvider
                {
                    Name = "Google Public DNS (8.8.8.8)",
                    Ipv4Primary = "8.8.8.8",
                    Ipv4Secondary = "8.8.4.4",
                    Ipv6Primary = "2001:4860:4860::8888",
                    Ipv6Secondary = "2001:4860:4860::8844",
                    TemplateUrl = "https://dns.google/dns-query"
                },
                new DohProvider
                {
                    Name = "Quad9 Security (9.9.9.9 - Threat Blocking)",
                    Ipv4Primary = "9.9.9.9",
                    Ipv4Secondary = "149.112.112.112",
                    Ipv6Primary = "2620:fe::fe",
                    Ipv6Secondary = "2620:fe::9",
                    TemplateUrl = "https://dns.quad9.net/dns-query"
                },
                new DohProvider
                {
                    Name = "AdGuard DNS (94.140.14.14 - Ad & Tracker Block)",
                    Ipv4Primary = "94.140.14.14",
                    Ipv4Secondary = "94.140.15.15",
                    Ipv6Primary = "2a10:50c0::ad1:ff",
                    Ipv6Secondary = "2a10:50c0::ad2:ff",
                    TemplateUrl = "https://dns.adguard-dns.com/dns-query"
                },
                new DohProvider
                {
                    Name = "Cisco Umbrella / OpenDNS (208.67.222.222)",
                    Ipv4Primary = "208.67.222.222",
                    Ipv4Secondary = "208.67.220.220",
                    Ipv6Primary = "2620:119:35::35",
                    Ipv6Secondary = "2620:119:53::53",
                    TemplateUrl = "https://doh.opendns.com/dns-query"
                }
            };
        }
    }

    public class HardeningCheckResult
    {
        public string Id { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public HardeningStatus Status { get; set; } = HardeningStatus.Unknown;
        public string CurrentValue { get; set; } = string.Empty;
        public string RemediationDescription { get; set; } = string.Empty;
        public bool IsSelected { get; set; } = true;

        public string StatusIcon => Status switch
        {
            HardeningStatus.Hardened => "\uE73E",    // Checkmark
            HardeningStatus.Vulnerable => "\uE814",  // Error / X
            HardeningStatus.Warning => "\uE7BA",     // Warning triangle
            _ => "\uE9CE"                             // Question mark
        };

        public string StatusColor => Status switch
        {
            HardeningStatus.Hardened => "#28A745",   // Green
            HardeningStatus.Vulnerable => "#DC3545",  // Red
            HardeningStatus.Warning => "#FFC107",     // Yellow / Warning
            _ => "#6C757D"                            // Gray
        };

        public string StatusText => Status switch
        {
            HardeningStatus.Hardened => "Hardened",
            HardeningStatus.Vulnerable => "Vulnerable",
            HardeningStatus.Warning => "Warning",
            _ => "Unknown"
        };
    }

    public class ListeningPortInfo
    {
        public int Port { get; set; }
        public string Protocol { get; set; } = "TCP";
        public string ProcessName { get; set; } = string.Empty;
        public int ProcessId { get; set; }
        public string LocalAddress { get; set; } = string.Empty;
        public string State { get; set; } = string.Empty;
        public bool IsSensitive { get; set; }
        public string SensitiveDescription { get; set; } = string.Empty;
        public bool IsShielded { get; set; }

        public string StatusText => IsSensitive
            ? (IsShielded ? "Sensitive (Shielded)" : "Sensitive (Exposed!)")
            : "Active Port";

        public string StatusColor => IsSensitive
            ? (IsShielded ? "#28A745" : "#DC3545")
            : "#17A2B8";
    }

    public class HardeningAuditReport
    {
        public DateTime ScanTime { get; set; } = DateTime.Now;
        public int ScorePercentage { get; set; }
        public int TotalChecks { get; set; }
        public int PassedChecks { get; set; }
        public int FailedChecks { get; set; }
        public List<HardeningCheckResult> CheckResults { get; set; } = new();
        public List<ListeningPortInfo> ListeningPorts { get; set; } = new();
        public List<string> ActiveDnsServers { get; set; } = new();
        public List<string> NetworkProfiles { get; set; } = new();
        public string DohStatus { get; set; } = "Disabled";
        public List<string> DohTemplates { get; set; } = new();
        public bool IsFullyHardened => FailedChecks == 0 && TotalChecks > 0;
    }
}
