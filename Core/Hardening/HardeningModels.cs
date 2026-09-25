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

    public class HardeningCheckResult
    {
        public string Id { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public HardeningStatus Status { get; set; } = HardeningStatus.Unknown;
        public string CurrentValue { get; set; } = string.Empty;
        public string RemediationDescription { get; set; } = string.Empty;

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
