using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace xScanner.Core.ScanEngine
{
    public enum ScanScope
    {
        Basic,
        Full,
        Both
    }

    public enum FindingSeverity
    {
        Informational,
        Low,
        Medium,
        High,
        Critical
    }

    public enum FindingConfidence
    {
        Unknown,
        Low,
        Medium,
        High,
        Confirmed
    }

    public enum FindingType
    {
        Process,
        Persistence,
        File,
        Registry,
        Service,
        Driver,
        Task,
        Wmi,
        PowerShell,
        Browser,
        Network,
        Firewall,
        SecurityConfig,
        Memory,
        Forensics,
        Other
    }

    public enum ProviderExecutionStatus
    {
        Pending,
        Running,
        Completed,
        Partial,
        AccessDenied,
        Failed,
        Cancelled,
        Skipped
    }

    public sealed class ScanFinding
    {
        public string Id { get; init; } = Guid.NewGuid().ToString();
        public string ProviderId { get; init; } = string.Empty;
        public string Category { get; init; } = string.Empty;
        public string Title { get; init; } = string.Empty;
        public string Description { get; init; } = string.Empty;
        public string? Path { get; init; }
        public string? RegistryPath { get; init; }
        public string? ProcessName { get; init; }
        public int? ProcessId { get; init; }
        public string? CommandLine { get; init; }
        public string? Sha256 { get; init; }
        public FindingSeverity Severity { get; init; } = FindingSeverity.Low;
        public FindingConfidence Confidence { get; init; } = FindingConfidence.Unknown;
        public FindingType Type { get; init; } = FindingType.Other;
        public bool IsActionable { get; init; } = false;
        public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
    }

    public sealed class ProviderStatusInfo
    {
        public string ProviderId { get; init; } = string.Empty;
        public string DisplayName { get; init; } = string.Empty;
        public ProviderExecutionStatus Status { get; set; } = ProviderExecutionStatus.Pending;
        public string StatusMessage { get; set; } = string.Empty;
        public int FindingsCount { get; set; }
        public TimeSpan Duration { get; set; }
    }

    public sealed class ScanResultContext
    {
        public string ScanId { get; init; } = Guid.NewGuid().ToString();
        public string ScanType { get; init; } = "Basic";
        public DateTimeOffset StartTime { get; init; } = DateTimeOffset.UtcNow;
        public CancellationToken CancellationToken { get; init; }

        private readonly ConcurrentBag<ScanFinding> _findings = new();
        private readonly ConcurrentDictionary<string, ProviderStatusInfo> _providerStatuses = new();
        private readonly ConcurrentBag<string> _accessDeniedItems = new();
        private readonly ConcurrentBag<string> _errorItems = new();

        public long FilesExamined { get; set; }
        public long FilesScanned { get; set; }
        public long FilesSkipped { get; set; }
        public long ThreatsDetected { get; set; }
        public long SuspiciousFiles { get; set; }
        public long ScannedRegistryKeys { get; set; }
        public long ScannedServices { get; set; }
        public long ScannedTasks { get; set; }
        public long ScannedProcesses { get; set; }

        public IReadOnlyCollection<ScanFinding> Findings => _findings;
        public IReadOnlyDictionary<string, ProviderStatusInfo> ProviderStatuses => _providerStatuses;
        public IReadOnlyCollection<string> AccessDeniedItems => _accessDeniedItems;
        public IReadOnlyCollection<string> ErrorItems => _errorItems;

        public ScanResultContext(string scanType, CancellationToken cancellationToken)
        {
            ScanType = scanType;
            CancellationToken = cancellationToken;
        }

        public void AddFinding(ScanFinding finding)
        {
            _findings.Add(finding);
            if (_providerStatuses.TryGetValue(finding.ProviderId, out var status))
            {
                status.FindingsCount++;
            }
        }

        public void RegisterProvider(string providerId, string displayName)
        {
            _providerStatuses[providerId] = new ProviderStatusInfo
            {
                ProviderId = providerId,
                DisplayName = displayName,
                Status = ProviderExecutionStatus.Pending
            };
        }

        public void SetProviderStatus(string providerId, ProviderExecutionStatus status, string message = "")
        {
            if (_providerStatuses.TryGetValue(providerId, out var info))
            {
                info.Status = status;
                info.StatusMessage = message;
            }
        }

        public void AddAccessDenied(string item)
        {
            _accessDeniedItems.Add(item);
        }

        public void AddError(string error)
        {
            _errorItems.Add(error);
        }
    }

    public interface IScanProvider
    {
        string Id { get; }
        string DisplayName { get; }
        ScanScope Scope { get; }

        Task ScanAsync(ScanResultContext context, CancellationToken cancellationToken);
    }
}
