using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace xScanner.Core.ScanEngine.Scanners
{
    public class ProcessScanner : IScanProvider
    {
        public string Id => "ProcessScanner";
        public string DisplayName => "Process & Loaded Modules Scanner";
        public ScanScope Scope => ScanScope.Basic;

        public async Task ScanAsync(ScanResultContext context, CancellationToken cancellationToken)
        {
            context.SetProviderStatus(Id, ProviderExecutionStatus.Running, "Enumerating running processes...");
            var sw = Stopwatch.StartNew();
            int count = 0;

            try
            {
                var processes = Process.GetProcesses();
                foreach (var proc in processes)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    count++;
                    context.ScannedProcesses++;

                    string procName = string.Empty;
                    string executablePath = string.Empty;
                    int pid = proc.Id;

                    try
                    {
                        procName = proc.ProcessName;
                    }
                    catch { }

                    try
                    {
                        executablePath = proc.MainModule?.FileName ?? string.Empty;
                    }
                    catch
                    {
                        // Access denied or system process without main module access
                        context.AddAccessDenied($"Process {pid} ({procName})");
                    }

                    if (!string.IsNullOrEmpty(executablePath))
                    {
                        bool isSuspiciousLocation = IsSuspiciousPath(executablePath);
                        if (isSuspiciousLocation)
                        {
                            context.AddFinding(new ScanFinding
                            {
                                ProviderId = Id,
                                Category = "Process Execution",
                                Title = $"Suspicious Process Path: {procName} (PID {pid})",
                                Description = $"Process executable is running from a suspicious or user-writable location: {executablePath}",
                                Path = executablePath,
                                ProcessName = procName,
                                ProcessId = pid,
                                Severity = FindingSeverity.Medium,
                                Confidence = FindingConfidence.Medium,
                                Type = FindingType.Process,
                                IsActionable = true
                            });
                        }
                    }
                }

                sw.Stop();
                context.SetProviderStatus(Id, ProviderExecutionStatus.Completed, $"Scanned {count} processes successfully.");
            }
            catch (Exception ex)
            {
                sw.Stop();
                context.SetProviderStatus(Id, ProviderExecutionStatus.Failed, ex.Message);
                context.AddError($"ProcessScanner error: {ex.Message}");
            }

            await Task.CompletedTask;
        }

        private bool IsSuspiciousPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            var lower = path.ToLowerInvariant();

            // Check temp, appdata, downloads, desktop, programdata user-writable areas
            if (lower.Contains("\\temp\\") ||
                lower.Contains("\\appdata\\local\\temp") ||
                lower.Contains("\\downloads\\") ||
                lower.Contains("\\desktop\\") ||
                lower.Contains("\\recyler\\") ||
                lower.Contains("\\$recycle.bin\\"))
            {
                return true;
            }

            return false;
        }
    }
}
