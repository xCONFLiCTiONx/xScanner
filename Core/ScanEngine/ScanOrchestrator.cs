using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using xScanner.Analysis;
using xScanner.Core.FileSystem;
using xScanner.Core.ScanCache;
using xScanner.Core.ScanEscalation;
using xScanner.Core.ScanEngine.Scanners;
using xScanner.Database;
using xScanner.Database.Models;
using xScanner.Engines.ClamAV;
using xScanner.Quarantine;

namespace xScanner.Core.ScanEngine
{
    public class ScanProgressEventArgs
    {
        public string CurrentFile { get; set; } = string.Empty;
        public long FilesExamined { get; set; }
        public long FilesScanned { get; set; }
        public long FilesSkipped { get; set; }
        public long ThreatsDetected { get; set; }
        public long SuspiciousFiles { get; set; }
        public bool IsCompleted { get; set; }
        public string LogMessage { get; set; } = string.Empty;
        public bool IsIndeterminate { get; set; } = true;
        public long TotalFiles { get; set; }
        public List<ScanFinding> Findings { get; set; } = new();
    }

    public class ScanOrchestrator
    {
        private readonly ScanDatabase _database;
        private readonly ClamAvManager _clamManager;
        private readonly ScanCacheManager _cacheManager;
        private readonly EscalationManager _escalationManager;
        private readonly QuarantineManager _quarantineManager;
        private readonly List<IScanProvider> _providers;

        public ScanOrchestrator(ScanDatabase database, ClamAvManager clamManager)
        {
            _database = database;
            _clamManager = clamManager;
            _cacheManager = new ScanCacheManager(database);
            _escalationManager = new EscalationManager(database, clamManager);
            _quarantineManager = new QuarantineManager(database);

            _providers = new List<IScanProvider>
            {
                new ProcessScanner(),
                new StartupPersistenceScanner(),
                new ServiceAndDriverScanner(),
                new TaskAndWmiScanner(),
                new SystemConfigScanner(),
                new ActiveNetworkAndBinScanner(),
                new FullFilesystemScanner(),
                new NtfsForensicsScanner(),
                new AdvancedRegistryExtensibilityScanner(),
                new ForensicArtifactsScanner(),
                new AdvancedSecurityAndMemoryScanner()
            };
        }

        public async Task RunBasicScanAsync(List<string>? exclusions, Action<ScanProgressEventArgs> onProgress, CancellationToken cancellationToken = default)
        {
            exclusions ??= _database.GetExclusions();
            onProgress?.Invoke(new ScanProgressEventArgs { CurrentFile = "Enumerating basic scan locations...", LogMessage = "[INFO] Starting basic scan file enumeration...", IsIndeterminate = true });
            var files = await Task.Run(() => FileEnumerator.GetBasicScanFiles(exclusions, cancellationToken), cancellationToken);
            var fileList = new List<string>(files);
            if (cancellationToken.IsCancellationRequested) return;

            onProgress?.Invoke(new ScanProgressEventArgs
            {
                CurrentFile = $"Found {fileList.Count} files to scan.",
                LogMessage = $"[INFO] Basic candidate enumeration: {fileList.Count} files found.",
                IsIndeterminate = false,
                TotalFiles = fileList.Count
            });

            var context = new ScanResultContext("Basic", cancellationToken);
            await RunProvidersAsync(ScanScope.Basic, context, onProgress, cancellationToken);

            await RunScanInternalAsync("Basic", fileList, context, onProgress, cancellationToken);
        }

        public async Task RunBasicScanAsync(Action<ScanProgressEventArgs> onProgress, CancellationToken cancellationToken = default)
        {
            await RunBasicScanAsync(null, onProgress, cancellationToken);
        }

        public async Task RunFullScanAsync(List<string> exclusions, Action<ScanProgressEventArgs> onProgress, CancellationToken cancellationToken = default)
        {
            onProgress?.Invoke(new ScanProgressEventArgs { CurrentFile = "Enumerating all fixed drives...", LogMessage = "[INFO] Starting full scan file enumeration across fixed drives...", IsIndeterminate = true });
            var files = await Task.Run(() => FileEnumerator.GetFullScanFiles(exclusions, cancellationToken), cancellationToken);
            var fileList = new List<string>(files);
            if (cancellationToken.IsCancellationRequested) return;

            onProgress?.Invoke(new ScanProgressEventArgs
            {
                CurrentFile = $"Found {fileList.Count} files to scan.",
                LogMessage = $"[INFO] Full candidate enumeration: {fileList.Count} files found across fixed drives.",
                IsIndeterminate = false,
                TotalFiles = fileList.Count
            });

            var context = new ScanResultContext("Full", cancellationToken);
            await RunProvidersAsync(ScanScope.Both, context, onProgress, cancellationToken);

            await RunScanInternalAsync("Full", fileList, context, onProgress, cancellationToken);
        }

        private async Task RunProvidersAsync(ScanScope targetScope, ScanResultContext context, Action<ScanProgressEventArgs>? onProgress, CancellationToken cancellationToken)
        {
            foreach (var provider in _providers)
            {
                cancellationToken.ThrowIfCancellationRequested();

                bool shouldRun = provider.Scope == ScanScope.Both ||
                                 provider.Scope == targetScope ||
                                 (targetScope == ScanScope.Both && (provider.Scope == ScanScope.Basic || provider.Scope == ScanScope.Full));

                if (!shouldRun) continue;

                context.RegisterProvider(provider.Id, provider.DisplayName);
                onProgress?.Invoke(new ScanProgressEventArgs
                {
                    CurrentFile = $"Running {provider.DisplayName}...",
                    LogMessage = $"[INFO] Starting provider: {provider.DisplayName}",
                    IsIndeterminate = true
                });

                try
                {
                    await provider.ScanAsync(context, cancellationToken);

                    if (context.ProviderStatuses.TryGetValue(provider.Id, out var statusInfo))
                    {
                        if (!string.IsNullOrEmpty(statusInfo.StatusMessage))
                        {
                            foreach (var line in statusInfo.StatusMessage.Split('\n'))
                            {
                                if (!string.IsNullOrWhiteSpace(line))
                                {
                                    onProgress?.Invoke(new ScanProgressEventArgs
                                    {
                                        LogMessage = $"[COMPLETED] {line.Trim()}",
                                        IsIndeterminate = true
                                    });
                                }
                            }
                        }
                    }

                    foreach (var finding in context.Findings)
                    {
                        if (finding.ProviderId == provider.Id)
                        {
                            onProgress?.Invoke(new ScanProgressEventArgs
                            {
                                CurrentFile = finding.Title,
                                LogMessage = $"[FINDING] [{finding.Severity}] {finding.Title}: {finding.Description}",
                                IsIndeterminate = true,
                                Findings = new List<ScanFinding> { finding }
                            });
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    context.SetProviderStatus(provider.Id, ProviderExecutionStatus.Cancelled, "Scan cancelled.");
                    throw;
                }
                catch (Exception ex)
                {
                    context.SetProviderStatus(provider.Id, ProviderExecutionStatus.Failed, ex.Message);
                    context.AddError($"Provider {provider.Id} failed: {ex.Message}");
                    onProgress?.Invoke(new ScanProgressEventArgs
                    {
                        LogMessage = $"[WARNING] Provider {provider.DisplayName} encountered an error: {ex.Message}",
                        IsIndeterminate = true
                    });
                }
            }
        }

        private async Task RunScanInternalAsync(string scanType, List<string> filePaths, ScanResultContext resultContext, Action<ScanProgressEventArgs>? onProgress, CancellationToken cancellationToken = default)
        {
            var startTime = DateTime.Now;
            string defVersion = _clamManager.GetDefinitionVersion();

            long providerExamined = resultContext.FilesExamined;
            long candidateCount = filePaths.Count;
            long examined = providerExamined;
            long scanned = resultContext.FilesScanned;
            long skipped = resultContext.FilesSkipped;
            long threats = resultContext.ThreatsDetected;
            long suspicious = resultContext.SuspiciousFiles;
            long totalFiles = candidateCount + providerExamined;

            onProgress?.Invoke(new ScanProgressEventArgs
            {
                CurrentFile = $"Starting {scanType} file scan...",
                LogMessage = $"[INFO] Beginning ClamAV file scan of {candidateCount} candidates (plus {providerExamined} provider inputs, total to examine: {totalFiles}) using definitions v{defVersion}...",
                IsIndeterminate = false,
                TotalFiles = totalFiles
            });

            foreach (var file in filePaths)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    _database.InsertScanRecord(new ScanRecord
                    {
                        StartTime = startTime,
                        EndTime = DateTime.Now,
                        ScanType = scanType,
                        FilesExamined = examined,
                        FilesScanned = scanned,
                        FilesSkipped = skipped,
                        ThreatsDetected = threats,
                        SuspiciousFiles = suspicious,
                        DefinitionVersion = defVersion,
                        Status = "Stopped"
                    });

                    onProgress?.Invoke(new ScanProgressEventArgs
                    {
                        FilesExamined = examined,
                        FilesScanned = scanned,
                        FilesSkipped = skipped,
                        ThreatsDetected = threats,
                        SuspiciousFiles = suspicious,
                        IsCompleted = true,
                        LogMessage = $"[INFO] {scanType} scan stopped cleanly."
                    });

                    return;
                }

                examined++;
                string logMsg = string.Empty;

                if (_cacheManager.ShouldScanFile(file, defVersion, out var existingRecord))
                {
                    if (FileEnumerator.IsVirtualOrOffline(file))
                    {
                        skipped++;
                        continue;
                    }

                    scanned++;
                    string sha256 = string.Empty;
                    try
                    {
                        sha256 = Heuristics.ComputeSha256(file);
                    }
                    catch { }

                    bool isPeSuspicious = false;
                    PEAnalysisResult? peResult = null;
                    string ext = Path.GetExtension(file);
                    if (ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                        ext.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
                        ext.Equals(".sys", StringComparison.OrdinalIgnoreCase) ||
                        ext.Equals(".scr", StringComparison.OrdinalIgnoreCase) ||
                        ext.Equals(".com", StringComparison.OrdinalIgnoreCase))
                    {
                        peResult = PEAnalyzer.Analyze(file);
                        isPeSuspicious = peResult.IsSuspicious;
                        if (isPeSuspicious)
                        {
                            suspicious++;
                        }
                    }

                    var clamRes = await _clamManager.ScanFileAsync(file, cancellationToken);

                    string scanResult = "Clean";
                    if (clamRes.IsThreat)
                    {
                        threats++;
                        scanResult = "Threat";
                        logMsg = $"[THREAT] Threat detected: {clamRes.ThreatName} in {file}";
                        _database.InsertDetection(new DetectionRecord
                        {
                            FilePath = file,
                            ThreatName = clamRes.ThreatName,
                            StaticAnalysisStatus = isPeSuspicious ? "Suspicious" : "Normal",
                            ActionTaken = "Quarantined"
                        });

                        _quarantineManager.QuarantineFile(file, clamRes.ThreatName);
                        await _escalationManager.InvestigateAsync(file, clamRes.ThreatName);
                    }
                    else if (isPeSuspicious && peResult != null)
                    {
                        scanResult = "Suspicious";
                        string indicatorsSummary = string.Join("; ", peResult.Indicators);
                        logMsg = $"[SUSPICIOUS PE] Path: {file} | Reason: {indicatorsSummary} | Architecture: {peResult.Architecture} | Signed: {peResult.HasDigitalSignature} ({peResult.SignerName}) | SHA-256: {sha256} | Entropy: {peResult.MaxEntropy:F2} | Sections: {peResult.Sections.Count}";

                        _database.InsertDetection(new DetectionRecord
                        {
                            FilePath = file,
                            ThreatName = "Suspicious.PE",
                            StaticAnalysisStatus = "Suspicious",
                            ActionTaken = "Logged"
                        });
                    }

                    _database.UpsertFileRecord(new FileRecord
                    {
                        FilePath = file,
                        FileSize = new FileInfo(file).Exists ? new FileInfo(file).Length : 0,
                        LastModified = new FileInfo(file).Exists ? new FileInfo(file).LastWriteTime : DateTime.Now,
                        Sha256 = sha256,
                        LastScanTime = DateTime.Now,
                        ScanResult = scanResult,
                        DefinitionVersion = defVersion
                    });
                }
                else
                {
                    skipped++;
                }

                if (!string.IsNullOrEmpty(logMsg) || examined == 1 || examined % 250 == 0 || examined == totalFiles)
                {
                    onProgress?.Invoke(new ScanProgressEventArgs
                    {
                        CurrentFile = file,
                        FilesExamined = examined,
                        FilesScanned = scanned,
                        FilesSkipped = skipped,
                        ThreatsDetected = threats,
                        SuspiciousFiles = suspicious,
                        LogMessage = logMsg,
                        IsIndeterminate = false,
                        TotalFiles = totalFiles
                    });
                }
            }

            _database.InsertScanRecord(new ScanRecord
            {
                StartTime = startTime,
                EndTime = DateTime.Now,
                ScanType = scanType,
                FilesExamined = examined,
                FilesScanned = scanned,
                FilesSkipped = skipped,
                ThreatsDetected = threats,
                SuspiciousFiles = suspicious,
                DefinitionVersion = defVersion,
                Status = "Completed"
            });

            onProgress?.Invoke(new ScanProgressEventArgs
            {
                FilesExamined = examined,
                FilesScanned = scanned,
                FilesSkipped = skipped,
                ThreatsDetected = threats,
                SuspiciousFiles = suspicious,
                IsCompleted = true,
                LogMessage = $"[INFO] {scanType} scan finished.\n" +
                             $"Candidate enumeration: {candidateCount}\n" +
                             $"Additional scan inputs from providers: {providerExamined}\n" +
                             $"Total examined: {examined}\n" +
                             $"Scanned by ClamAV: {scanned}\n" +
                             $"Skipped/Cached: {skipped}\n" +
                             $"Threats: {threats}\n" +
                             $"Suspicious PE: {suspicious}"
            });
        }
    }
}
