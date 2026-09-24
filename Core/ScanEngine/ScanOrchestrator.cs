using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using xScanner.Analysis;
using xScanner.Core.FileSystem;
using xScanner.Core.ScanCache;
using xScanner.Core.ScanEscalation;
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
    }

    public class ScanOrchestrator
    {
        private readonly ScanDatabase _database;
        private readonly ClamAvManager _clamManager;
        private readonly ScanCacheManager _cacheManager;
        private readonly EscalationManager _escalationManager;
        private readonly QuarantineManager _quarantineManager;

        public ScanOrchestrator(ScanDatabase database, ClamAvManager clamManager)
        {
            _database = database;
            _clamManager = clamManager;
            _cacheManager = new ScanCacheManager(database);
            _escalationManager = new EscalationManager(database, clamManager);
            _quarantineManager = new QuarantineManager(database);
        }

        public async Task RunBasicScanAsync(List<string>? exclusions, Action<ScanProgressEventArgs> onProgress, CancellationToken cancellationToken = default)
        {
            exclusions ??= _database.GetExclusions();
            onProgress?.Invoke(new ScanProgressEventArgs { CurrentFile = "Enumerating basic scan locations...", LogMessage = "[INFO] Starting basic scan file enumeration...", IsIndeterminate = true });
            var files = await Task.Run(() => FileEnumerator.GetBasicScanFiles(exclusions, cancellationToken), cancellationToken);
            var fileList = new List<string>(files);
            if (cancellationToken.IsCancellationRequested) return;
            onProgress?.Invoke(new ScanProgressEventArgs { CurrentFile = $"Found {fileList.Count} files to scan.", LogMessage = $"[INFO] Basic scan enumeration complete. Found {fileList.Count} files.", IsIndeterminate = false, TotalFiles = fileList.Count });
            await RunScanInternalAsync("Basic", fileList, onProgress, cancellationToken);
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
            onProgress?.Invoke(new ScanProgressEventArgs { CurrentFile = $"Found {fileList.Count} files to scan.", LogMessage = $"[INFO] Full scan enumeration complete. Found {fileList.Count} files across fixed drives.", IsIndeterminate = false, TotalFiles = fileList.Count });
            await RunScanInternalAsync("Full", fileList, onProgress, cancellationToken);
        }

        private async Task RunScanInternalAsync(string scanType, List<string> filePaths, Action<ScanProgressEventArgs>? onProgress, CancellationToken cancellationToken = default)
        {
            var startTime = DateTime.Now;
            string defVersion = _clamManager.GetDefinitionVersion();

            long examined = 0;
            long scanned = 0;
            long skipped = 0;
            long threats = 0;
            long suspicious = 0;
            long totalCount = filePaths.Count;

            onProgress?.Invoke(new ScanProgressEventArgs
            {
                CurrentFile = $"Starting {scanType} scan...",
                LogMessage = $"[INFO] Beginning scan of {totalCount} files using ClamAV definitions v{defVersion}...",
                IsIndeterminate = false,
                TotalFiles = totalCount
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
                bool isThreatOrSuspicious = false;
                string logMsg = string.Empty;

                if (_cacheManager.ShouldScanFile(file, defVersion, out var existingRecord))
                {
                    scanned++;
                    string sha256 = string.Empty;
                    try
                    {
                        sha256 = Heuristics.ComputeSha256(file);
                    }
                    catch { }

                    // Static analysis for PE files
                    bool isPeSuspicious = false;
                    string ext = Path.GetExtension(file);
                    if (ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                        ext.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
                        ext.Equals(".sys", StringComparison.OrdinalIgnoreCase) ||
                        ext.Equals(".scr", StringComparison.OrdinalIgnoreCase) ||
                        ext.Equals(".com", StringComparison.OrdinalIgnoreCase))
                    {
                        var peResult = PEAnalyzer.Analyze(file);
                        isPeSuspicious = peResult.IsSuspicious;
                        if (isPeSuspicious) suspicious++;
                    }

                    // ClamAV scan
                    var clamRes = await _clamManager.ScanFileAsync(file, cancellationToken);

                    string scanResult = "Clean";
                    if (clamRes.IsThreat)
                    {
                        threats++;
                        isThreatOrSuspicious = true;
                        scanResult = "Threat";
                        logMsg = $"[THREAT] Threat detected: {clamRes.ThreatName} in {file}";
                        _database.InsertDetection(new DetectionRecord
                        {
                            FilePath = file,
                            ThreatName = clamRes.ThreatName,
                            StaticAnalysisStatus = isPeSuspicious ? "Suspicious" : "Normal",
                            ActionTaken = "Quarantined"
                        });

                        // Quarantine threat safely
                        _quarantineManager.QuarantineFile(file, clamRes.ThreatName);

                        // Escalate investigation
                        await _escalationManager.InvestigateAsync(file, clamRes.ThreatName);
                    }
                    else if (isPeSuspicious)
                    {
                        scanResult = "Suspicious";
                        isThreatOrSuspicious = true;
                        logMsg = $"[SUSPICIOUS] Suspicious PE pattern detected in {file}";
                        _database.InsertDetection(new DetectionRecord
                        {
                            FilePath = file,
                            ThreatName = "Suspicious.PE",
                            StaticAnalysisStatus = "Suspicious",
                            ActionTaken = "Logged"
                        });
                    }

                    // Update cache
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

                // Throttle progress updates to every 50 files, or when threat/suspicious found, or first file
                if (examined == 1 || examined % 50 == 0 || isThreatOrSuspicious || examined == totalCount)
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
                        TotalFiles = totalCount
                    });
                }
            }

            // Record scan history
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
                IsCompleted = true
            });
        }
    }
}
