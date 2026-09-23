using System;
using System.Collections.Generic;
using System.IO;
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

        public async Task RunBasicScanAsync(Action<ScanProgressEventArgs> onProgress)
        {
            await RunScanInternalAsync("Basic", FileEnumerator.GetBasicScanFiles(), onProgress);
        }

        public async Task RunFullScanAsync(List<string> exclusions, Action<ScanProgressEventArgs> onProgress)
        {
            await RunScanInternalAsync("Full", FileEnumerator.GetFullScanFiles(exclusions), onProgress);
        }

        private async Task RunScanInternalAsync(string scanType, IEnumerable<string> filePaths, Action<ScanProgressEventArgs> onProgress)
        {
            var startTime = DateTime.Now;
            string defVersion = _clamManager.GetDefinitionVersion();

            long examined = 0;
            long scanned = 0;
            long skipped = 0;
            long threats = 0;
            long suspicious = 0;

            foreach (var file in filePaths)
            {
                examined++;
                onProgress?.Invoke(new ScanProgressEventArgs
                {
                    CurrentFile = file,
                    FilesExamined = examined,
                    FilesScanned = scanned,
                    FilesSkipped = skipped,
                    ThreatsDetected = threats,
                    SuspiciousFiles = suspicious
                });

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
                    var clamRes = await _clamManager.ScanFileAsync(file);

                    string scanResult = "Clean";
                    if (clamRes.IsThreat)
                    {
                        threats++;
                        scanResult = "Threat";
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
