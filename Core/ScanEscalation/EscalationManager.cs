using System;
using System.IO;
using System.Threading.Tasks;
using xScanner.Database;
using xScanner.Database.Models;
using xScanner.Engines.ClamAV;

namespace xScanner.Core.ScanEscalation
{
    public class EscalationManager
    {
        private readonly ScanDatabase _database;
        private readonly ClamAvManager _clamManager;

        public EscalationManager(ScanDatabase database, ClamAvManager clamManager)
        {
            _database = database;
            _clamManager = clamManager;
        }

        public async Task InvestigateAsync(string suspiciousFilePath, string threatName)
        {
            try
            {
                var dir = Path.GetDirectoryName(suspiciousFilePath);
                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return;

                // 1. Scan containing directory recursively
                foreach (var file in Directory.GetFiles(dir, "*.*", SearchOption.AllDirectories))
                {
                    if (file.Equals(suspiciousFilePath, StringComparison.OrdinalIgnoreCase)) continue;

                    var res = await _clamManager.ScanFileAsync(file);
                    if (res.IsThreat)
                    {
                        _database.InsertDetection(new DetectionRecord
                        {
                            FilePath = file,
                            ThreatName = res.ThreatName,
                            StaticAnalysisStatus = "Suspicious",
                            ActionTaken = "Detected via Escalation"
                        });
                    }
                }

                // 2. Examine relevant temp/staging locations & persistence
                string tempPath = Path.GetTempPath();
                if (Directory.Exists(tempPath))
                {
                    foreach (var file in Directory.GetFiles(tempPath, "*.exe", SearchOption.TopDirectoryOnly))
                    {
                        var res = await _clamManager.ScanFileAsync(file);
                        if (res.IsThreat)
                        {
                            _database.InsertDetection(new DetectionRecord
                            {
                                FilePath = file,
                                ThreatName = res.ThreatName,
                                StaticAnalysisStatus = "Suspicious",
                                ActionTaken = "Detected in Temp"
                            });
                        }
                    }
                }
            }
            catch { }
        }
    }
}
