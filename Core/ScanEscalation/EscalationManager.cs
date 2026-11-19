using System;
using System.Collections.Generic;
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
                var dirFiles = new List<string>();
                var dir = Path.GetDirectoryName(suspiciousFilePath);
                if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
                {
                    foreach (var file in Directory.GetFiles(dir, "*.*", SearchOption.AllDirectories))
                    {
                        if (!file.Equals(suspiciousFilePath, StringComparison.OrdinalIgnoreCase))
                        {
                            dirFiles.Add(file);
                        }
                    }
                }

                if (dirFiles.Count > 0)
                {
                    await _clamManager.ScanFilesBatchAsync(dirFiles, (file, res) =>
                    {
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
                    });
                }

                string tempPath = Path.GetTempPath();
                if (Directory.Exists(tempPath))
                {
                    var tempExes = Directory.GetFiles(tempPath, "*.exe", SearchOption.TopDirectoryOnly);
                    if (tempExes.Length > 0)
                    {
                        await _clamManager.ScanFilesBatchAsync(tempExes, (file, res) =>
                        {
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
                        });
                    }
                }
            }
            catch { }
        }
    }
}
