using System;
using System.IO;
using xScanner.Database;
using xScanner.Database.Models;

namespace xScanner.Quarantine
{
    public class QuarantineManager
    {
        private readonly ScanDatabase _database;
        private readonly string _quarantineDir;

        public QuarantineManager(ScanDatabase database)
        {
            _database = database;
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            _quarantineDir = Path.Combine(appData, "xScanner", "QuarantineStore");
            Directory.CreateDirectory(_quarantineDir);
        }

        public bool QuarantineFile(string originalPath, string threatName)
        {
            try
            {
                if (!File.Exists(originalPath)) return false;

                string fileName = Path.GetFileName(originalPath);
                string uniqueName = $"{Guid.NewGuid}_{fileName}";
                string quarantinePath = Path.Combine(_quarantineDir, uniqueName);

                // Atomic-like move with verification
                File.Move(originalPath, quarantinePath, true);

                if (!File.Exists(quarantinePath)) return false;

                _database.InsertQuarantine(new QuarantineRecord
                {
                    OriginalPath = originalPath,
                    QuarantinePath = quarantinePath,
                    ThreatName = threatName,
                    QuarantineTime = DateTime.Now,
                    Status = "Quarantined"
                });

                return true;
            }
            catch
            {
                return false;
            }
        }

        public bool RestoreFile(long quarantineId, string originalPath, string quarantinePath)
        {
            try
            {
                if (!File.Exists(quarantinePath)) return false;

                string? targetDir = Path.GetDirectoryName(originalPath);
                if (!string.IsNullOrEmpty(targetDir))
                {
                    Directory.CreateDirectory(targetDir);
                }

                File.Move(quarantinePath, originalPath, true);
                _database.UpdateQuarantineStatus(quarantineId, "Restored");
                _database.AddExclusion(originalPath);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public bool DeletePermanently(long quarantineId, string quarantinePath)
        {
            try
            {
                if (File.Exists(quarantinePath))
                {
                    File.Delete(quarantinePath);
                }
                _database.UpdateQuarantineStatus(quarantineId, "Deleted");
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
