using System.IO;
using xScanner.Database;
using xScanner.Database.Models;

namespace xScanner.Core.ScanCache
{
    public class ScanCacheManager
    {
        private readonly ScanDatabase _database;

        public ScanCacheManager(ScanDatabase database)
        {
            _database = database;
        }

        public bool ShouldScanFile(string filePath, string currentDefinitionVersion, out FileRecord? existingRecord)
        {
            existingRecord = null;
            try
            {
                if (!File.Exists(filePath)) return false;

                var fi = new FileInfo(filePath);
                existingRecord = _database.GetFileRecord(filePath);

                if (existingRecord == null) return true; // Never scanned

                // Check if file size or last modified time changed
                if (existingRecord.FileSize != fi.Length || existingRecord.LastModified != fi.LastWriteTime)
                    return true;

                // Check if ClamAV definitions changed since last scan
                if (existingRecord.DefinitionVersion != currentDefinitionVersion)
                    return true; // Definition updated, re-evaluate

                // If previous result was error or suspicious, re-scan
                if (existingRecord.ScanResult == "Suspicious" || existingRecord.ScanResult == "Error")
                    return true;

                // Unchanged file with valid clean result -> skip
                return false;
            }
            catch
            {
                return true;
            }
        }
    }
}
