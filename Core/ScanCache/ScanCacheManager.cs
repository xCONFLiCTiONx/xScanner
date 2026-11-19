using System;
using System.Collections.Generic;
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

                return EvaluateNeedsScan(fi, existingRecord, currentDefinitionVersion);
            }
            catch
            {
                return true;
            }
        }

        public bool ShouldScanFile(string filePath, string currentDefinitionVersion, IReadOnlyDictionary<string, FileRecord> cacheLookup, out FileRecord? existingRecord, out long fileSize, out DateTime lastModified)
        {
            existingRecord = null;
            fileSize = 0;
            lastModified = DateTime.Now;
            try
            {
                var fi = new FileInfo(filePath);
                if (!fi.Exists) return false;

                fileSize = fi.Length;
                lastModified = fi.LastWriteTime;

                cacheLookup.TryGetValue(filePath, out existingRecord);
                return EvaluateNeedsScan(fi, existingRecord, currentDefinitionVersion);
            }
            catch
            {
                return true;
            }
        }

        private static bool EvaluateNeedsScan(FileInfo fi, FileRecord? existingRecord, string currentDefinitionVersion)
        {
            if (existingRecord == null) return true; // Never scanned

            // Check if file size or last modified time changed (allow 1-tick tolerance for round-trip formatting)
            if (existingRecord.FileSize != fi.Length || Math.Abs((existingRecord.LastModified - fi.LastWriteTime).TotalSeconds) > 1)
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
    }
}
