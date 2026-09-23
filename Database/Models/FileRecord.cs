using System;

namespace xScanner.Database.Models
{
    public class FileRecord
    {
        public long Id { get; set; }
        public string FilePath { get; set; } = string.Empty;
        public long FileSize { get; set; }
        public DateTime LastModified { get; set; }
        public string Sha256 { get; set; } = string.Empty;
        public DateTime LastScanTime { get; set; }
        public string ScanResult { get; set; } = "Clean"; // Clean, Threat, Suspicious, Error
        public string DefinitionVersion { get; set; } = string.Empty;
    }
}
