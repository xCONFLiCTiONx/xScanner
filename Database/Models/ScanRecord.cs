using System;

namespace xScanner.Database.Models
{
    public class ScanRecord
    {
        public long Id { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public string ScanType { get; set; } = "Basic"; // Basic, Full
        public long FilesExamined { get; set; }
        public long FilesScanned { get; set; }
        public long FilesSkipped { get; set; }
        public long ThreatsDetected { get; set; }
        public long SuspiciousFiles { get; set; }
        public string DefinitionVersion { get; set; } = string.Empty;
        public string Status { get; set; } = "Completed"; // Completed, Cancelled, Error
    }
}
