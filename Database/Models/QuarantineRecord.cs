using System;

namespace xScanner.Database.Models
{
    public class QuarantineRecord
    {
        public long Id { get; set; }
        public string OriginalPath { get; set; } = string.Empty;
        public string QuarantinePath { get; set; } = string.Empty;
        public string ThreatName { get; set; } = string.Empty;
        public DateTime QuarantineTime { get; set; } = DateTime.Now;
        public string Status { get; set; } = "Quarantined"; // Quarantined, Restored, Deleted
    }
}
