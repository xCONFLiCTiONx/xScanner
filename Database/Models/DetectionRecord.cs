using System;

namespace xScanner.Database.Models
{
    public class DetectionRecord
    {
        public long Id { get; set; }
        public string FilePath { get; set; } = string.Empty;
        public string Engine { get; set; } = "ClamAV";
        public string ThreatName { get; set; } = string.Empty;
        public string StaticAnalysisStatus { get; set; } = "Normal"; // Normal, Suspicious
        public string ActionTaken { get; set; } = "Quarantined"; // Quarantined, Ignored, Deleted
        public DateTime DetectionTime { get; set; } = DateTime.Now;
    }
}
