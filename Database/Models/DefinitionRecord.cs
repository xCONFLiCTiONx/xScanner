using System;

namespace xScanner.Database.Models
{
    public class DefinitionRecord
    {
        public long Id { get; set; }
        public string Version { get; set; } = string.Empty;
        public DateTime UpdateTime { get; set; } = DateTime.Now;
        public string Status { get; set; } = "Current";
    }
}
