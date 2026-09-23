using System;
using System.Diagnostics;

namespace xScanner.Core.ScanScheduler
{
    public static class SchedulerManager
    {
        public static bool ConfigureSchedule(string taskName, string timeStr, bool daily)
        {
            try
            {
                string exePath = Process.GetCurrentProcess().MainModule?.FileName ?? "xScanner.exe";
                string args = $"/create /tn \"{taskName}\" /tr \"\\\"{exePath}\\\" /scheduled\" /sc {(daily ? "DAILY" : "WEEKLY")} /st {timeStr} /f";

                var psi = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    Arguments = args,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                process?.WaitForExit();
                return process?.ExitCode == 0;
            }
            catch
            {
                return false;
            }
        }

        public static bool RemoveSchedule(string taskName)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    Arguments = $"/delete /tn \"{taskName}\" /f",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                process?.WaitForExit();
                return process?.ExitCode == 0;
            }
            catch
            {
                return false;
            }
        }
    }
}
