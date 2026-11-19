using System;
using System.Diagnostics;
using System.IO;
using System.Xml.Linq;

namespace xScanner.Core.ScanScheduler
{
    public static class SchedulerManager
    {
        public const string DefaultTaskName = "xScanner_WeeklyScan";

        public static bool IsTaskRegistered(string taskName = DefaultTaskName)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    Arguments = $"/query /tn \"{taskName}\"",
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

        public static bool ConfigureWeeklySchedule(string taskName = DefaultTaskName, string timeStr = "01:00", bool wakePc = true)
        {
            try
            {
                string exePath = Process.GetCurrentProcess().MainModule?.FileName ?? "xScanner.exe";
                // Added /rl HIGHEST so Windows Task Scheduler checks "Run with highest privileges"
                string args = $"/create /tn \"{taskName}\" /tr \"\\\"{exePath}\\\" /scheduled\" /sc WEEKLY /st {timeStr} /rl HIGHEST /f";

                var psi = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    Arguments = args,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var process = Process.Start(psi))
                {
                    process?.WaitForExit();
                    if (process?.ExitCode != 0) return false;
                }

                if (wakePc)
                {
                    SetTaskWakeToRunAndHighestPrivileges(taskName);
                }

                return IsTaskRegistered(taskName);
            }
            catch
            {
                return false;
            }
        }

        public static bool ConfigureSchedule(string taskName, string timeStr, bool daily)
        {
            try
            {
                string exePath = Process.GetCurrentProcess().MainModule?.FileName ?? "xScanner.exe";
                // Added /rl HIGHEST so Windows Task Scheduler checks "Run with highest privileges"
                string args = $"/create /tn \"{taskName}\" /tr \"\\\"{exePath}\\\" /scheduled\" /sc {(daily ? "DAILY" : "WEEKLY")} /st {timeStr} /rl HIGHEST /f";

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

        public static bool RemoveSchedule(string taskName = DefaultTaskName)
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

        private static void SetTaskWakeToRunAndHighestPrivileges(string taskName)
        {
            try
            {
                var psiQuery = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    Arguments = $"/query /tn \"{taskName}\" /xml",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var queryProc = Process.Start(psiQuery);
                if (queryProc == null) return;
                string xml = queryProc.StandardOutput.ReadToEnd();
                queryProc.WaitForExit();

                if (queryProc.ExitCode != 0 || string.IsNullOrWhiteSpace(xml)) return;

                var doc = XDocument.Parse(xml);
                XNamespace ns = doc.Root?.GetDefaultNamespace() ?? XNamespace.None;

                // Ensure Settings -> WakeToRun = true
                var settings = doc.Root?.Element(ns + "Settings");
                if (settings != null)
                {
                    var wakeElement = settings.Element(ns + "WakeToRun");
                    if (wakeElement != null)
                    {
                        wakeElement.Value = "true";
                    }
                    else
                    {
                        settings.Add(new XElement(ns + "WakeToRun", "true"));
                    }
                }

                // Ensure Principals -> Principal -> RunLevel = HighestAvailable
                var principals = doc.Root?.Element(ns + "Principals");
                if (principals == null)
                {
                    principals = new XElement(ns + "Principals");
                    doc.Root?.Add(principals);
                }
                var principal = principals.Element(ns + "Principal");
                if (principal == null)
                {
                    principal = new XElement(ns + "Principal", new XAttribute("id", "Author"));
                    principals.Add(principal);
                }
                var runLevel = principal.Element(ns + "RunLevel");
                if (runLevel != null)
                {
                    runLevel.Value = "HighestAvailable";
                }
                else
                {
                    principal.Add(new XElement(ns + "RunLevel", "HighestAvailable"));
                }

                string tempFile = Path.Combine(Path.GetTempPath(), $"xScanner_task_{Guid.NewGuid():N}.xml");
                doc.Save(tempFile);

                var psiUpdate = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    Arguments = $"/create /tn \"{taskName}\" /xml \"{tempFile}\" /f",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var updateProc = Process.Start(psiUpdate);
                updateProc?.WaitForExit();

                try { File.Delete(tempFile); } catch { }
            }
            catch
            {
                // Fallback: task was already created via base schtasks command
            }
        }
    }
}
