using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace xScanner.Core.ScanEngine.Scanners
{
    public class StartupPersistenceScanner : IScanProvider
    {
        public string Id => "StartupPersistenceScanner";
        public string DisplayName => "Windows Startup & Registry Persistence Scanner";
        public ScanScope Scope => ScanScope.Basic;

        public async Task ScanAsync(ScanResultContext context, CancellationToken cancellationToken)
        {
            context.SetProviderStatus(Id, ProviderExecutionStatus.Running, "Scanning startup registry keys and folders...");
            var sw = Stopwatch.StartNew();
            int regLocationsChecked = 0;
            int runEntriesExamined = 0;
            int startupFilesExamined = 0;
            int shortcutsResolved = 0;
            int findingsCount = 0;

            try
            {
                // 1. Registry Run keys
                string[] regPaths = new[]
                {
                    @"Software\Microsoft\Windows\CurrentVersion\Run",
                    @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                    @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                    @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
                };

                foreach (var regPath in regPaths)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    regLocationsChecked += ScanRegistryHive(Registry.CurrentUser, regPath, context, ref runEntriesExamined, ref findingsCount);
                    regLocationsChecked += ScanRegistryHive(Registry.LocalMachine, regPath, context, ref runEntriesExamined, ref findingsCount);
                }

                // 2. Startup Folders
                string userStartup = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Startup));
                string commonStartup = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup));

                startupFilesExamined += ScanStartupFolder(userStartup, context, cancellationToken, ref shortcutsResolved, ref findingsCount);
                startupFilesExamined += ScanStartupFolder(commonStartup, context, cancellationToken, ref shortcutsResolved, ref findingsCount);

                sw.Stop();
                context.SetProviderStatus(Id, ProviderExecutionStatus.Completed,
                    $"Provider completed: {DisplayName}\n" +
                    $"Registry locations checked: {regLocationsChecked}\n" +
                    $"Run entries examined: {runEntriesExamined}\n" +
                    $"Startup files examined: {startupFilesExamined}\n" +
                    $"Shortcuts resolved: {shortcutsResolved}\n" +
                    $"Findings: {findingsCount}\n" +
                    $"Duration: {sw.ElapsedMilliseconds / 1000.0:F1}s");
            }
            catch (Exception ex)
            {
                sw.Stop();
                context.SetProviderStatus(Id, ProviderExecutionStatus.Failed, ex.Message);
                context.AddError($"StartupPersistenceScanner error: {ex.Message}");
            }

            await Task.CompletedTask;
        }

        private int ScanRegistryHive(RegistryKey rootHive, string subKeyPath, ScanResultContext context, ref int entriesExamined, ref int findingsCount)
        {
            try
            {
                using var key = rootHive.OpenSubKey(subKeyPath, false);
                if (key == null) return 0;

                foreach (var valueName in key.GetValueNames())
                {
                    context.ScannedRegistryKeys++;
                    entriesExamined++;
                    var valueData = key.GetValue(valueName)?.ToString() ?? string.Empty;

                    bool isSuspicious = IsSuspiciousStartupValue(valueName, valueData);
                    if (isSuspicious)
                    {
                        findingsCount++;
                        context.AddFinding(new ScanFinding
                        {
                            ProviderId = Id,
                            Category = "Registry Persistence",
                            Title = $"Startup Persistence Entry: {valueName}",
                            Description = $"Executable registered for automatic startup.\nPath: {valueData}\nRegistry: {rootHive.Name}\\{subKeyPath}",
                            RegistryPath = $"{rootHive.Name}\\{subKeyPath}\\{valueName}",
                            Path = valueData,
                            Severity = valueData.Contains("LM Studio", StringComparison.OrdinalIgnoreCase) ? FindingSeverity.Medium : FindingSeverity.Low,
                            Confidence = FindingConfidence.Medium,
                            Type = FindingType.Persistence,
                            IsActionable = true
                        });
                    }
                }
                return 1;
            }
            catch
            {
                context.AddAccessDenied($"Registry {rootHive.Name}\\{subKeyPath}");
                return 0;
            }
        }

        private int ScanStartupFolder(string folderPath, ScanResultContext context, CancellationToken cancellationToken, ref int shortcutsResolved, ref int findingsCount)
        {
            if (!Directory.Exists(folderPath)) return 0;
            int count = 0;

            try
            {
                foreach (var file in Directory.GetFiles(folderPath))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    count++;
                    context.FilesExamined++;

                    string fileName = Path.GetFileName(file);
                    // Filter out desktop.ini, thumbs.db
                    if (fileName.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase) ||
                        fileName.Equals("thumbs.db", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    // Filter out known legitimate Microsoft / Office shortcuts unless suspicious
                    if (fileName.Contains("OneNote", StringComparison.OrdinalIgnoreCase) ||
                        fileName.Contains("Teams", StringComparison.OrdinalIgnoreCase) ||
                        fileName.Contains("OneDrive", StringComparison.OrdinalIgnoreCase))
                    {
                        // Legitimate app shortcut in startup, skip reporting as finding
                        continue;
                    }

                    string targetPath = file;
                    if (file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
                    {
                        shortcutsResolved++;
                        targetPath = ResolveShortcut(file) ?? file;
                    }

                    // Only report if it's in an unusual location or script/executable
                    if (IsSuspiciousStartupFile(file, targetPath))
                    {
                        findingsCount++;
                        context.AddFinding(new ScanFinding
                        {
                            ProviderId = Id,
                            Category = "Startup Folder",
                            Title = $"Startup File: {fileName}",
                            Description = $"Startup item detected.\nFile: {file}\nTarget: {targetPath}",
                            Path = targetPath,
                            Severity = FindingSeverity.Low,
                            Confidence = FindingConfidence.Low,
                            Type = FindingType.Persistence,
                            IsActionable = true
                        });
                    }
                }
            }
            catch
            {
                context.AddAccessDenied($"Startup folder {folderPath}");
            }

            return count;
        }

        private string ResolveShortcut(string lnkPath)
        {
            try
            {
                return lnkPath;
            }
            catch
            {
                return lnkPath;
            }
        }

        private bool IsSuspiciousStartupValue(string name, string value)
        {
            if (string.IsNullOrEmpty(value)) return false;
            var lower = value.ToLowerInvariant();
            // Flag if running powershell, cmd, wscript, or located in user temp/appdata temp
            return lower.Contains("powershell") ||
                   lower.Contains("cmd.exe") ||
                   lower.Contains("wscript") ||
                   lower.Contains("cscript") ||
                   lower.Contains("mshta") ||
                   lower.Contains("\\temp\\") ||
                   lower.Contains("lm studio");
        }

        private bool IsSuspiciousStartupFile(string file, string target)
        {
            var lowerTarget = target.ToLowerInvariant();
            return lowerTarget.Contains("\\temp\\") ||
                   lowerTarget.Contains("\\appdata\\local\\temp") ||
                   lowerTarget.EndsWith(".bat") ||
                   lowerTarget.EndsWith(".ps1") ||
                   lowerTarget.EndsWith(".vbs") ||
                   lowerTarget.EndsWith(".cmd");
        }
    }
}
