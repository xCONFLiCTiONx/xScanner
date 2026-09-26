using Microsoft.Win32;
using System;
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
            int checkedItems = 0;

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
                    ScanRegistryHive(Registry.CurrentUser, regPath, context);
                    ScanRegistryHive(Registry.LocalMachine, regPath, context);
                    checkedItems++;
                }

                // 2. Startup Folders
                string userStartup = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Startup));
                string commonStartup = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup));

                ScanStartupFolder(userStartup, context, cancellationToken);
                ScanStartupFolder(commonStartup, context, cancellationToken);

                context.SetProviderStatus(Id, ProviderExecutionStatus.Completed, "Startup persistence scan completed successfully.");
            }
            catch (Exception ex)
            {
                context.SetProviderStatus(Id, ProviderExecutionStatus.Failed, ex.Message);
                context.AddError($"StartupPersistenceScanner error: {ex.Message}");
            }

            await Task.CompletedTask;
        }

        private void ScanRegistryHive(RegistryKey rootHive, string subKeyPath, ScanResultContext context)
        {
            try
            {
                using var key = rootHive.OpenSubKey(subKeyPath, false);
                if (key == null) return;

                foreach (var valueName in key.GetValueNames())
                {
                    context.ScannedRegistryKeys++;
                    var valueData = key.GetValue(valueName)?.ToString() ?? string.Empty;

                    bool isSuspicious = IsSuspiciousStartupValue(valueData);
                    if (isSuspicious)
                    {
                        context.AddFinding(new ScanFinding
                        {
                            ProviderId = Id,
                            Category = "Registry Persistence",
                            Title = $"Suspicious Startup Entry: {valueName}",
                            Description = $"Registry startup key points to suspicious location or command: {valueData}",
                            RegistryPath = $"{rootHive.Name}\\{subKeyPath}\\{valueName}",
                            Path = valueData,
                            Severity = FindingSeverity.Medium,
                            Confidence = FindingConfidence.Medium,
                            Type = FindingType.Persistence,
                            IsActionable = true
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                context.AddAccessDenied($"Registry {rootHive.Name}\\{subKeyPath}: {ex.Message}");
            }
        }

        private void ScanStartupFolder(string folderPath, ScanResultContext context, CancellationToken cancellationToken)
        {
            if (!Directory.Exists(folderPath)) return;

            try
            {
                foreach (var file in Directory.GetFiles(folderPath))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    context.FilesExamined++;

                    string targetPath = file;
                    if (file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
                    {
                        targetPath = ResolveShortcut(file) ?? file;
                    }

                    context.AddFinding(new ScanFinding
                    {
                        ProviderId = Id,
                        Category = "Startup Folder",
                        Title = $"Startup File: {Path.GetFileName(file)}",
                        Description = formatStartupDescription(file, targetPath),
                        Path = targetPath,
                        Severity = FindingSeverity.Low,
                        Confidence = FindingConfidence.Low,
                        Type = FindingType.Persistence,
                        IsActionable = true
                    });
                }
            }
            catch (Exception ex)
            {
                context.AddAccessDenied($"Startup folder {folderPath}: {ex.Message}");
            }
        }

        private string formatStartupDescription(string shortcut, string target)
        {
            return shortcut != target ? $"Shortcut pointing to: {target}" : $"File in startup folder: {shortcut}";
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

        private bool IsSuspiciousStartupValue(string value)
        {
            if (string.IsNullOrEmpty(value)) return false;
            var lower = value.ToLowerInvariant();
            return lower.Contains("powershell") ||
                   lower.Contains("cmd.exe") ||
                   lower.Contains("wscript") ||
                   lower.Contains("cscript") ||
                   lower.Contains("mshta") ||
                   lower.Contains("\\temp\\") ||
                   lower.Contains("\\appdata\\");
        }
    }
}
