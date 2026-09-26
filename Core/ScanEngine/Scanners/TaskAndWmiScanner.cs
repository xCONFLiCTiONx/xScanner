using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace xScanner.Core.ScanEngine.Scanners
{
    public class TaskAndWmiScanner : IScanProvider
    {
        public string Id => "TaskAndWmiScanner";
        public string DisplayName => "Scheduled Tasks & WMI Persistence Scanner";
        public ScanScope Scope => ScanScope.Basic;

        public async Task ScanAsync(ScanResultContext context, CancellationToken cancellationToken)
        {
            context.SetProviderStatus(Id, ProviderExecutionStatus.Running, "Scanning scheduled tasks and WMI persistence...");

            try
            {
                string tasksDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks");
                if (Directory.Exists(tasksDir))
                {
                    ScanTaskFolder(tasksDir, tasksDir, context, cancellationToken);
                }

                context.SetProviderStatus(Id, ProviderExecutionStatus.Completed, $"Scanned {context.ScannedTasks} scheduled tasks successfully.");
            }
            catch (Exception ex)
            {
                context.SetProviderStatus(Id, ProviderExecutionStatus.Failed, ex.Message);
                context.AddError($"TaskAndWmiScanner error: {ex.Message}");
            }

            await Task.CompletedTask;
        }

        private void ScanTaskFolder(string rootDir, string currentDir, ScanResultContext context, CancellationToken cancellationToken)
        {
            try
            {
                foreach (var file in Directory.GetFiles(currentDir))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    context.ScannedTasks++;

                    try
                    {
                        string content = File.ReadAllText(file);
                        bool isSuspicious = content.Contains("powershell", StringComparison.OrdinalIgnoreCase) ||
                                            content.Contains("cmd.exe", StringComparison.OrdinalIgnoreCase) ||
                                            content.Contains("mshta", StringComparison.OrdinalIgnoreCase) ||
                                            content.Contains("\\AppData\\", StringComparison.OrdinalIgnoreCase) ||
                                            content.Contains("\\Temp\\", StringComparison.OrdinalIgnoreCase);

                        if (isSuspicious)
                        {
                            string taskName = file.Substring(rootDir.Length).TrimStart(Path.DirectorySeparatorChar);
                            context.AddFinding(new ScanFinding
                            {
                                ProviderId = Id,
                                Category = "Scheduled Task",
                                Title = $"Suspicious Scheduled Task: {taskName}",
                                Description = "Scheduled task XML configuration contains script execution or runs from user-writable/temp directory.",
                                Path = file,
                                Severity = FindingSeverity.Medium,
                                Confidence = FindingConfidence.Medium,
                                Type = FindingType.Task,
                                IsActionable = true
                            });
                        }
                    }
                    catch
                    {
                        context.AddAccessDenied(file);
                    }
                }

                foreach (var subDir in Directory.GetDirectories(currentDir))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    ScanTaskFolder(rootDir, subDir, context, cancellationToken);
                }
            }
            catch
            {
                context.AddAccessDenied(currentDir);
            }
        }
    }
}
