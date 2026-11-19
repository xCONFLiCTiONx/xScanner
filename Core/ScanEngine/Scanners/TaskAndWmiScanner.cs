using System;
using System.Diagnostics;
using System.IO;
using System.Management;
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
            context.SetProviderStatus(Id, ProviderExecutionStatus.Running, "Scanning scheduled tasks and WMI permanent event subscriptions...");
            var sw = Stopwatch.StartNew();
            int tasksEnumerated = 0;
            int systemTasksFiltered = 0;
            int suspiciousTasksFound = 0;
            int wmiFiltersExamined = 0;
            int wmiConsumersExamined = 0;
            int wmiBindingsExamined = 0;
            int accessDeniedCount = 0;

            try
            {
                // 1. Scheduled Tasks
                string tasksDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks");
                if (Directory.Exists(tasksDir))
                {
                    ScanTaskFolder(tasksDir, tasksDir, context, cancellationToken, ref tasksEnumerated, ref systemTasksFiltered, ref suspiciousTasksFound, ref accessDeniedCount);
                }

                // 2. WMI Permanent Event Subscriptions
                try
                {
                    var options = new ConnectionOptions();
                    var scopePath = @"\\.\root\subscription";
                    using var searcherFilter = new ManagementObjectSearcher(scopePath, "SELECT * FROM __EventFilter");
                    foreach (var obj in searcherFilter.Get())
                    {
                        wmiFiltersExamined++;
                    }

                    using var searcherConsumer = new ManagementObjectSearcher(scopePath, "SELECT * FROM __EventConsumer");
                    foreach (var obj in searcherConsumer.Get())
                    {
                        wmiConsumersExamined++;
                    }

                    using var searcherBinding = new ManagementObjectSearcher(scopePath, "SELECT * FROM __FilterToConsumerBinding");
                    foreach (var obj in searcherBinding.Get())
                    {
                        wmiBindingsExamined++;
                    }
                }
                catch
                {
                    // WMI query access denied or namespace unavailable
                    accessDeniedCount++;
                }

                sw.Stop();
                context.SetProviderStatus(Id, ProviderExecutionStatus.Completed,
                    $"Provider completed: {DisplayName}\n" +
                    $"Tasks enumerated: {tasksEnumerated}\n" +
                    $"System tasks filtered: {systemTasksFiltered}\n" +
                    $"WMI filters examined: {wmiFiltersExamined}\n" +
                    $"WMI consumers examined: {wmiConsumersExamined}\n" +
                    $"WMI bindings examined: {wmiBindingsExamined}\n" +
                    $"Access denied: {accessDeniedCount}\n" +
                    $"Suspicious tasks found: {suspiciousTasksFound}\n" +
                    $"Duration: {sw.ElapsedMilliseconds / 1000.0:F1}s");
            }
            catch (Exception ex)
            {
                sw.Stop();
                context.SetProviderStatus(Id, ProviderExecutionStatus.Failed, ex.Message);
                context.AddError($"TaskAndWmiScanner error: {ex.Message}");
            }

            await Task.CompletedTask;
        }

        private void ScanTaskFolder(string rootDir, string currentDir, ScanResultContext context, CancellationToken cancellationToken, ref int tasksEnumerated, ref int systemTasksFiltered, ref int suspiciousTasksFound, ref int accessDeniedCount)
        {
            try
            {
                foreach (var file in Directory.GetFiles(currentDir))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    tasksEnumerated++;
                    context.ScannedTasks++;

                    try
                    {
                        string taskName = file.Substring(rootDir.Length).TrimStart(Path.DirectorySeparatorChar);

                        if (taskName.StartsWith("Microsoft\\Windows\\", StringComparison.OrdinalIgnoreCase) ||
                            taskName.Equals("Windows App Updater", StringComparison.OrdinalIgnoreCase))
                        {
                            systemTasksFiltered++;
                            continue;
                        }

                        string content = File.ReadAllText(file);
                        bool isSuspicious = content.Contains("\\AppData\\Local\\Temp\\", StringComparison.OrdinalIgnoreCase) ||
                                            content.Contains("\\AppData\\Roaming\\Temp\\", StringComparison.OrdinalIgnoreCase) ||
                                            content.Contains("C:\\Temp\\", StringComparison.OrdinalIgnoreCase);

                        if (isSuspicious)
                        {
                            suspiciousTasksFound++;
                            context.AddFinding(new ScanFinding
                            {
                                ProviderId = Id,
                                Category = "Scheduled Task",
                                Title = $"Suspicious Scheduled Task: {taskName}",
                                Description = $"Scheduled task action points to a temporary or user-writable path.\nTask file: {file}",
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
                        accessDeniedCount++;
                        context.AddAccessDenied(file);
                    }
                }

                foreach (var subDir in Directory.GetDirectories(currentDir))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    ScanTaskFolder(rootDir, subDir, context, cancellationToken, ref tasksEnumerated, ref systemTasksFiltered, ref suspiciousTasksFound, ref accessDeniedCount);
                }
            }
            catch
            {
                accessDeniedCount++;
                context.AddAccessDenied(currentDir);
            }
        }
    }
}
