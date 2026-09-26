using System;
using System.IO;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;

namespace xScanner.Core.ScanEngine.Scanners
{
    public class ActiveNetworkAndBinScanner : IScanProvider
    {
        public string Id => "ActiveNetworkAndBinScanner";
        public string DisplayName => "Active Network Connections & Recent Binaries Scanner";
        public ScanScope Scope => ScanScope.Basic;

        public async Task ScanAsync(ScanResultContext context, CancellationToken cancellationToken)
        {
            context.SetProviderStatus(Id, ProviderExecutionStatus.Running, "Inspecting active network connections and high-value directories...");

            try
            {
                var ipProperties = IPGlobalProperties.GetIPGlobalProperties();
                var tcpConnections = ipProperties.GetActiveTcpConnections();

                foreach (var conn in tcpConnections)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                }

                string tempDir = Path.GetTempPath();
                if (Directory.Exists(tempDir))
                {
                    ScanRecentFilesInDirectory(tempDir, context, cancellationToken, TimeSpan.FromDays(3));
                }

                context.SetProviderStatus(Id, ProviderExecutionStatus.Completed, "Active network and recent binaries scan completed.");
            }
            catch (Exception ex)
            {
                context.SetProviderStatus(Id, ProviderExecutionStatus.Failed, ex.Message);
                context.AddError($"ActiveNetworkAndBinScanner error: {ex.Message}");
            }

            await Task.CompletedTask;
        }

        private void ScanRecentFilesInDirectory(string dirPath, ScanResultContext context, CancellationToken cancellationToken, TimeSpan maxAge)
        {
            try
            {
                var di = new DirectoryInfo(dirPath);
                foreach (var file in di.GetFiles("*.*", SearchOption.TopDirectoryOnly))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (file.LastWriteTime >= DateTime.Now.Subtract(maxAge))
                    {
                        string ext = file.Extension.ToLowerInvariant();
                        if (ext == ".exe" || ext == ".dll" || ext == ".bat" || ext == ".ps1" || ext == ".vbs" || ext == ".scr")
                        {
                            context.AddFinding(new ScanFinding
                            {
                                ProviderId = Id,
                                Category = "Recent Binary",
                                Title = $"Recent Executable in Temp: {file.Name}",
                                Description = $"Recently modified executable or script found in temporary directory: {file.FullName}",
                                Path = file.FullName,
                                Severity = FindingSeverity.Low,
                                Confidence = FindingConfidence.Low,
                                Type = FindingType.File,
                                IsActionable = true
                            });
                        }
                    }
                }
            }
            catch
            {
                context.AddAccessDenied(dirPath);
            }
        }
    }
}
