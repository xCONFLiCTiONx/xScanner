using System;
using System.Diagnostics;
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
            var sw = Stopwatch.StartNew();
            int tcpConnectionsCount = 0;
            int udpEndpointsCount = 0;
            int recentBinariesExamined = 0;
            int findingsCount = 0;

            try
            {
                var ipProperties = IPGlobalProperties.GetIPGlobalProperties();
                var tcpConnections = ipProperties.GetActiveTcpConnections();
                tcpConnectionsCount = tcpConnections.Length;

                var udpEndpoints = ipProperties.GetActiveUdpListeners();
                udpEndpointsCount = udpEndpoints.Length;

                string tempDir = Path.GetTempPath();
                if (Directory.Exists(tempDir))
                {
                    recentBinariesExamined += ScanRecentFilesInDirectory(tempDir, context, cancellationToken, TimeSpan.FromDays(3), ref findingsCount);
                }

                sw.Stop();
                context.SetProviderStatus(Id, ProviderExecutionStatus.Completed,
                    $"Provider completed: {DisplayName}\n" +
                    $"TCP connections: {tcpConnectionsCount}\n" +
                    $"UDP listeners: {udpEndpointsCount}\n" +
                    $"Recent binaries examined: {recentBinariesExamined}\n" +
                    $"Findings: {findingsCount}\n" +
                    $"Duration: {sw.ElapsedMilliseconds / 1000.0:F1}s");
            }
            catch (Exception ex)
            {
                sw.Stop();
                context.SetProviderStatus(Id, ProviderExecutionStatus.Failed, ex.Message);
                context.AddError($"ActiveNetworkAndBinScanner error: {ex.Message}");
            }

            await Task.CompletedTask;
        }

        private int ScanRecentFilesInDirectory(string dirPath, ScanResultContext context, CancellationToken cancellationToken, TimeSpan maxAge, ref int findingsCount)
        {
            int examined = 0;
            try
            {
                var di = new DirectoryInfo(dirPath);
                foreach (var file in di.GetFiles("*.*", SearchOption.TopDirectoryOnly))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    examined++;
                    if (file.LastWriteTime >= DateTime.Now.Subtract(maxAge))
                    {
                        string ext = file.Extension.ToLowerInvariant();
                        if (ext == ".exe" || ext == ".dll" || ext == ".bat" || ext == ".ps1" || ext == ".vbs" || ext == ".scr")
                        {
                            findingsCount++;
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
            return examined;
        }
    }
}
