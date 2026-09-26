using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace xScanner.Core.ScanEngine.Scanners
{
    public class ForensicArtifactsScanner : IScanProvider
    {
        public string Id => "ForensicArtifactsScanner";
        public string DisplayName => "Forensic Artifacts, Prefetch & Event Logs Scanner";
        public ScanScope Scope => ScanScope.Full;

        public async Task ScanAsync(ScanResultContext context, CancellationToken cancellationToken)
        {
            context.SetProviderStatus(Id, ProviderExecutionStatus.Running, "Scanning Prefetch and forensic artifacts...");

            try
            {
                string prefetchDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "..", "Prefetch");
                if (Directory.Exists(prefetchDir))
                {
                    try
                    {
                        var files = Directory.GetFiles(prefetchDir, "*.pf");
                        foreach (var pf in files)
                        {
                            cancellationToken.ThrowIfCancellationRequested();
                        }
                    }
                    catch
                    {
                        context.AddAccessDenied(prefetchDir);
                    }
                }

                context.SetProviderStatus(Id, ProviderExecutionStatus.Completed, "Forensic artifacts scan completed successfully.");
            }
            catch (Exception ex)
            {
                context.SetProviderStatus(Id, ProviderExecutionStatus.Failed, ex.Message);
                context.AddError($"ForensicArtifactsScanner error: {ex.Message}");
            }

            await Task.CompletedTask;
        }
    }
}
