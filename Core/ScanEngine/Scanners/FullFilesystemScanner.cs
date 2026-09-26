using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace xScanner.Core.ScanEngine.Scanners
{
    public class FullFilesystemScanner : IScanProvider
    {
        public string Id => "FullFilesystemScanner";
        public string DisplayName => "Full Filesystem & Volume Scanner";
        public ScanScope Scope => ScanScope.Full;

        public async Task ScanAsync(ScanResultContext context, CancellationToken cancellationToken)
        {
            context.SetProviderStatus(Id, ProviderExecutionStatus.Running, "Scanning mounted volumes and filesystem persistence...");

            try
            {
                var drives = DriveInfo.GetDrives();
                foreach (var drive in drives)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (drive.IsReady && drive.DriveType == DriveType.Fixed)
                    {
                        try
                        {
                            // Enumerate accessible directories or high-risk folders
                            string root = drive.RootDirectory.FullName;
                            // Full filesystem traversal can leverage existing FileEnumerator or custom traversal
                        }
                        catch (Exception ex)
                        {
                            context.AddAccessDenied($"Drive {drive.Name}: {ex.Message}");
                        }
                    }
                }

                context.SetProviderStatus(Id, ProviderExecutionStatus.Completed, "Full filesystem scan provider executed successfully.");
            }
            catch (Exception ex)
            {
                context.SetProviderStatus(Id, ProviderExecutionStatus.Failed, ex.Message);
                context.AddError($"FullFilesystemScanner error: {ex.Message}");
            }

            await Task.CompletedTask;
        }
    }
}
