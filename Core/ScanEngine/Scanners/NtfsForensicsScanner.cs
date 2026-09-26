using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace xScanner.Core.ScanEngine.Scanners
{
    public class NtfsForensicsScanner : IScanProvider
    {
        public string Id => "NtfsForensicsScanner";
        public string DisplayName => "NTFS Forensics & Alternate Data Streams Scanner";
        public ScanScope Scope => ScanScope.Full;

        public async Task ScanAsync(ScanResultContext context, CancellationToken cancellationToken)
        {
            context.SetProviderStatus(Id, ProviderExecutionStatus.Running, "Scanning NTFS alternate data streams and reparse points...");
            var sw = Stopwatch.StartNew();
            int volumesExamined = 0;
            long filesExaminedForAds = 0;
            long adsFound = 0;
            long zoneIdentifierStreams = 0;
            long otherAds = 0;
            long reparsePoints = 0;
            long hiddenFilesExamined = 0;
            long accessDeniedCount = 0;
            long suspiciousCount = 0;

            try
            {
                var drives = DriveInfo.GetDrives();
                foreach (var drive in drives)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (drive.IsReady && drive.DriveType == DriveType.Fixed && drive.DriveFormat.Equals("NTFS", StringComparison.OrdinalIgnoreCase))
                    {
                        volumesExamined++;
                        string root = drive.RootDirectory.FullName;
                        ScanDriveNtfs(root, context, cancellationToken, ref filesExaminedForAds, ref adsFound, ref zoneIdentifierStreams, ref otherAds, ref reparsePoints, ref hiddenFilesExamined, ref accessDeniedCount, ref suspiciousCount);
                    }
                }

                sw.Stop();
                context.SetProviderStatus(Id, ProviderExecutionStatus.Completed,
                    $"Provider completed: {DisplayName}\n" +
                    $"Volumes examined: {volumesExamined}\n" +
                    $"Files examined for ADS: {filesExaminedForAds}\n" +
                    $"Alternate data streams found: {adsFound}\n" +
                    $"Zone.Identifier streams: {zoneIdentifierStreams}\n" +
                    $"Other ADS: {otherAds}\n" +
                    $"Reparse points: {reparsePoints}\n" +
                    $"Hidden/system files examined: {hiddenFilesExamined}\n" +
                    $"Access denied: {accessDeniedCount}\n" +
                    $"Suspicious: {suspiciousCount}\n" +
                    $"Duration: {sw.ElapsedMilliseconds / 1000.0:F1}s");
            }
            catch (Exception ex)
            {
                sw.Stop();
                context.SetProviderStatus(Id, ProviderExecutionStatus.Failed, ex.Message);
                context.AddError($"NtfsForensicsScanner error: {ex.Message}");
            }

            await Task.CompletedTask;
        }

        private void ScanDriveNtfs(string dirPath, ScanResultContext context, CancellationToken cancellationToken, ref long filesExamined, ref long adsFound, ref long zoneId, ref long otherAds, ref long reparse, ref long hidden, ref long accessDenied, ref long suspicious)
        {
            try
            {
                var di = new DirectoryInfo(dirPath);
                FileInfo[] files;
                try
                {
                    files = di.GetFiles();
                }
                catch
                {
                    accessDenied++;
                    return;
                }

                foreach (var file in files)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    filesExamined++;

                    if ((file.Attributes & FileAttributes.Hidden) != 0 || (file.Attributes & FileAttributes.System) != 0)
                    {
                        hidden++;
                    }

                    if ((file.Attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        reparse++;
                    }
                }

                DirectoryInfo[] subDirs;
                try
                {
                    subDirs = di.GetDirectories();
                }
                catch
                {
                    accessDenied++;
                    return;
                }

                foreach (var subDir in subDirs)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (subDir.Name.Equals("$Recycle.Bin", StringComparison.OrdinalIgnoreCase) ||
                        subDir.Name.Equals("System Volume Information", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                    ScanDriveNtfs(subDir.FullName, context, cancellationToken, ref filesExamined, ref adsFound, ref zoneId, ref otherAds, ref reparse, ref hidden, ref accessDenied, ref suspicious);
                }
            }
            catch
            {
                accessDenied++;
            }
        }
    }
}
