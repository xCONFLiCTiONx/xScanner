using System;
using System.Diagnostics;
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
            context.SetProviderStatus(Id, ProviderExecutionStatus.Running, "Scanning fixed volumes and filesystem categories...");
            var sw = Stopwatch.StartNew();
            int volumesExamined = 0;
            long directoriesExamined = 0;
            long filesExamined = 0;
            long executablesIdentified = 0;
            long scriptsIdentified = 0;
            long archivesIdentified = 0;
            long accessDeniedCount = 0;
            long suspiciousCount = 0;

            try
            {
                var drives = DriveInfo.GetDrives();
                foreach (var drive in drives)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (drive.IsReady && drive.DriveType == DriveType.Fixed)
                    {
                        volumesExamined++;
                        try
                        {
                            string root = drive.RootDirectory.FullName;
                            TraverseDirectory(root, context, cancellationToken, ref directoriesExamined, ref filesExamined, ref executablesIdentified, ref scriptsIdentified, ref archivesIdentified, ref accessDeniedCount, ref suspiciousCount);
                        }
                        catch
                        {
                            accessDeniedCount++;
                            context.AddAccessDenied($"Drive {drive.Name}");
                        }
                    }
                }

                sw.Stop();
                context.SetProviderStatus(Id, ProviderExecutionStatus.Completed,
                    $"Provider completed: {DisplayName}\n" +
                    $"Volumes examined: {volumesExamined}\n" +
                    $"Directories examined: {directoriesExamined}\n" +
                    $"Files examined: {filesExamined}\n" +
                    $"Executables identified: {executablesIdentified}\n" +
                    $"Scripts identified: {scriptsIdentified}\n" +
                    $"Archives identified: {archivesIdentified}\n" +
                    $"Access denied: {accessDeniedCount}\n" +
                    $"Suspicious: {suspiciousCount}\n" +
                    $"Duration: {sw.ElapsedMilliseconds / 1000.0:F1}s");
            }
            catch (Exception ex)
            {
                sw.Stop();
                context.SetProviderStatus(Id, ProviderExecutionStatus.Failed, ex.Message);
                context.AddError($"FullFilesystemScanner error: {ex.Message}");
            }

            await Task.CompletedTask;
        }

        private void TraverseDirectory(string dirPath, ScanResultContext context, CancellationToken cancellationToken, ref long dirs, ref long files, ref long exes, ref long scripts, ref long archives, ref long accessDenied, ref long suspicious)
        {
            try
            {
                dirs++;
                var di = new DirectoryInfo(dirPath);

                FileInfo[] fileInfos;
                try
                {
                    fileInfos = di.GetFiles();
                }
                catch
                {
                    accessDenied++;
                    context.AddAccessDenied(dirPath);
                    return;
                }

                foreach (var file in fileInfos)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    files++;
                    string ext = file.Extension.ToLowerInvariant();

                    if (ext == ".exe" || ext == ".dll" || ext == ".sys" || ext == ".scr" || ext == ".com")
                    {
                        exes++;
                    }
                    else if (ext == ".bat" || ext == ".cmd" || ext == ".ps1" || ext == ".vbs" || ext == ".js")
                    {
                        scripts++;
                    }
                    else if (ext == ".zip" || ext == ".7z" || ext == ".rar" || ext == ".cab" || ext == ".iso")
                    {
                        archives++;
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
                    // Skip system recovery or recycling bins for speed/safety if desired, or traverse
                    if (subDir.Name.Equals("$Recycle.Bin", StringComparison.OrdinalIgnoreCase) ||
                        subDir.Name.Equals("System Volume Information", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                    TraverseDirectory(subDir.FullName, context, cancellationToken, ref dirs, ref files, ref exes, ref scripts, ref archives, ref accessDenied, ref suspicious);
                }
            }
            catch
            {
                accessDenied++;
            }
        }
    }
}
