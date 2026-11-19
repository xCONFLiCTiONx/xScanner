using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using xScanner.Database;

namespace xScanner.Engines.ClamAV
{
    public class ScanResultInfo
    {
        public bool IsThreat { get; set; }
        public string ThreatName { get; set; } = string.Empty;
        public string ErrorMessage { get; set; } = string.Empty;
    }

    public class ClamAvManager
    {
        private readonly ScanDatabase _database;
        private readonly object _processLock = new();
        private readonly HashSet<Process> _activeProcesses = new();

        // Centralized ClamAV 1.5.4 configuration
        public const string ClamVersion = "1.5.4";
        public const string ClamDownloadUrl = "https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.5.4/clamav-1.5.4.win.x64.zip";
        public const string ClamExpectedSha256 = "0d9e0228b2674137ea1a2853566c98a0278ad52ab2582c3d6dbd75373848c395";

        public ClamAvManager(ScanDatabase database)
        {
            _database = database;
        }

        private void RegisterProcess(Process process)
        {
            lock (_processLock)
            {
                _activeProcesses.Add(process);
            }
        }

        private void UnregisterProcess(Process process)
        {
            lock (_processLock)
            {
                _activeProcesses.Remove(process);
            }
        }

        public void KillActiveProcesses()
        {
            lock (_processLock)
            {
                foreach (var p in _activeProcesses)
                {
                    try
                    {
                        if (!p.HasExited)
                        {
                            p.Kill(true);
                        }
                    }
                    catch { }
                }
                _activeProcesses.Clear();
            }
        }

        public string GetEngineDirectory()
        {
            return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Engines", "ClamAV");
        }

        public string GetClamScanPath()
        {
            string customPath = _database.GetSetting("ClamScanPath", "");
            if (!string.IsNullOrEmpty(customPath) && File.Exists(customPath))
                return customPath;

            string localPath = Path.Combine(GetEngineDirectory(), "clamscan.exe");
            if (File.Exists(localPath))
                return localPath;

            return "clamscan.exe"; // Fallback to PATH
        }

        public string GetFreshClamPath()
        {
            string customPath = _database.GetSetting("FreshClamPath", "");
            if (!string.IsNullOrEmpty(customPath) && File.Exists(customPath))
                return customPath;

            string localPath = Path.Combine(GetEngineDirectory(), "freshclam.exe");
            if (File.Exists(localPath))
                return localPath;

            return "freshclam.exe"; // Fallback to PATH
        }

        public bool IsInstalled()
        {
            return File.Exists(GetClamScanPath()) && File.Exists(GetFreshClamPath());
        }

        public async Task<bool> DownloadAndInstallAsync(IProgress<string> statusProgress, IProgress<double> percentProgress, CancellationToken cancellationToken = default)
        {
            string engineDir = GetEngineDirectory();
            Directory.CreateDirectory(engineDir);

            string tempZip = Path.Combine(Path.GetTempPath(), $"clamav_{Guid.NewGuid()}.zip");
            string extractTemp = Path.Combine(Path.GetTempPath(), $"clamav_extract_{Guid.NewGuid()}");

            try
            {
                statusProgress?.Report("Downloading official ClamAV package...");
                percentProgress?.Report(10);

                using (var httpClient = new HttpClient())
                {
                    httpClient.Timeout = TimeSpan.FromMinutes(10);
                    using var response = await httpClient.GetAsync(ClamDownloadUrl, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                    response.EnsureSuccessStatusCode();

                    var totalBytes = response.Content.Headers.ContentLength ?? 200 * 1024 * 1024;
                    using var contentStream = await response.Content.ReadAsStreamAsync(cancellationToken);
                    using var fileStream = new FileStream(tempZip, FileMode.Create, FileAccess.Write, FileShare.None, 8192, true);

                    var buffer = new byte[8192];
                    long totalRead = 0;
                    int read;
                    while ((read = await contentStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken)) > 0)
                    {
                        await fileStream.WriteAsync(buffer, 0, read, cancellationToken);
                        totalRead += read;
                        double pct = 10 + (double)totalRead / totalBytes * 40;
                        percentProgress?.Report(Math.Min(pct, 50));
                    }
                }

                if (cancellationToken.IsCancellationRequested) return false;

                statusProgress?.Report("Verifying package integrity (SHA-256)...");
                percentProgress?.Report(55);

                string actualHash;
                using (var sha256 = SHA256.Create())
                {
                    using var fs = File.OpenRead(tempZip);
                    byte[] hashBytes = await sha256.ComputeHashAsync(fs, cancellationToken);
                    actualHash = BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
                }

                if (!string.Equals(actualHash, ClamExpectedSha256, StringComparison.OrdinalIgnoreCase))
                {
                    throw new Exception("SHA-256 hash verification failed! The downloaded file may be corrupted or compromised.");
                }

                statusProgress?.Report("Extracting ClamAV files...");
                percentProgress?.Report(60);

                if (Directory.Exists(extractTemp)) Directory.Delete(extractTemp, true);
                ZipFile.ExtractToDirectory(tempZip, extractTemp);

                // Locate clamscan.exe recursively in extracted folder
                string? foundClamScan = null;
                foreach (var file in Directory.GetFiles(extractTemp, "clamscan.exe", SearchOption.AllDirectories))
                {
                    foundClamScan = file;
                    break;
                }

                if (string.IsNullOrEmpty(foundClamScan))
                {
                    throw new Exception("clamscan.exe not found in extracted archive.");
                }

                string sourceDir = Path.GetDirectoryName(foundClamScan)!;

                statusProgress?.Report("Installing ClamAV components...");
                percentProgress?.Report(75);

                // Copy all files from sourceDir to engineDir
                foreach (var file in Directory.GetFiles(sourceDir, "*.*", SearchOption.AllDirectories))
                {
                    if (cancellationToken.IsCancellationRequested) return false;
                    string relPath = Path.GetRelativePath(sourceDir, file);
                    string destFile = Path.Combine(engineDir, relPath);
                    string? destDir = Path.GetDirectoryName(destFile);
                    if (!string.IsNullOrEmpty(destDir)) Directory.CreateDirectory(destDir);
                    File.Copy(file, destFile, true);
                }

                statusProgress?.Report("Configuring FreshClam...");
                percentProgress?.Report(85);

                // Create database dir and freshclam.conf
                string dbDir = Path.Combine(engineDir, "database");
                Directory.CreateDirectory(dbDir);

                string confPath = Path.Combine(engineDir, "freshclam.conf");
                string confContent = $"DatabaseDirectory {dbDir}\nUpdateLogFile {Path.Combine(engineDir, "freshclam.log")}\nDatabaseMirror database.clamav.net\nDatabaseMirror db.us.clamav.net\n";
                await File.WriteAllTextAsync(confPath, confContent, cancellationToken);

                statusProgress?.Report("Downloading malware definitions via FreshClam...");
                percentProgress?.Report(90);

                string freshclamExe = Path.Combine(engineDir, "freshclam.exe");
                if (File.Exists(freshclamExe))
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = freshclamExe,
                        Arguments = $"--config-file=\"{confPath}\"",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };

                    using var process = Process.Start(psi);
                    if (process != null)
                    {
                        RegisterProcess(process);
                        try
                        {
                            using var reg = cancellationToken.Register(() => { try { if (!process.HasExited) process.Kill(true); } catch { } });
                            var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
                            var errorTask = process.StandardError.ReadToEndAsync(cancellationToken);
                            await Task.WhenAll(outputTask, errorTask);
                            await process.WaitForExitAsync(cancellationToken);
                        }
                        catch (OperationCanceledException) { }
                        finally { UnregisterProcess(process); }
                    }
                }

                _database.SetSetting("ClamDefinitionVersion", ClamVersion);
                _database.SetSetting("LastDefinitionUpdate", DateTime.Now.ToString("g"));

                percentProgress?.Report(100);
                statusProgress?.Report("ClamAV installed successfully.");
                return true;
            }
            catch (Exception ex)
            {
                statusProgress?.Report($"Installation failed: {ex.Message}");
                throw;
            }
            finally
            {
                try
                {
                    if (File.Exists(tempZip)) File.Delete(tempZip);
                    if (Directory.Exists(extractTemp)) Directory.Delete(extractTemp, true);
                }
                catch { }
            }
        }

        public async Task<bool> UpdateDefinitionsAsync(IProgress<string>? progress = null, CancellationToken cancellationToken = default)
        {
            string freshclam = GetFreshClamPath();
            string engineDir = GetEngineDirectory();
            string confPath = Path.Combine(engineDir, "freshclam.conf");

            try
            {
                string dbDir = Path.Combine(engineDir, "database");
                Directory.CreateDirectory(dbDir);

                string confContent = $"DatabaseDirectory {dbDir}\nUpdateLogFile {Path.Combine(engineDir, "freshclam.log")}\nDatabaseMirror database.clamav.net\nDatabaseMirror db.us.clamav.net\n";
                await File.WriteAllTextAsync(confPath, confContent, cancellationToken);

                string args = $"--config-file=\"{confPath}\" --stdout";
                var psi = new ProcessStartInfo
                {
                    FileName = freshclam,
                    Arguments = args,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process == null) return false;

                RegisterProcess(process);
                try
                {
                    using var updateCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    updateCts.CancelAfter(TimeSpan.FromMinutes(3));

                    using var reg = updateCts.Token.Register(() => { try { if (!process.HasExited) process.Kill(true); } catch { } });

                    var outputTask = Task.Run(async () =>
                    {
                        using var reader = process.StandardOutput;
                        string? line;
                        while ((line = await reader.ReadLineAsync(updateCts.Token)) != null)
                        {
                            if (!string.IsNullOrWhiteSpace(line))
                            {
                                progress?.Report(line.Trim());
                            }
                        }
                    }, updateCts.Token);

                    var errorTask = Task.Run(async () =>
                    {
                        using var reader = process.StandardError;
                        string? line;
                        while ((line = await reader.ReadLineAsync(updateCts.Token)) != null)
                        {
                            if (!string.IsNullOrWhiteSpace(line))
                            {
                                progress?.Report($"[FRESHCLAM ERR] {line.Trim()}");
                            }
                        }
                    }, updateCts.Token);

                    await Task.WhenAll(outputTask, errorTask);
                    await process.WaitForExitAsync(updateCts.Token);

                    bool success = process.ExitCode == 0;
                    if (success)
                    {
                        _database.SetSetting("LastDefinitionUpdate", DateTime.Now.ToString("g"));
                        progress?.Report("[SUCCESS] Definitions update complete!");
                    }
                    else
                    {
                        progress?.Report("[WARN] Definition update finished (exit code non-zero).");
                    }
                    return success;
                }
                finally
                {
                    UnregisterProcess(process);
                }
            }
            catch (Exception ex)
            {
                progress?.Report($"[ERROR] Definition update failed: {ex.Message}");
                _database.SetSetting("LastDefinitionUpdate", DateTime.Now.ToString("g") + " (Failed/Unavailable)");
                return false;
            }
        }

        public async Task<ScanResultInfo> ScanFileAsync(string filePath, CancellationToken cancellationToken = default)
        {
            string clamscan = GetClamScanPath();
            try
            {
                if (!File.Exists(filePath))
                {
                    return new ScanResultInfo { IsThreat = false, ErrorMessage = "File not found" };
                }

                if (!File.Exists(clamscan))
                {
                    return new ScanResultInfo { IsThreat = false, ErrorMessage = "ClamAV not installed" };
                }

                if (cancellationToken.IsCancellationRequested)
                {
                    return new ScanResultInfo { IsThreat = false, ErrorMessage = "Cancelled" };
                }

                string dbDir = Path.Combine(GetEngineDirectory(), "database");
                string dbArg = Directory.Exists(dbDir) ? $"--database=\"{dbDir}\" " : "";

                var psi = new ProcessStartInfo
                {
                    FileName = clamscan,
                    Arguments = $"{dbArg}--no-summary --stdout --max-scantime=15000 --max-filesize=50M --max-scansize=100M \"{filePath}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process == null)
                {
                    return new ScanResultInfo { IsThreat = false, ErrorMessage = "Failed to start clamscan" };
                }

                RegisterProcess(process);
                try
                {
                    using var fileCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    fileCts.CancelAfter(TimeSpan.FromSeconds(60));

                    using var reg = fileCts.Token.Register(() =>
                    {
                        try
                        {
                            if (!process.HasExited)
                            {
                                process.Kill(true);
                            }
                        }
                        catch { }
                    });

                    var outputTask = process.StandardOutput.ReadToEndAsync(fileCts.Token);
                    var errorTask = process.StandardError.ReadToEndAsync(fileCts.Token);

                    await Task.WhenAll(outputTask, errorTask);
                    await process.WaitForExitAsync(fileCts.Token);

                    string output = outputTask.IsCompletedSuccessfully ? outputTask.Result : string.Empty;

                    if (process.ExitCode == 1)
                    {
                        string threatName = "Generic.Malware";
                        int foundIndex = output.IndexOf("FOUND", StringComparison.OrdinalIgnoreCase);
                        if (foundIndex > 0)
                        {
                            var parts = output.Substring(0, foundIndex).Trim().Split(':');
                            if (parts.Length > 1)
                            {
                                threatName = parts[^1].Trim();
                            }
                        }
                        return new ScanResultInfo { IsThreat = true, ThreatName = threatName };
                    }

                    return new ScanResultInfo { IsThreat = false };
                }
                catch (OperationCanceledException)
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        return new ScanResultInfo { IsThreat = false, ErrorMessage = "Scan cancelled" };
                    }
                    else
                    {
                        return new ScanResultInfo { IsThreat = false, ErrorMessage = "Scan timeout (file too large or slow)" };
                    }
                }
                finally
                {
                    UnregisterProcess(process);
                }
            }
            catch (Exception ex)
            {
                return new ScanResultInfo { IsThreat = false, ErrorMessage = ex.Message };
            }
        }

        /// <summary>
        /// Scans a batch of files in a single clamscan.exe invocation using --file-list so the
        /// 3.6M+ signature database is loaded only once instead of once per file.
        /// Streams per-file results in real time via <paramref name="onFileScanned"/>.
        /// </summary>
        public async Task ScanFilesBatchAsync(
            IReadOnlyList<string> filePaths,
            Action<string, ScanResultInfo>? onFileScanned = null,
            CancellationToken cancellationToken = default)
        {
            if (filePaths == null || filePaths.Count == 0) return;

            string clamscan = GetClamScanPath();
            if (!File.Exists(clamscan))
            {
                foreach (var fp in filePaths)
                {
                    if (cancellationToken.IsCancellationRequested) break;
                    onFileScanned?.Invoke(fp, new ScanResultInfo { IsThreat = false, ErrorMessage = "ClamAV not installed" });
                }
                return;
            }

            string tempListFile = Path.Combine(Path.GetTempPath(), $"xscanner_filelist_{Guid.NewGuid():N}.txt");
            try
            {
                var pendingFiles = new Dictionary<string, string>(filePaths.Count, StringComparer.OrdinalIgnoreCase);
                var validPaths = new List<string>(filePaths.Count);

                foreach (var fp in filePaths)
                {
                    if (string.IsNullOrWhiteSpace(fp)) continue;
                    if (!File.Exists(fp))
                    {
                        onFileScanned?.Invoke(fp, new ScanResultInfo { IsThreat = false, ErrorMessage = "File not found" });
                        continue;
                    }
                    if (pendingFiles.TryAdd(fp, fp))
                    {
                        validPaths.Add(fp);
                    }
                }

                if (validPaths.Count == 0 || cancellationToken.IsCancellationRequested) return;

                // Must be UTF-8 WITHOUT BOM so clamscan does not prepend \uFEFF to the first file path
                var utf8NoBom = new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
                await File.WriteAllLinesAsync(tempListFile, validPaths, utf8NoBom, cancellationToken);

                string dbDir = Path.Combine(GetEngineDirectory(), "database");
                string dbArg = Directory.Exists(dbDir) ? $"--database=\"{dbDir}\" " : "";

                var psi = new ProcessStartInfo
                {
                    FileName = clamscan,
                    Arguments = $"{dbArg}--no-summary --stdout --max-scantime=15000 --max-filesize=50M --max-scansize=100M --file-list=\"{tempListFile}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    StandardOutputEncoding = System.Text.Encoding.UTF8,
                    StandardErrorEncoding = System.Text.Encoding.UTF8,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process == null)
                {
                    foreach (var fp in validPaths)
                    {
                        onFileScanned?.Invoke(fp, new ScanResultInfo { IsThreat = false, ErrorMessage = "Failed to start clamscan" });
                    }
                    return;
                }

                RegisterProcess(process);
                try
                {
                    using var reg = cancellationToken.Register(() =>
                    {
                        try
                        {
                            if (!process.HasExited)
                            {
                                process.Kill(true);
                            }
                        }
                        catch { }
                    });

                    var stdoutTask = Task.Run(async () =>
                    {
                        using var reader = process.StandardOutput;
                        string? line;
                        while ((line = await reader.ReadLineAsync(cancellationToken)) != null)
                        {
                            if (string.IsNullOrWhiteSpace(line)) continue;
                            ParseClamScanLine(line, pendingFiles, onFileScanned);
                        }
                    }, cancellationToken);

                    var stderrTask = Task.Run(async () =>
                    {
                        using var reader = process.StandardError;
                        string? line;
                        while ((line = await reader.ReadLineAsync(cancellationToken)) != null)
                        {
                            // Drain stderr to prevent buffer deadlock
                        }
                    }, cancellationToken);

                    await Task.WhenAll(stdoutTask, stderrTask);
                    await process.WaitForExitAsync(cancellationToken);

                    if (!cancellationToken.IsCancellationRequested && pendingFiles.Count > 0)
                    {
                        foreach (var remaining in pendingFiles.Values)
                        {
                            onFileScanned?.Invoke(remaining, new ScanResultInfo { IsThreat = false });
                        }
                        pendingFiles.Clear();
                    }
                }
                catch (OperationCanceledException)
                {
                    // Cancelled by user
                }
                finally
                {
                    UnregisterProcess(process);
                }
            }
            finally
            {
                try
                {
                    if (File.Exists(tempListFile)) File.Delete(tempListFile);
                }
                catch { }
            }
        }

        private static void ParseClamScanLine(
            string line,
            Dictionary<string, string> pendingFiles,
            Action<string, ScanResultInfo>? onFileScanned)
        {
            string trimmed = line.Trim();
            if (trimmed.StartsWith("WARNING: ", StringComparison.OrdinalIgnoreCase))
            {
                trimmed = trimmed.Substring("WARNING: ".Length).Trim();
            }

            int lastColon = trimmed.LastIndexOf(": ", StringComparison.Ordinal);
            if (lastColon <= 0) return;

            string candidatePath = trimmed.Substring(0, lastColon).Trim();
            string statusPart = trimmed.Substring(lastColon + 2).Trim();

            if (!pendingFiles.Remove(candidatePath, out string? originalPath))
            {
                return;
            }

            if (statusPart.EndsWith("FOUND", StringComparison.OrdinalIgnoreCase))
            {
                string threatName = statusPart.Substring(0, statusPart.Length - "FOUND".Length).Trim();
                if (string.IsNullOrEmpty(threatName)) threatName = "Generic.Malware";
                onFileScanned?.Invoke(originalPath, new ScanResultInfo { IsThreat = true, ThreatName = threatName });
            }
            else if (statusPart.Equals("OK", StringComparison.OrdinalIgnoreCase) ||
                     statusPart.Equals("Empty file", StringComparison.OrdinalIgnoreCase))
            {
                onFileScanned?.Invoke(originalPath, new ScanResultInfo { IsThreat = false });
            }
            else
            {
                onFileScanned?.Invoke(originalPath, new ScanResultInfo { IsThreat = false, ErrorMessage = statusPart });
            }
        }

        public string GetDefinitionVersion()
        {
            return _database.GetSetting("ClamDefinitionVersion", ClamVersion);
        }
    }
}
