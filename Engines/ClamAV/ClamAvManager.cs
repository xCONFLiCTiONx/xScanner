using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Security.Cryptography;
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

        // Centralized ClamAV 1.5.4 configuration
        public const string ClamVersion = "1.5.4";
        public const string ClamDownloadUrl = "https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.5.4/clamav-1.5.4.win.x64.zip";
        public const string ClamExpectedSha256 = "0d9e0228b2674137ea1a2853566c98a0278ad52ab2582c3d6dbd75373848c395";

        public ClamAvManager(ScanDatabase database)
        {
            _database = database;
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

        public async Task<bool> DownloadAndInstallAsync(IProgress<string> statusProgress, IProgress<double> percentProgress)
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
                    using var response = await httpClient.GetAsync(ClamDownloadUrl, HttpCompletionOption.ResponseHeadersRead);
                    response.EnsureSuccessStatusCode();

                    var totalBytes = response.Content.Headers.ContentLength ?? 200 * 1024 * 1024;
                    using var contentStream = await response.Content.ReadAsStreamAsync();
                    using var fileStream = new FileStream(tempZip, FileMode.Create, FileAccess.Write, FileShare.None, 8192, true);

                    var buffer = new byte[8192];
                    long totalRead = 0;
                    int read;
                    while ((read = await contentStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                    {
                        await fileStream.WriteAsync(buffer, 0, read);
                        totalRead += read;
                        double pct = 10 + (double)totalRead / totalBytes * 40;
                        percentProgress?.Report(Math.Min(pct, 50));
                    }
                }

                statusProgress?.Report("Verifying package integrity (SHA-256)...");
                percentProgress?.Report(55);

                string actualHash;
                using (var sha256 = SHA256.Create())
                {
                    using var fs = File.OpenRead(tempZip);
                    byte[] hashBytes = await sha256.ComputeHashAsync(fs);
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
                string confContent = $"DatabaseDirectory {dbDir}\nUpdateLogFile {Path.Combine(engineDir, "freshclam.log")}\n";
                await File.WriteAllTextAsync(confPath, confContent);

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
                        await process.WaitForExitAsync();
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

        public async Task<bool> UpdateDefinitionsAsync()
        {
            string freshclam = GetFreshClamPath();
            string engineDir = GetEngineDirectory();
            string confPath = Path.Combine(engineDir, "freshclam.conf");

            try
            {
                string args = File.Exists(confPath) ? $"--config-file=\"{confPath}\"" : "";
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

                await process.WaitForExitAsync();
                _database.SetSetting("LastDefinitionUpdate", DateTime.Now.ToString("g"));
                return process.ExitCode == 0;
            }
            catch
            {
                _database.SetSetting("LastDefinitionUpdate", DateTime.Now.ToString("g") + " (Failed/Unavailable)");
                return false;
            }
        }

        public async Task<ScanResultInfo> ScanFileAsync(string filePath)
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

                var psi = new ProcessStartInfo
                {
                    FileName = clamscan,
                    Arguments = $"--no-summary \"{filePath}\"",
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

                string output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();

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
            catch (Exception ex)
            {
                return new ScanResultInfo { IsThreat = false, ErrorMessage = ex.Message };
            }
        }

        public string GetDefinitionVersion()
        {
            return _database.GetSetting("ClamDefinitionVersion", ClamVersion);
        }
    }
}
