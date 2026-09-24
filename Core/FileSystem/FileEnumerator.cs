using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using Microsoft.Win32;

namespace xScanner.Core.FileSystem
{
    public static class FileEnumerator
    {
        public static IEnumerable<string> GetBasicScanFiles(List<string>? exclusions = null, CancellationToken cancellationToken = default)
        {
            var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // 1. Startup folders
            try
            {
                string startupUser = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                if (Directory.Exists(startupUser))
                    foreach (var f in Directory.GetFiles(startupUser, "*.*", SearchOption.AllDirectories))
                    {
                        if (cancellationToken.IsCancellationRequested) return files;
                        if (!IsExcluded(f, exclusions)) files.Add(f);
                    }

                string startupCommon = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
                if (Directory.Exists(startupCommon))
                    foreach (var f in Directory.GetFiles(startupCommon, "*.*", SearchOption.AllDirectories))
                    {
                        if (cancellationToken.IsCancellationRequested) return files;
                        if (!IsExcluded(f, exclusions)) files.Add(f);
                    }
            }
            catch { }

            if (cancellationToken.IsCancellationRequested) return files;

            // 2. Downloads, Desktop, Temp, AppData, LocalAppData
            AddDirectoryFiles(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads", files, exclusions, cancellationToken);
            AddDirectoryFiles(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop", files, exclusions, cancellationToken);
            AddDirectoryFiles(Path.GetTempPath(), "", files, exclusions, cancellationToken);
            AddDirectoryFiles(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "", files, exclusions, cancellationToken);
            AddDirectoryFiles(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "", files, exclusions, cancellationToken);

            if (cancellationToken.IsCancellationRequested) return files;

            // 3. Registry Run / RunOnce locations
            GetRegistryFiles(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", files, exclusions);
            GetRegistryFiles(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", files, exclusions);
            GetRegistryFiles(Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run", files, exclusions);
            GetRegistryFiles(Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", files, exclusions);
            GetRegistryFiles(Registry.LocalMachine, @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", files, exclusions);

            return files;
        }

        public static IEnumerable<string> GetFullScanFiles(List<string> exclusions, CancellationToken cancellationToken = default)
        {
            var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var drives = DriveInfo.GetDrives();

            foreach (var drive in drives)
            {
                if (cancellationToken.IsCancellationRequested) break;

                if (drive.DriveType == DriveType.Fixed && drive.IsReady)
                {
                    string rootDir = drive.RootDirectory.FullName;
                    if (IsExcluded(rootDir, exclusions)) continue;

                    EnumerateDirectoryRecursive(rootDir, exclusions, files, cancellationToken);
                }
            }

            return files;
        }

        private static void EnumerateDirectoryRecursive(string dir, List<string> exclusions, HashSet<string> files, CancellationToken cancellationToken)
        {
            try
            {
                if (cancellationToken.IsCancellationRequested) return;

                foreach (var file in Directory.GetFiles(dir))
                {
                    if (cancellationToken.IsCancellationRequested) return;
                    if (IsExcluded(file, exclusions)) continue;
                    files.Add(file);
                }

                foreach (var subDir in Directory.GetDirectories(dir))
                {
                    if (cancellationToken.IsCancellationRequested) return;
                    if (IsExcluded(subDir, exclusions)) continue;
                    EnumerateDirectoryRecursive(subDir, exclusions, files, cancellationToken);
                }
            }
            catch { }
        }

        private static bool IsExcluded(string path, List<string>? exclusions)
        {
            if (exclusions == null) return false;
            foreach (var excl in exclusions)
            {
                if (string.IsNullOrEmpty(excl)) continue;
                if (path.StartsWith(excl, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(path, excl, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        private static void AddDirectoryFiles(string basePath, string subFolder, HashSet<string> files, List<string>? exclusions = null, CancellationToken cancellationToken = default)
        {
            try
            {
                if (cancellationToken.IsCancellationRequested) return;

                string target = string.IsNullOrEmpty(subFolder) ? basePath : Path.Combine(basePath, subFolder);
                if (Directory.Exists(target))
                {
                    foreach (var f in Directory.GetFiles(target, "*.*", SearchOption.TopDirectoryOnly))
                    {
                        if (cancellationToken.IsCancellationRequested) return;
                        if (!IsExcluded(f, exclusions)) files.Add(f);
                    }
                    // Also check 1 level subfolders for temp/appdata
                    foreach (var d in Directory.GetDirectories(target))
                    {
                        if (cancellationToken.IsCancellationRequested) return;
                        if (IsExcluded(d, exclusions)) continue;
                        try
                        {
                            foreach (var f in Directory.GetFiles(d, "*.*", SearchOption.TopDirectoryOnly))
                            {
                                if (cancellationToken.IsCancellationRequested) return;
                                if (!IsExcluded(f, exclusions)) files.Add(f);
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        private static void GetRegistryFiles(RegistryKey rootKey, string subKeyPath, HashSet<string> files, List<string>? exclusions = null)
        {
            try
            {
                using var key = rootKey.OpenSubKey(subKeyPath);
                if (key != null)
                {
                    foreach (var valName in key.GetValueNames())
                    {
                        string valData = key.GetValue(valName)?.ToString() ?? string.Empty;
                        // Extract file path from command line (e.g. "C:\path\app.exe" /arg -> C:\path\app.exe)
                        string cleanedPath = CleanFilePathFromCommand(valData);
                        if (!string.IsNullOrEmpty(cleanedPath) && File.Exists(cleanedPath) && !IsExcluded(cleanedPath, exclusions))
                        {
                            files.Add(cleanedPath);
                        }
                    }
                }
            }
            catch { }
        }

        private static string CleanFilePathFromCommand(string cmd)
        {
            cmd = cmd.Trim();
            if (cmd.StartsWith("\""))
            {
                int endQuote = cmd.IndexOf('"', 1);
                if (endQuote > 1)
                {
                    return cmd.Substring(1, endQuote - 1);
                }
            }
            int spaceIdx = cmd.IndexOf(' ');
            if (spaceIdx > 0)
            {
                string possiblePath = cmd.Substring(0, spaceIdx);
                if (File.Exists(possiblePath)) return possiblePath;
            }
            return cmd;
        }
    }
}
