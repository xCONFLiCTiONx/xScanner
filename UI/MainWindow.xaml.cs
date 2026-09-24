using System;
using System.Windows;
using xScanner.Core.ScanEngine;
using xScanner.Database;
using xScanner.Engines.ClamAV;

namespace xScanner.UI
{
    public partial class MainWindow : Window
    {
        private readonly ScanDatabase _database;
        private readonly ClamAvManager _clamManager;
        private readonly ScanOrchestrator _orchestrator;
        private bool _isScanning = false;

        public MainWindow()
        {
            InitializeComponent();
            _database = new ScanDatabase();
            _clamManager = new ClamAvManager(_database);
            _orchestrator = new ScanOrchestrator(_database, _clamManager);
            ThemeHelper.ApplyTheme(this);

            LoadStatus();
            LogTerminal("[INFO] xScanner initialized successfully. Ready.");
        }

        private void LoadStatus()
        {
            string lastUp = _database.GetSetting("LastDefinitionUpdate", "Today");
            TxtClamStatus.Text = $"ClamAV: {_clamManager.GetDefinitionVersion()}";
            TxtDefinitionStatus.Text = $"Last Update: {lastUp}";
        }

        private void LogTerminal(string message)
        {
            string timestamp = DateTime.Now.ToString("HH:mm:ss");
            TxtTerminal.AppendText($"[{timestamp}] {message}\n");
            TxtTerminal.ScrollToEnd();
        }

        private void BtnClearTerminal_Click(object sender, RoutedEventArgs e)
        {
            TxtTerminal.Clear();
        }

        private async void BtnBasicScan_Click(object sender, RoutedEventArgs e)
        {
            if (_isScanning) return;
            _isScanning = true;
            SetScanButtonsEnabled(false);
            TxtStatus.Text = "SCANNING";
            TxtStatus.Foreground = System.Windows.Media.Brushes.DarkOrange;
            ScanProgressBar.IsIndeterminate = true;
            ScanProgressBar.Value = 0;

            LogTerminal("[INFO] Starting Basic Scan...");

            try
            {
                LogTerminal("[INFO] Updating ClamAV definitions...");
                await _clamManager.UpdateDefinitionsAsync();
                LogTerminal("[INFO] Definitions update check finished.");

                await _orchestrator.RunBasicScanAsync(progress =>
                {
                    Dispatcher.BeginInvoke(new Action(() =>
                    {
                        if (!string.IsNullOrEmpty(progress.LogMessage))
                        {
                            LogTerminal(progress.LogMessage);
                        }
                        TxtProgress.Text = progress.CurrentFile;
                        TxtFilesScanned.Text = $"Files Scanned: {progress.FilesScanned}";
                        TxtThreatsFound.Text = $"Threats Found: {progress.ThreatsDetected}";

                        ScanProgressBar.IsIndeterminate = progress.IsIndeterminate;
                        if (!progress.IsIndeterminate && progress.TotalFiles > 0)
                        {
                            ScanProgressBar.Maximum = progress.TotalFiles;
                            ScanProgressBar.Value = progress.FilesExamined;
                        }

                        if (progress.IsCompleted)
                        {
                            ScanProgressBar.Value = ScanProgressBar.Maximum > 0 ? ScanProgressBar.Maximum : 100;
                            ScanProgressBar.IsIndeterminate = false;
                            TxtLastScan.Text = $"Last Scan: {DateTime.Now:g}";
                            TxtStatus.Text = progress.ThreatsDetected > 0 ? "THREATS" : "CLEAN";
                            TxtStatus.Foreground = progress.ThreatsDetected > 0 ? System.Windows.Media.Brushes.Red : System.Windows.Media.Brushes.Green;
                            TxtProgress.Text = "Scan completed.";
                            LogTerminal($"[INFO] Basic Scan completed. Examined: {progress.FilesExamined}, Scanned: {progress.FilesScanned}, Threats: {progress.ThreatsDetected}");
                            System.Media.SystemSounds.Asterisk.Play();
                        }
                    }));
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Scan error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                TxtStatus.Text = "ERROR";
                LogTerminal($"[ERROR] Scan failed: {ex.Message}");
            }
            finally
            {
                _isScanning = false;
                SetScanButtonsEnabled(true);
                ScanProgressBar.IsIndeterminate = false;
                LoadStatus();
            }
        }

        private async void BtnFullScan_Click(object sender, RoutedEventArgs e)
        {
            if (_isScanning) return;
            _isScanning = true;
            SetScanButtonsEnabled(false);
            TxtStatus.Text = "SCANNING";
            TxtStatus.Foreground = System.Windows.Media.Brushes.DarkOrange;
            ScanProgressBar.IsIndeterminate = true;
            ScanProgressBar.Value = 0;

            LogTerminal("[INFO] Starting Full Scan across fixed drives...");

            try
            {
                LogTerminal("[INFO] Updating ClamAV definitions...");
                await _clamManager.UpdateDefinitionsAsync();
                LogTerminal("[INFO] Definitions update check finished.");

                var exclusions = _database.GetExclusions();
                if (exclusions.Count > 0)
                {
                    LogTerminal($"[INFO] Loaded {exclusions.Count} exclusion path(s).");
                }

                await _orchestrator.RunFullScanAsync(exclusions, progress =>
                {
                    Dispatcher.Invoke(() =>
                    {
                        if (!string.IsNullOrEmpty(progress.LogMessage))
                        {
                            LogTerminal(progress.LogMessage);
                        }
                        TxtProgress.Text = progress.CurrentFile;
                        TxtFilesScanned.Text = $"Files Scanned: {progress.FilesScanned}";
                        TxtThreatsFound.Text = $"Threats Found: {progress.ThreatsDetected}";

                        ScanProgressBar.IsIndeterminate = progress.IsIndeterminate;
                        if (!progress.IsIndeterminate && progress.TotalFiles > 0)
                        {
                            ScanProgressBar.Maximum = progress.TotalFiles;
                            ScanProgressBar.Value = progress.FilesExamined;
                        }

                        if (progress.IsCompleted)
                        {
                            ScanProgressBar.Value = ScanProgressBar.Maximum > 0 ? ScanProgressBar.Maximum : 100;
                            ScanProgressBar.IsIndeterminate = false;
                            TxtLastScan.Text = $"Last Scan: {DateTime.Now:g}";
                            TxtStatus.Text = progress.ThreatsDetected > 0 ? "THREATS" : "CLEAN";
                            TxtStatus.Foreground = progress.ThreatsDetected > 0 ? System.Windows.Media.Brushes.Red : System.Windows.Media.Brushes.Green;
                            TxtProgress.Text = "Full Scan completed.";
                            LogTerminal($"[INFO] Full Scan completed. Examined: {progress.FilesExamined}, Scanned: {progress.FilesScanned}, Threats: {progress.ThreatsDetected}");
                            System.Media.SystemSounds.Asterisk.Play();
                        }
                    });
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Scan error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                TxtStatus.Text = "ERROR";
                LogTerminal($"[ERROR] Full scan failed: {ex.Message}");
            }
            finally
            {
                _isScanning = false;
                SetScanButtonsEnabled(true);
                ScanProgressBar.IsIndeterminate = false;
                LoadStatus();
            }
        }

        private void SetScanButtonsEnabled(bool enabled)
        {
            BtnBasicScan.IsEnabled = enabled;
            BtnFullScan.IsEnabled = enabled;
        }

        private void BtnQuarantine_Click(object sender, RoutedEventArgs e)
        {
            var qWindow = new QuarantineWindow(_database);
            qWindow.Owner = this;
            qWindow.ShowDialog();
        }

        private void BtnHistory_Click(object sender, RoutedEventArgs e)
        {
            var hWindow = new HistoryWindow(_database);
            hWindow.Owner = this;
            hWindow.ShowDialog();
        }

        private void BtnSettings_Click(object sender, RoutedEventArgs e)
        {
            var sWindow = new SettingsWindow(_database);
            sWindow.Owner = this;
            sWindow.ShowDialog();
            LoadStatus();
        }
    }
}
