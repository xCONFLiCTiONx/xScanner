using System;
using System.ComponentModel;
using System.Threading;
using System.Threading.Tasks;
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
        private SystemTrayManager? _trayManager;
        private bool _isScanning = false;
        private CancellationTokenSource? _scanCts;
        private Task? _activeScanTask;
        private bool _isShutdownInProgress = false;
        private bool _isShutdownCompleted = false;
        private bool _isExplicitExit = false;
        private bool _hasShownTrayTip = false;

        public MainWindow()
        {
            InitializeComponent();
            _database = new ScanDatabase();
            _clamManager = new ClamAvManager(_database);
            _orchestrator = new ScanOrchestrator(_database, _clamManager);
            ThemeHelper.ApplyTheme(this);

            _trayManager = new SystemTrayManager(ShowFromTray, ExitApplication);

            LoadStatus();
            LogTerminal("[INFO] xScanner initialized successfully. Ready.");
        }

        public void ShowFromTray()
        {
            Show();
            if (WindowState == WindowState.Minimized)
            {
                WindowState = WindowState.Normal;
            }
            Activate();
        }

        public async void ExitApplication()
        {
            _isExplicitExit = true;
            if (_isShutdownInProgress) return;

            _isShutdownInProgress = true;
            await PerformShutdownCleanupAsync();
            _trayManager?.Dispose();
            _isShutdownCompleted = true;
            Close();
            System.Windows.Application.Current.Shutdown();
        }

        private void LoadStatus()
        {
            string lastUp = _database.GetSetting("LastDefinitionUpdate", "Today");
            TxtClamStatus.Text = $"ClamAV: {_clamManager.GetDefinitionVersion()}";
            TxtDefinitionStatus.Text = $"Last Update: {lastUp}";
        }

        private void LogTerminal(string message)
        {
            if (!Dispatcher.CheckAccess())
            {
                Dispatcher.Invoke(() => LogTerminal(message));
                return;
            }

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
            if (_isScanning || _isShutdownInProgress) return;
            _isScanning = true;
            _scanCts = new CancellationTokenSource();
            var token = _scanCts.Token;

            SetScanButtonsEnabled(false);
            TxtStatus.Text = "SCANNING";
            TxtStatus.Foreground = System.Windows.Media.Brushes.DarkOrange;
            ScanProgressBar.IsIndeterminate = true;
            ScanProgressBar.Value = 0;
            _trayManager?.UpdateStatus("Scanning in progress...");

            LogTerminal("[INFO] Starting Basic Scan...");

            _activeScanTask = Task.Run(async () =>
            {
                try
                {
                    LogTerminal("[INFO] Updating ClamAV definitions...");
                    await _clamManager.UpdateDefinitionsAsync(token);
                    if (token.IsCancellationRequested) return;
                    LogTerminal("[INFO] Definitions update check finished.");

                    await _orchestrator.RunBasicScanAsync(progress =>
                    {
                        _ = Dispatcher.BeginInvoke(new Action(() =>
                        {
                            if (_isShutdownInProgress) return;

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
                                _trayManager?.UpdateStatus("Ready");
                                System.Media.SystemSounds.Asterisk.Play();
                            }
                        }));
                    }, token);
                }
                catch (OperationCanceledException)
                {
                    Dispatcher.Invoke(() => LogTerminal("[INFO] Basic Scan cancelled."));
                }
                catch (Exception ex)
                {
                    Dispatcher.Invoke(() =>
                    {
                        System.Windows.MessageBox.Show($"Scan error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        TxtStatus.Text = "ERROR";
                        LogTerminal($"[ERROR] Scan failed: {ex.Message}");
                        _trayManager?.UpdateStatus("Scan Error");
                    });
                }
                finally
                {
                    Dispatcher.Invoke(() =>
                    {
                        bool wasCancelled = _scanCts != null && _scanCts.IsCancellationRequested;
                        _isScanning = false;
                        if (!_isShutdownInProgress)
                        {
                            SetScanButtonsEnabled(true);
                            ScanProgressBar.IsIndeterminate = false;
                            if (wasCancelled)
                            {
                                TxtStatus.Text = "STOPPED";
                                TxtStatus.Foreground = System.Windows.Media.Brushes.Gray;
                                TxtProgress.Text = "Scan stopped by user.";
                                _trayManager?.UpdateStatus("Scan Stopped");
                            }
                            LoadStatus();
                        }
                    });
                }
            }, token);

            await _activeScanTask;
        }

        private async void BtnFullScan_Click(object sender, RoutedEventArgs e)
        {
            if (_isScanning || _isShutdownInProgress) return;
            _isScanning = true;
            _scanCts = new CancellationTokenSource();
            var token = _scanCts.Token;

            SetScanButtonsEnabled(false);
            TxtStatus.Text = "SCANNING";
            TxtStatus.Foreground = System.Windows.Media.Brushes.DarkOrange;
            ScanProgressBar.IsIndeterminate = true;
            ScanProgressBar.Value = 0;
            _trayManager?.UpdateStatus("Full Scan in progress...");

            LogTerminal("[INFO] Starting Full Scan across fixed drives...");

            _activeScanTask = Task.Run(async () =>
            {
                try
                {
                    LogTerminal("[INFO] Updating ClamAV definitions...");
                    await _clamManager.UpdateDefinitionsAsync(token);
                    if (token.IsCancellationRequested) return;
                    LogTerminal("[INFO] Definitions update check finished.");

                    var exclusions = _database.GetExclusions();
                    if (exclusions.Count > 0)
                    {
                        LogTerminal($"[INFO] Loaded {exclusions.Count} exclusion path(s).");
                    }

                    await _orchestrator.RunFullScanAsync(exclusions, progress =>
                    {
                        _ = Dispatcher.BeginInvoke(new Action(() =>
                        {
                            if (_isShutdownInProgress) return;

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
                                _trayManager?.UpdateStatus("Ready");
                                System.Media.SystemSounds.Asterisk.Play();
                            }
                        }));
                    }, token);
                }
                catch (OperationCanceledException)
                {
                    Dispatcher.Invoke(() => LogTerminal("[INFO] Full Scan cancelled."));
                }
                catch (Exception ex)
                {
                    Dispatcher.Invoke(() =>
                    {
                        System.Windows.MessageBox.Show($"Scan error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        TxtStatus.Text = "ERROR";
                        LogTerminal($"[ERROR] Full scan failed: {ex.Message}");
                        _trayManager?.UpdateStatus("Scan Error");
                    });
                }
                finally
                {
                    Dispatcher.Invoke(() =>
                    {
                        bool wasCancelled = _scanCts != null && _scanCts.IsCancellationRequested;
                        _isScanning = false;
                        if (!_isShutdownInProgress)
                        {
                            SetScanButtonsEnabled(true);
                            ScanProgressBar.IsIndeterminate = false;
                            if (wasCancelled)
                            {
                                TxtStatus.Text = "STOPPED";
                                TxtStatus.Foreground = System.Windows.Media.Brushes.Gray;
                                TxtProgress.Text = "Scan stopped by user.";
                                _trayManager?.UpdateStatus("Scan Stopped");
                            }
                            LoadStatus();
                        }
                    });
                }
            }, token);

            await _activeScanTask;
        }

        protected override async void OnClosing(CancelEventArgs e)
        {
            if (_isShutdownCompleted)
            {
                base.OnClosing(e);
                return;
            }

            if (!_isExplicitExit)
            {
                // User clicked 'X' on window: minimize/hide to System Tray
                e.Cancel = true;
                Hide();

                if (!_hasShownTrayTip)
                {
                    _hasShownTrayTip = true;
                    _trayManager?.ShowNotification(
                        "xScanner System Tray",
                        "xScanner is running in the system tray. Right-click the icon to open or exit.",
                        System.Windows.Forms.ToolTipIcon.Info
                    );
                }
                return;
            }

            e.Cancel = true;

            if (_isShutdownInProgress)
            {
                return;
            }

            _isShutdownInProgress = true;
            await PerformShutdownCleanupAsync();

            _trayManager?.Dispose();
            _isShutdownCompleted = true;
            Close();
            System.Windows.Application.Current.Shutdown();
        }

        private async Task PerformShutdownCleanupAsync()
        {
            SetScanButtonsEnabled(false);
            TxtStatus.Text = "CLOSING";
            TxtStatus.Foreground = System.Windows.Media.Brushes.DarkOrange;

            ScanProgressBar.IsIndeterminate = false;
            ScanProgressBar.Minimum = 0;
            ScanProgressBar.Maximum = 100;
            ScanProgressBar.Value = 0;

            LogTerminal("[INFO] =========================================");
            LogTerminal("[INFO] Standard window close requested (X button).");
            LogTerminal("[INFO] Initiating graceful shutdown and cleanup...");

            // Step 1: Signal cancellation to active scan tasks (0% -> 25%)
            ScanProgressBar.Value = 10;
            TxtProgress.Text = "Stopping active scan operations (10%)...";
            if (_scanCts != null && !_scanCts.IsCancellationRequested)
            {
                LogTerminal("[INFO] Step 1/4: Cancelling active scan engine tasks...");
                _scanCts.Cancel();
            }
            else
            {
                LogTerminal("[INFO] Step 1/4: No active scan tasks to cancel.");
            }

            if (_activeScanTask != null && !_activeScanTask.IsCompleted)
            {
                ScanProgressBar.Value = 20;
                TxtProgress.Text = "Waiting for scan worker thread to stop cleanly (20%)...";
                try
                {
                    await Task.WhenAny(_activeScanTask, Task.Delay(1500));
                }
                catch { }
            }

            ScanProgressBar.Value = 25;
            await Task.Delay(100);

            // Step 2: Terminate child processes (ClamAV) (25% -> 50%)
            ScanProgressBar.Value = 40;
            TxtProgress.Text = "Terminating background ClamAV engine processes (40%)...";
            LogTerminal("[INFO] Step 2/4: Terminating any running child engine processes...");
            _clamManager.KillActiveProcesses();
            ScanProgressBar.Value = 50;
            await Task.Delay(150);

            // Step 3: Flush database and record application shutdown (50% -> 80%)
            ScanProgressBar.Value = 65;
            TxtProgress.Text = "Flushing scan history and saving final database state (65%)...";
            LogTerminal("[INFO] Step 3/4: Writing final shutdown record to local database...");
            try
            {
                _database.SetSetting("LastShutdownTime", DateTime.Now.ToString("o"));
                _database.SetSetting("LastCleanStopStatus", "Successful");
            }
            catch (Exception ex)
            {
                LogTerminal($"[WARN] Could not write shutdown state: {ex.Message}");
            }
            ScanProgressBar.Value = 80;
            await Task.Delay(150);

            // Step 4: Finalizing shutdown (80% -> 100%)
            ScanProgressBar.Value = 95;
            TxtProgress.Text = "Cleanup complete. Finalizing shutdown (95%)...";
            LogTerminal("[INFO] Step 4/4: Cleanup operations complete. Closing xScanner.");
            ScanProgressBar.Value = 100;
            TxtProgress.Text = "Closed cleanly.";
            await Task.Delay(350);
        }

        private void BtnStopScan_Click(object sender, RoutedEventArgs e)
        {
            if (!_isScanning || _scanCts == null || _scanCts.IsCancellationRequested) return;

            LogTerminal("[INFO] Stop requested by user. Cancelling active scan...");
            BtnStopScan.IsEnabled = false;
            TxtProgress.Text = "Stopping scan...";
            _scanCts.Cancel();
            _clamManager.KillActiveProcesses();
        }

        private void SetScanButtonsEnabled(bool enableStartButtons)
        {
            BtnBasicScan.IsEnabled = enableStartButtons && !_isShutdownInProgress;
            BtnFullScan.IsEnabled = enableStartButtons && !_isShutdownInProgress;
            BtnStopScan.IsEnabled = !enableStartButtons && _isScanning && !_isShutdownInProgress;
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
