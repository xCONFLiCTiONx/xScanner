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

            LoadStatus();
        }

        private void LoadStatus()
        {
            string lastUp = _database.GetSetting("LastDefinitionUpdate", "Today");
            TxtDefinitionStatus.Text = $"Last Update: {lastUp}";
            TxtClamStatus.Text = $"ClamAV: {_clamManager.GetDefinitionVersion()}";
        }

        private async void BtnBasicScan_Click(object sender, RoutedEventArgs e)
        {
            if (_isScanning) return;
            _isScanning = true;
            SetScanButtonsEnabled(false);
            TxtStatus.Text = "SCANNING";
            TxtStatus.Foreground = System.Windows.Media.Brushes.DarkOrange;

            try
            {
                await _clamManager.UpdateDefinitionsAsync();
                await _orchestrator.RunBasicScanAsync(progress =>
                {
                    Dispatcher.Invoke(() =>
                    {
                        TxtProgress.Text = progress.CurrentFile;
                        TxtFilesScanned.Text = $"Files Scanned: {progress.FilesScanned}";
                        TxtThreatsFound.Text = $"Threats Found: {progress.ThreatsDetected}";
                        if (progress.IsCompleted)
                        {
                            TxtLastScan.Text = $"Last Scan: {DateTime.Now:g}";
                            TxtStatus.Text = progress.ThreatsDetected > 0 ? "THREATS" : "CLEAN";
                            TxtStatus.Foreground = progress.ThreatsDetected > 0 ? System.Windows.Media.Brushes.Red : System.Windows.Media.Brushes.Green;
                            TxtProgress.Text = "Scan completed.";
                        }
                    });
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Scan error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                TxtStatus.Text = "ERROR";
            }
            finally
            {
                _isScanning = false;
                SetScanButtonsEnabled(true);
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

            try
            {
                await _clamManager.UpdateDefinitionsAsync();
                var exclusions = _database.GetExclusions();
                await _orchestrator.RunFullScanAsync(exclusions, progress =>
                {
                    Dispatcher.Invoke(() =>
                    {
                        TxtProgress.Text = progress.CurrentFile;
                        TxtFilesScanned.Text = $"Files Scanned: {progress.FilesScanned}";
                        TxtThreatsFound.Text = $"Threats Found: {progress.ThreatsDetected}";
                        if (progress.IsCompleted)
                        {
                            TxtLastScan.Text = $"Last Scan: {DateTime.Now:g}";
                            TxtStatus.Text = progress.ThreatsDetected > 0 ? "THREATS" : "CLEAN";
                            TxtStatus.Foreground = progress.ThreatsDetected > 0 ? System.Windows.Media.Brushes.Red : System.Windows.Media.Brushes.Green;
                            TxtProgress.Text = "Full Scan completed.";
                        }
                    });
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Scan error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                TxtStatus.Text = "ERROR";
            }
            finally
            {
                _isScanning = false;
                SetScanButtonsEnabled(true);
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
