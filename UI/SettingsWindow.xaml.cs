using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using xScanner.Core.ScanScheduler;
using xScanner.Database;
using xScanner.Engines.ClamAV;

namespace xScanner.UI
{
    public partial class SettingsWindow : Window
    {
        private readonly ScanDatabase _database;
        private readonly ClamAvManager _clamManager;
        private bool _isInitialized = false;

        public SettingsWindow(ScanDatabase database)
        {
            InitializeComponent();
            _database = database;
            _clamManager = new ClamAvManager(database);
            ThemeHelper.ApplyTheme(this);
            LoadSettings();
            _isInitialized = true;
        }

        private void LoadSettings()
        {
            string mode = _database.GetSetting("AutomaticScanMode", "Basic");
            CbAutoMode.SelectedIndex = mode switch
            {
                "Disabled" => 0,
                "Basic" => 1,
                "Full" => 2,
                _ => 1
            };

            bool enableAll = bool.Parse(_database.GetSetting("EnableAllNotifications", "True"));
            bool enableHardening = bool.Parse(_database.GetSetting("EnableHardeningAlerts", "True"));

            CbEnableAllNotifications.IsChecked = enableAll;
            CbEnableHardeningAlerts.IsChecked = enableHardening;
            CbEnableHardeningAlerts.IsEnabled = enableAll;

            TxtClamPath.Text = _clamManager.GetEngineDirectory();
            RefreshClamStatus();
            RefreshExclusions();
            RefreshScheduleStatus();
        }

        private void RefreshClamStatus()
        {
            bool installed = _clamManager.IsInstalled();
            TxtClamPath.Text = _clamManager.GetEngineDirectory();

            if (installed)
            {
                TxtClamStatus.Text = $"Status: Installed — Version {ClamAvManager.ClamVersion} (Path: {_clamManager.GetEngineDirectory()})";
                TxtClamStatus.Foreground = System.Windows.Media.Brushes.Green;
                BtnInstallClam.Content = "Reinstall / Update ClamAV";
                BtnUpdateDefs.IsEnabled = true;
                string lastUp = _database.GetSetting("LastDefinitionUpdate", "Never");
                TxtDefinitionInfo.Text = $"Definitions: Current (Last Updated: {lastUp})";
            }
            else
            {
                TxtClamStatus.Text = "Status: Not Installed";
                TxtClamStatus.Foreground = System.Windows.Media.Brushes.Red;
                BtnInstallClam.Content = "Download / Install ClamAV";
                BtnUpdateDefs.IsEnabled = false;
                TxtDefinitionInfo.Text = "Definitions: Not Available";
            }
        }

        private void RefreshScheduleStatus()
        {
            bool isRegistered = SchedulerManager.IsTaskRegistered(SchedulerManager.DefaultTaskName);
            if (isRegistered)
            {
                TxtTaskStatus.Text = "Status: Registered (1 AM Weekly)";
                TxtTaskStatus.Foreground = System.Windows.Media.Brushes.Green;
                BtnScheduleTask.Content = "Remove Scheduled Task";
                BtnScheduleTask.Background = (System.Windows.Media.Brush?)new System.Windows.Media.BrushConverter().ConvertFrom("#DC3545") ?? System.Windows.Media.Brushes.Red;
            }
            else
            {
                TxtTaskStatus.Text = "Status: Not Registered";
                TxtTaskStatus.Foreground = System.Windows.Media.Brushes.Gray;
                BtnScheduleTask.Content = "Create Scheduled Scan (1 AM, Wake PC)";
                BtnScheduleTask.Background = (System.Windows.Media.Brush?)new System.Windows.Media.BrushConverter().ConvertFrom("#007ACC") ?? System.Windows.Media.Brushes.Blue;
            }
        }

        private void RefreshExclusions()
        {
            LbExclusions.ItemsSource = _database.GetExclusions();
        }

        private void BtnBrowseExclusion_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFolderDialog
            {
                Title = "Select Folder to Exclude"
            };
            if (dialog.ShowDialog() == true)
            {
                TxtNewExclusion.Text = dialog.FolderName;
            }
        }

        private void BtnAddExclusion_Click(object sender, RoutedEventArgs e)
        {
            string path = TxtNewExclusion.Text.Trim();
            if (!string.IsNullOrEmpty(path))
            {
                _database.AddExclusion(path);
                TxtNewExclusion.Clear();
                RefreshExclusions();
            }
        }

        private void BtnRemoveExclusion_Click(object sender, RoutedEventArgs e)
        {
            if (LbExclusions.SelectedItem is string path)
            {
                _database.RemoveExclusion(path);
                RefreshExclusions();
            }
        }

        private void BtnScheduleTask_Click(object sender, RoutedEventArgs e)
        {
            bool isRegistered = SchedulerManager.IsTaskRegistered(SchedulerManager.DefaultTaskName);
            if (isRegistered)
            {
                bool removed = SchedulerManager.RemoveSchedule(SchedulerManager.DefaultTaskName);
                if (removed)
                {
                    RefreshScheduleStatus();
                }
                else
                {
                    TxtTaskStatus.Text = "Status: Failed to remove task";
                    TxtTaskStatus.Foreground = System.Windows.Media.Brushes.Red;
                }
            }
            else
            {
                bool created = SchedulerManager.ConfigureWeeklySchedule(SchedulerManager.DefaultTaskName, "01:00", wakePc: true);
                if (created)
                {
                    RefreshScheduleStatus();
                }
                else
                {
                    TxtTaskStatus.Text = "Status: Failed to create task (Admin required)";
                    TxtTaskStatus.Foreground = System.Windows.Media.Brushes.Red;
                }
            }
        }

        private async void BtnInstallClam_Click(object sender, RoutedEventArgs e)
        {
            BtnInstallClam.IsEnabled = false;
            BtnUpdateDefs.IsEnabled = false;
            PbInstall.Visibility = Visibility.Visible;
            PbInstall.Value = 0;

            var statusProgress = new Progress<string>(msg => TxtInstallProgress.Text = msg);
            var pctProgress = new Progress<double>(pct => PbInstall.Value = pct);

            try
            {
                bool success = await Task.Run(() => _clamManager.DownloadAndInstallAsync(statusProgress, pctProgress));
                if (success)
                {
                    System.Media.SystemSounds.Asterisk.Play();
                }
            }
            catch (Exception ex)
            {
                TxtInstallProgress.Text = $"Installation failed: {ex.Message}";
            }
            finally
            {
                BtnInstallClam.IsEnabled = true;
                RefreshClamStatus();
            }
        }

        private async void BtnUpdateDefs_Click(object sender, RoutedEventArgs e)
        {
            BtnUpdateDefs.IsEnabled = false;
            TxtInstallProgress.Text = "Updating definitions...";

            try
            {
                bool success = await _clamManager.UpdateDefinitionsAsync();
                if (success)
                {
                    System.Media.SystemSounds.Asterisk.Play();
                    RefreshClamStatus();
                }
                else
                {
                    TxtInstallProgress.Text = "Definition update failed.";
                }
            }
            catch (Exception ex)
            {
                TxtInstallProgress.Text = $"Update error: {ex.Message}";
            }
            finally
            {
                BtnUpdateDefs.IsEnabled = true;
            }
        }

        private void CbAutoMode_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (!_isInitialized) return;
            string mode = (CbAutoMode.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Basic";
            _database.SetSetting("AutomaticScanMode", mode);
        }

        private void CbEnableAllNotifications_Changed(object sender, RoutedEventArgs e)
        {
            if (CbEnableHardeningAlerts != null && CbEnableAllNotifications != null)
            {
                CbEnableHardeningAlerts.IsEnabled = CbEnableAllNotifications.IsChecked == true;
                if (_isInitialized)
                {
                    _database.SetSetting("EnableAllNotifications", (CbEnableAllNotifications.IsChecked == true).ToString());
                }
            }
        }

        private void CbEnableHardeningAlerts_Changed(object sender, RoutedEventArgs e)
        {
            if (_isInitialized && CbEnableHardeningAlerts != null)
            {
                _database.SetSetting("EnableHardeningAlerts", (CbEnableHardeningAlerts.IsChecked == true).ToString());
            }
        }
    }
}
