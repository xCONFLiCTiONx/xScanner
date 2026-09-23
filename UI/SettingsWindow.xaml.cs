using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using xScanner.Database;
using xScanner.Engines.ClamAV;

namespace xScanner.UI
{
    public partial class SettingsWindow : Window
    {
        private readonly ScanDatabase _database;
        private readonly ClamAvManager _clamManager;

        public SettingsWindow(ScanDatabase database)
        {
            InitializeComponent();
            _database = database;
            _clamManager = new ClamAvManager(database);
            ThemeHelper.ApplyTheme(this);
            LoadSettings();
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

            TxtClamPath.Text = _clamManager.GetEngineDirectory();
            RefreshClamStatus();
            RefreshExclusions();
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
                MessageBox.Show($"ClamAV installation failed:\n{ex.Message}", "Installation Error", MessageBoxButton.OK, MessageBoxImage.Error);
                TxtInstallProgress.Text = "Installation failed.";
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
                    MessageBox.Show("Definition update failed.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Update error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                BtnUpdateDefs.IsEnabled = true;
                TxtInstallProgress.Text = "";
            }
        }

        private void BtnSave_Click(object sender, RoutedEventArgs e)
        {
            string mode = (CbAutoMode.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Basic";
            _database.SetSetting("AutomaticScanMode", mode);
            _database.SetSetting("ClamScanPath", TxtClamPath.Text.Trim());
            Close();
        }
    }
}
