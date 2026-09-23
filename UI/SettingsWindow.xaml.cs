using System.Windows;
using System.Windows.Controls;
using xScanner.Database;

namespace xScanner.UI
{
    public partial class SettingsWindow : Window
    {
        private readonly ScanDatabase _database;

        public SettingsWindow(ScanDatabase database)
        {
            InitializeComponent();
            _database = database;
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

            TxtClamPath.Text = _database.GetSetting("ClamScanPath", "");

            RefreshExclusions();
        }

        private void RefreshExclusions()
        {
            LbExclusions.ItemsSource = _database.GetExclusions();
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

        private void BtnSave_Click(object sender, RoutedEventArgs e)
        {
            string mode = (CbAutoMode.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Basic";
            _database.SetSetting("AutomaticScanMode", mode);
            _database.SetSetting("ClamScanPath", TxtClamPath.Text.Trim());
            Close();
        }
    }
}
