using System.Windows;
using xScanner.Database;
using xScanner.Database.Models;
using xScanner.Quarantine;

namespace xScanner.UI
{
    public partial class QuarantineWindow : Window
    {
        private readonly ScanDatabase _database;
        private readonly QuarantineManager _quarantineManager;

        public QuarantineWindow(ScanDatabase database)
        {
            InitializeComponent();
            _database = database;
            _quarantineManager = new QuarantineManager(database);
            ThemeHelper.ApplyTheme(this);
            LoadQuarantine();
        }

        private void LoadQuarantine()
        {
            DgQuarantine.ItemsSource = _database.GetQuarantineRecords();
        }

        private void BtnRestore_Click(object sender, RoutedEventArgs e)
        {
            if (DgQuarantine.SelectedItem is QuarantineRecord record)
            {
                if (_quarantineManager.RestoreFile(record.Id, record.OriginalPath, record.QuarantinePath))
                {
                    System.Media.SystemSounds.Asterisk.Play();
                    LoadQuarantine();
                }
                else
                {
                    MessageBox.Show("Failed to restore file.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void BtnDelete_Click(object sender, RoutedEventArgs e)
        {
            if (DgQuarantine.SelectedItem is QuarantineRecord record)
            {
                if (MessageBox.Show("Are you sure you want to permanently delete this file?", "Confirm Delete", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes)
                {
                    _quarantineManager.DeletePermanently(record.Id, record.QuarantinePath);
                    LoadQuarantine();
                }
            }
        }
    }
}
