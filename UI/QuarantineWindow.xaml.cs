using System.Linq;
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
            var selectedRecords = DgQuarantine.SelectedItems.OfType<QuarantineRecord>().ToList();
            if (selectedRecords.Count == 0 && DgQuarantine.SelectedItem is QuarantineRecord single)
            {
                selectedRecords.Add(single);
            }

            if (selectedRecords.Count == 0) return;

            int restoredCount = 0;
            int failedCount = 0;

            foreach (var record in selectedRecords)
            {
                if (_quarantineManager.RestoreFile(record.Id, record.OriginalPath, record.QuarantinePath))
                {
                    restoredCount++;
                }
                else
                {
                    failedCount++;
                }
            }

            if (restoredCount > 0)
            {
                System.Media.SystemSounds.Asterisk.Play();
                LoadQuarantine();
            }

            if (failedCount > 0)
            {
                System.Windows.MessageBox.Show($"Failed to restore {failedCount} file(s).", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void BtnDelete_Click(object sender, RoutedEventArgs e)
        {
            var selectedRecords = DgQuarantine.SelectedItems.OfType<QuarantineRecord>().ToList();
            if (selectedRecords.Count == 0 && DgQuarantine.SelectedItem is QuarantineRecord single)
            {
                selectedRecords.Add(single);
            }

            if (selectedRecords.Count == 0) return;

            foreach (var record in selectedRecords)
            {
                _quarantineManager.DeletePermanently(record.Id, record.QuarantinePath);
            }
            LoadQuarantine();
        }
    }
}
