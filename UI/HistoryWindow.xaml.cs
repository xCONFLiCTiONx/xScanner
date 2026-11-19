using System.Windows;
using Microsoft.Data.Sqlite;
using xScanner.Database;
using xScanner.Database.Models;
using System.Collections.Generic;
using System;

namespace xScanner.UI
{
    public partial class HistoryWindow : Window
    {
        private readonly ScanDatabase _database;

        public HistoryWindow(ScanDatabase database)
        {
            InitializeComponent();
            _database = database;
            ThemeHelper.ApplyTheme(this);
            LoadHistory();
        }

        private void LoadHistory()
        {
            try
            {
                DgHistory.ItemsSource = _database.GetScanRecords();
            }
            catch
            {
                DgHistory.ItemsSource = new List<ScanRecord>();
            }
        }
    }
}
