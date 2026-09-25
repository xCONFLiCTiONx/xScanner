using System;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using xScanner.Core.Hardening;
using xScanner.Database;

namespace xScanner.UI
{
    public partial class HardeningWindow : Window
    {
        private readonly HardeningManager _manager;
        private bool _isBusy = false;

        public HardeningWindow()
        {
            InitializeComponent();
            ThemeHelper.ApplyTheme(this);

            _manager = new HardeningManager();
            _manager.LogProgress += LogTerminal;

            CbDohProvider.ItemsSource = DohProvider.GetPopularProviders();
            CbDohProvider.SelectedIndex = 0;

            Loaded += HardeningWindow_Loaded;
        }

        private async void HardeningWindow_Loaded(object sender, RoutedEventArgs e)
        {
            await RunAuditAsync();
        }

        private async Task RunAuditAsync()
        {
            if (_isBusy) return;
            SetBusyState(true);

            LogTerminal("[UI] Initiating security audit pass...");
            TxtSummaryTitle.Text = "Running System Security Audit...";

            try
            {
                var report = await _manager.RunSecurityAuditAsync();
                UpdateUiFromReport(report);
                CheckAndSendVulnerabilityNotification(report);
            }
            catch (Exception ex)
            {
                LogTerminal($"[ERROR] Security audit failed: {ex.Message}");
                TxtSummaryTitle.Text = "Audit Failed";
            }
            finally
            {
                SetBusyState(false);
            }
        }

        private async void BtnHarden_Click(object sender, RoutedEventArgs e)
        {
            if (_isBusy) return;

            var selectedProvider = CbDohProvider.SelectedItem as DohProvider ?? DohProvider.GetPopularProviders()[0];
            var selectedChecks = IcChecks.ItemsSource as List<HardeningCheckResult>;

            SetBusyState(true);
            TxtSummaryTitle.Text = "Applying Selected Hardening & Lockdown Actions...";

            try
            {
                var report = await _manager.ApplyHardeningAndVerifyAsync(selectedProvider, selectedChecks);
                UpdateUiFromReport(report);

                if (report.IsFullyHardened)
                {
                    LogTerminal("[HARDEN SUCCESS] All selected security controls verified and fully active.");
                }
                else
                {
                    LogTerminal($"[HARDEN NOTICE] Hardening pass completed. Verified {report.PassedChecks} of {report.TotalChecks} controls.");
                    CheckAndSendVulnerabilityNotification(report);
                }
            }
            catch (Exception ex)
            {
                LogTerminal($"[ERROR] Hardening execution failed: {ex.Message}");
                System.Windows.MessageBox.Show($"Hardening error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                SetBusyState(false);
            }
        }

        private async void BtnRefresh_Click(object sender, RoutedEventArgs e)
        {
            await RunAuditAsync();
        }

        private void UpdateUiFromReport(HardeningAuditReport report)
        {
            TxtScore.Text = $"{report.ScorePercentage}%";

            if (report.ScorePercentage >= 100)
            {
                TxtScore.Foreground = new SolidColorBrush(System.Windows.Media.Color.FromRgb(40, 167, 69)); // Green
                TxtScoreStatus.Text = "System Hardened";
                TxtSummaryTitle.Text = "PC Security Hardening Complete";
            }
            else if (report.ScorePercentage >= 50)
            {
                TxtScore.Foreground = new SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 193, 7)); // Yellow
                TxtScoreStatus.Text = "Partially Hardened";
                TxtSummaryTitle.Text = "Weaknesses Detected";
            }
            else
            {
                TxtScore.Foreground = new SolidColorBrush(System.Windows.Media.Color.FromRgb(220, 53, 69)); // Red
                TxtScoreStatus.Text = "Vulnerable";
                TxtSummaryTitle.Text = "Hardening Recommended";
            }

            TxtPassedCount.Text = $"Passed: {report.PassedChecks}/{report.TotalChecks}";
            TxtFailedCount.Text = $"Vulnerable: {report.FailedChecks}/{report.TotalChecks}";

            string dnsStr = report.ActiveDnsServers.Count > 0 ? string.Join(", ", report.ActiveDnsServers) : "None";
            string netStr = report.NetworkProfiles.Count > 0 ? string.Join(", ", report.NetworkProfiles) : "Public";
            string dohUrlStr = report.DohTemplates.Count > 0 ? string.Join(", ", report.DohTemplates) : "None Configured";

            TxtNetworkProfiles.Text = $"Network Profiles : {netStr}";
            TxtActiveDns.Text       = $"Active DNS IPs   : {dnsStr}";
            TxtDohStatus.Text       = $"Encrypted DoH    : {report.DohStatus}";
            TxtDohTemplates.Text    = $"DoH Template URLs: {dohUrlStr}";

            IcChecks.ItemsSource = null;
            IcChecks.ItemsSource = report.CheckResults;

            DgPorts.ItemsSource = null;
            DgPorts.ItemsSource = report.ListeningPorts;
        }

        private void CheckAndSendVulnerabilityNotification(HardeningAuditReport report)
        {
            try
            {
                var db = new ScanDatabase();
                bool allNotifications = bool.Parse(db.GetSetting("EnableAllNotifications", "True"));
                bool hardeningAlerts = bool.Parse(db.GetSetting("EnableHardeningAlerts", "True"));

                if (!allNotifications || !hardeningAlerts) return;

                // Network check: if private network and not open Wi-Fi, it's fine (no alerts)
                if (!_manager.IsPublicOrOpenWifi()) return;

                // Only consider checks selected by the user
                var failedSelectedChecks = report.CheckResults
                    .Where(c => c.IsSelected && c.Status != HardeningStatus.Hardened)
                    .Select(c => c.Name)
                    .ToList();

                if (failedSelectedChecks.Count > 0)
                {
                    string title = "xScanner Security Warning";
                    string message;

                    if (failedSelectedChecks.Count <= 3)
                    {
                        message = "Security weaknesses detected on your system:\n• " + string.Join("\n• ", failedSelectedChecks) + "\n\nClick to review and apply hardening fixes.";
                    }
                    else
                    {
                        message = $"{failedSelectedChecks.Count} security vulnerabilities detected on your computer! Please open xScanner Hardening to apply recommended fixes.";
                    }

                    if (System.Windows.Application.Current.MainWindow is MainWindow mainWin)
                    {
                        mainWin.ShowTrayNotification(title, message, System.Windows.Forms.ToolTipIcon.Warning);
                    }
                }
            }
            catch { }
        }

        private void SetBusyState(bool isBusy)
        {
            _isBusy = isBusy;
            BtnHarden.IsEnabled = !isBusy;
            BtnRefresh.IsEnabled = !isBusy;
            CbDohProvider.IsEnabled = !isBusy;
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
    }
}
