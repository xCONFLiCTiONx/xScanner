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

            var result = System.Windows.MessageBox.Show(
                $"Hardening will enforce Encrypted DNS (DoH) using {selectedProvider.Name} for IPv4 & IPv6 with no plaintext fallback, enable Public Firewall, stop/disable file sharing (LanmanServer) and casting services (SSDP/uPnP), block inbound Remote Desktop, disable Advertising ID tracking, restrict telemetry, block global webcam access, and shield TCP ports 135 & 445.\n\nDo you wish to apply these hardening measures now?",
                "Confirm System Hardening",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning
            );

            if (result != MessageBoxResult.Yes) return;

            SetBusyState(true);
            TxtSummaryTitle.Text = "Applying Hardening & Lockdown Actions...";

            try
            {
                var report = await _manager.ApplyHardeningAndVerifyAsync(selectedProvider);
                UpdateUiFromReport(report);

                if (report.IsFullyHardened)
                {
                    System.Windows.MessageBox.Show(
                        "System Hardening complete! All security controls were verified and are fully active.",
                        "Hardening Success",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information
                    );
                }
                else
                {
                    System.Windows.MessageBox.Show(
                        $"Hardening pass completed. Verified {report.PassedChecks} of {report.TotalChecks} controls. Check terminal log for details.",
                        "Hardening Status",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning
                    );
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

                if (report.FailedChecks > 0)
                {
                    var failedChecks = report.CheckResults
                        .Where(c => c.Status != HardeningStatus.Hardened)
                        .Select(c => c.Name)
                        .ToList();

                    string title = "xScanner Security Warning";
                    string message;

                    if (failedChecks.Count <= 3)
                    {
                        message = "Security weaknesses detected on your system:\n• " + string.Join("\n• ", failedChecks) + "\n\nClick to review and apply hardening fixes.";
                    }
                    else
                    {
                        message = $"{report.FailedChecks} security vulnerabilities detected on your computer! Please open xScanner Hardening to apply recommended fixes.";
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
