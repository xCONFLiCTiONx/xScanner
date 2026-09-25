using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using xScanner.Core.Hardening;

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

            var result = System.Windows.MessageBox.Show(
                "Hardening will enable Public Firewall profile, stop/disable file sharing (LanmanServer) and casting services (SSDP/uPnP), block inbound Remote Desktop, disable Advertising ID tracking, restrict telemetry, block global webcam access, and shield TCP ports 135 & 445.\n\nDo you wish to apply these hardening measures now?",
                "Confirm System Hardening",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning
            );

            if (result != MessageBoxResult.Yes) return;

            SetBusyState(true);
            TxtSummaryTitle.Text = "Applying Hardening & Lockdown Actions...";

            try
            {
                var report = await _manager.ApplyHardeningAndVerifyAsync();
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
            string dohStr = report.DohTemplates.Count > 0 ? string.Join(", ", report.DohTemplates) : "None";
            TxtNetworkDnsInfo.Text = $"Profiles: {netStr} | Active DNS: {dnsStr} | DoH ({report.DohStatus}): {dohStr}";

            IcChecks.ItemsSource = null;
            IcChecks.ItemsSource = report.CheckResults;

            DgPorts.ItemsSource = null;
            DgPorts.ItemsSource = report.ListeningPorts;
        }

        private void SetBusyState(bool isBusy)
        {
            _isBusy = isBusy;
            BtnHarden.IsEnabled = !isBusy;
            BtnRefresh.IsEnabled = !isBusy;
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
