using System;
using System.Windows;
using xScanner.UI;

namespace xScanner
{
    public partial class App : System.Windows.Application
    {
        private void Application_Startup(object sender, StartupEventArgs e)
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            ThemeHelper.InitializeTheme();

            bool isScheduled = false;
            foreach (var arg in e.Args)
            {
                if (arg.Equals("/scheduled", StringComparison.OrdinalIgnoreCase) ||
                    arg.Equals("-scheduled", StringComparison.OrdinalIgnoreCase))
                {
                    isScheduled = true;
                    break;
                }
            }

            if (isScheduled)
            {
                // Run scheduled scan with tray notification and auto-close when done
                RunScheduledScanAsync();
            }
            else
            {
                // Normal UI startup
                var mainWindow = new UI.MainWindow();
                mainWindow.Show();
            }
        }

        private async void RunScheduledScanAsync()
        {
            SystemTrayManager? trayManager = null;
            try
            {
                var db = new Database.ScanDatabase();

                string mode = db.GetSetting("AutomaticScanMode", "Basic");
                if (mode.Equals("Disabled", StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }

                trayManager = new SystemTrayManager(
                    onOpenRequested: null,
                    onExitRequested: () => System.Windows.Application.Current.Shutdown()
                );
                trayManager.ShowNotification("xScanner Scheduled Scan", "Scheduled background scan has started.", System.Windows.Forms.ToolTipIcon.Info);
                trayManager.UpdateStatus("Scheduled Scan Running...");

                var clamManager = new Engines.ClamAV.ClamAvManager(db);
                var orchestrator = new Core.ScanEngine.ScanOrchestrator(db, clamManager);

                // Update definitions first
                await clamManager.UpdateDefinitionsAsync();

                long threatsDetected = 0;
                if (mode.Equals("Full", StringComparison.OrdinalIgnoreCase))
                {
                    var exclusions = db.GetExclusions();
                    await orchestrator.RunFullScanAsync(exclusions, progress =>
                    {
                        if (progress.IsCompleted)
                        {
                            threatsDetected = progress.ThreatsDetected;
                        }
                    });
                }
                else
                {
                    await orchestrator.RunBasicScanAsync(progress =>
                    {
                        if (progress.IsCompleted)
                        {
                            threatsDetected = progress.ThreatsDetected;
                        }
                    });
                }

                string resultText = threatsDetected > 0
                    ? $"Scheduled scan complete. WARNING: {threatsDetected} threat(s) detected!"
                    : "Scheduled scan complete. No threats detected.";

                trayManager.ShowNotification(
                    "xScanner Scheduled Scan",
                    resultText,
                    threatsDetected > 0 ? System.Windows.Forms.ToolTipIcon.Warning : System.Windows.Forms.ToolTipIcon.Info
                );

                await System.Threading.Tasks.Task.Delay(2500);
            }
            catch (Exception ex)
            {
                try
                {
                    System.IO.File.WriteAllText("xscanner_error.log", ex.ToString());
                }
                catch { }
            }
            finally
            {
                trayManager?.Dispose();
                System.Windows.Application.Current.Shutdown();
                Environment.Exit(0);
            }
        }
    }
}
