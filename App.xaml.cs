using System.Windows;

namespace xScanner
{
    public partial class App : Application
    {
        private void Application_Startup(object sender, StartupEventArgs e)
        {
            bool isScheduled = false;
            foreach (var arg in e.Args)
            {
                if (arg.Equals("/scheduled", System.StringComparison.OrdinalIgnoreCase) ||
                    arg.Equals("-scheduled", System.StringComparison.OrdinalIgnoreCase))
                {
                    isScheduled = true;
                    break;
                }
            }

            if (isScheduled)
            {
                // Run scheduled scan headless/non-interactive and exit when done
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
            try
            {
                // Initialize DB and run scheduled automatic scan (Basic or Full as configured)
                var db = new Database.ScanDatabase();
                var clamManager = new Engines.ClamAV.ClamAvManager(db);
                var orchestrator = new Core.ScanEngine.ScanOrchestrator(db, clamManager);

                // Update definitions first
                await clamManager.UpdateDefinitionsAsync();

                // Get configured automatic scan mode from settings (default to Basic)
                string mode = db.GetSetting("AutomaticScanMode", "Basic");
                if (mode.Equals("Full", System.StringComparison.OrdinalIgnoreCase))
                {
                    var exclusions = db.GetExclusions();
                    await orchestrator.RunFullScanAsync(exclusions, progress => { });
                }
                else
                {
                    await orchestrator.RunBasicScanAsync(progress => { });
                }
            }
            catch (System.Exception ex)
            {
                System.IO.File.WriteAllText("xscanner_error.log", ex.ToString());
            }
            finally
            {
                Shutdown();
            }
        }
    }
}
