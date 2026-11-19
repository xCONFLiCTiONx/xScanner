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

            var mainWindow = new UI.MainWindow();

            if (isScheduled)
            {
                // Start scheduled scan in tray mode (allows double-clicking / opening window from tray)
                mainWindow.StartScheduledScan();
            }
            else
            {
                // Normal UI startup
                mainWindow.Show();
            }
        }
    }
}
