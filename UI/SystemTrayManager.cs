using System;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Windows.Forms;

namespace xScanner.UI
{
    public class SystemTrayManager : IDisposable
    {
        private NotifyIcon? _notifyIcon;
        private readonly Action? _onOpenRequested;
        private readonly Action? _onExitRequested;

        public SystemTrayManager(Action? onOpenRequested, Action? onExitRequested)
        {
            _onOpenRequested = onOpenRequested;
            _onExitRequested = onExitRequested;
            InitializeTrayIcon();
        }

        private void InitializeTrayIcon()
        {
            _notifyIcon = new NotifyIcon
            {
                Text = "xScanner - Anti-Malware Protection",
                Visible = true
            };

            // Attempt to load application icon
            try
            {
                string exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName ?? "";
                if (!string.IsNullOrEmpty(exePath) && File.Exists(exePath))
                {
                    _notifyIcon.Icon = Icon.ExtractAssociatedIcon(exePath);
                }
            }
            catch { }

            if (_notifyIcon.Icon == null)
            {
                try
                {
                    var assembly = Assembly.GetExecutingAssembly();
                    using var stream = assembly.GetManifestResourceStream("xScanner.icon.ico");
                    if (stream != null)
                    {
                        _notifyIcon.Icon = new Icon(stream);
                    }
                }
                catch { }
            }

            if (_notifyIcon.Icon == null)
            {
                _notifyIcon.Icon = SystemIcons.Shield;
            }

            // Create Context Menu with Open and Exit options
            var contextMenu = new ContextMenuStrip();

            var openMenuItem = new ToolStripMenuItem("Open")
            {
                Font = new Font(contextMenu.Font, FontStyle.Bold)
            };
            openMenuItem.Click += (s, e) => _onOpenRequested?.Invoke();

            var exitMenuItem = new ToolStripMenuItem("Exit");
            exitMenuItem.Click += (s, e) => _onExitRequested?.Invoke();

            contextMenu.Items.Add(openMenuItem);
            contextMenu.Items.Add(new ToolStripSeparator());
            contextMenu.Items.Add(exitMenuItem);

            _notifyIcon.ContextMenuStrip = contextMenu;
            _notifyIcon.DoubleClick += (s, e) => _onOpenRequested?.Invoke();
        }

        public void UpdateStatus(string statusText)
        {
            if (_notifyIcon != null)
            {
                string text = $"xScanner - {statusText}";
                if (text.Length > 63) text = text.Substring(0, 60) + "...";
                _notifyIcon.Text = text;
            }
        }

        public void ShowNotification(string title, string message, ToolTipIcon icon = ToolTipIcon.Info)
        {
            if (_notifyIcon != null && _notifyIcon.Visible)
            {
                _notifyIcon.ShowBalloonTip(3000, title, message, icon);
            }
        }

        public void Dispose()
        {
            if (_notifyIcon != null)
            {
                _notifyIcon.Visible = false;
                _notifyIcon.ContextMenuStrip?.Dispose();
                _notifyIcon.Dispose();
                _notifyIcon = null;
            }
        }
    }
}
