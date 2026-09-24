using System;
using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;

namespace xScanner.UI
{
    public static class ThemeHelper
    {
        static ThemeHelper()
        {
            InitializeTheme();
        }

        public static void InitializeTheme()
        {
            if (System.Windows.Application.Current == null) return;
            bool isDark = IsDarkTheme();

            var resources = System.Windows.Application.Current.Resources;

            if (isDark)
            {
                resources["ThemeWindowBackground"] = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(30, 30, 30));   // #1E1E1E
                resources["ThemeCardBackground"] = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(37, 37, 38));    // #252526
                resources["ThemeHeaderBackground"] = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(45, 45, 48));  // #2D2D2D
                resources["ThemeTextColor"] = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 255, 255));        // #FFFFFF
                resources["ThemeSubTextColor"] = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(204, 204, 204));     // #CCCCCC
                resources["ThemeMutedTextColor"] = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(153, 153, 153));   // #999999
                resources["ThemeBorderBrush"] = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(63, 63, 70));       // #3F3F46
                resources["ThemeControlBackground"] = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(51, 51, 56)); // #333338
                resources["ThemeStatusBarBackground"] = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(37, 37, 38));// #252526
            }
            else
            {
                resources["ThemeWindowBackground"] = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(245, 245, 247));
                resources["ThemeCardBackground"] = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 255, 255));
                resources["ThemeHeaderBackground"] = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 255, 255));
                resources["ThemeTextColor"] = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(51, 51, 51));
                resources["ThemeSubTextColor"] = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(85, 85, 85));
                resources["ThemeMutedTextColor"] = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(136, 136, 136));
                resources["ThemeBorderBrush"] = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(221, 221, 221));
                resources["ThemeControlBackground"] = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(239, 239, 239));
                resources["ThemeStatusBarBackground"] = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(234, 234, 234));
            }
        }

        public static bool IsDarkTheme()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
                if (key != null)
                {
                    object? val = key.GetValue("AppsUseLightTheme");
                    if (val is int i && i == 0) return true;
                }
            }
            catch { }
            return false;
        }

        public static void ApplyTheme(Window window)
        {
            InitializeTheme();
            var resources = System.Windows.Application.Current.Resources;
            window.Background = (System.Windows.Media.Brush)resources["ThemeWindowBackground"];
        }
    }
}
