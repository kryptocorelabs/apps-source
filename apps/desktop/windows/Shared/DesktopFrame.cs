using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Shell;

namespace KryptoCore.Desktop;

/// <summary>Common window chrome and navigation for the Windows applications.</summary>
internal static class DesktopFrame
{
    internal static string Glyph(string name) => name switch
    {
        "Start" => "\uE80F", "Verschlüsseln" => "\uE72E", "Öffnen" => "\uE8E5",
        "Signaturen" => "\uE73E", "Erweitert" or "Einstellungen" => "\uE713",
        "Nachrichten" => "\uE8F2", "Kontakte" => "\uE716", "Mein Profil" => "\uE77B",
        "Dateiprüfung" => "\uE9F9", "Konzept" => "\uE946", _ => "\uE8A5"
    };

    internal static FrameworkElement Create(Window window, string product, StackPanel navigation,
        ScrollViewer page, FrameworkElement status)
    {
        window.WindowStyle = WindowStyle.None;
        window.ResizeMode = ResizeMode.CanResize;
        WindowChrome.SetWindowChrome(window, new WindowChrome
        {
            CaptionHeight = 40, ResizeBorderThickness = new Thickness(6),
            GlassFrameThickness = new Thickness(0), CornerRadius = new CornerRadius(16), UseAeroCaptionButtons = false
        });
        var frame = new Grid();
        frame.RowDefinitions.Add(new RowDefinition { Height = new GridLength(40) });
        frame.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        var caption = new DockPanel { LastChildFill = true, Margin = new Thickness(14, 0, 6, 0) };
        var controls = new StackPanel { Orientation = Orientation.Horizontal };
        controls.Children.Add(CaptionButton("—", "Fenster minimieren", () => SystemCommands.MinimizeWindow(window)));
        var maximize = CaptionButton("□", "Fenster maximieren", () =>
        {
            if (window.WindowState == WindowState.Maximized) SystemCommands.RestoreWindow(window);
            else SystemCommands.MaximizeWindow(window);
        });
        controls.Children.Add(maximize);
        controls.Children.Add(CaptionButton("×", "Fenster schließen", window.Close));
        window.StateChanged += (_, _) =>
        {
            maximize.Content = window.WindowState == WindowState.Maximized ? "❐" : "□";
            AutomationProperties.SetName(maximize, window.WindowState == WindowState.Maximized ? "Fenster wiederherstellen" : "Fenster maximieren");
        };
        DockPanel.SetDock(controls, Dock.Right);
        caption.Children.Add(controls);
        caption.Children.Add(new TextBlock
        {
            Text = "KRYPTOCORE  /  " + product.ToUpperInvariant(), Foreground = Brush("Muted"), FontSize = 10,
            VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(5, 0, 0, 0)
        });
        frame.Children.Add(caption);
        var body = new Grid();
        body.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(112) });
        body.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        Grid.SetRow(body, 1); frame.Children.Add(body);
        var rail = new DockPanel { Margin = new Thickness(9, 10, 9, 14) };
        FrameworkElement mark = window.Icon is not null
            ? new Image { Source = window.Icon, Width = 46, Height = 46 }
            : new TextBlock { Text = "K", FontSize = 25, Foreground = Brush("Mint"),
                HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
        var emblem = new Border
        {
            Width = 46, Height = 46, CornerRadius = new CornerRadius(13), Child = mark,
            Margin = new Thickness(0, 5, 0, 24), HorizontalAlignment = HorizontalAlignment.Center
        };
        AutomationProperties.SetName(emblem, "KryptoCore " + product);
        DockPanel.SetDock(emblem, Dock.Top); rail.Children.Add(emblem);
        var brand = new TextBlock
        {
            Text = "LABS\nPC PREVIEW", TextAlignment = TextAlignment.Center, FontSize = 9,
            Foreground = Brush("Muted"), LineHeight = 17, Margin = new Thickness(0, 10, 0, 0)
        };
        DockPanel.SetDock(brand, Dock.Bottom); rail.Children.Add(brand);
        navigation.Orientation = Orientation.Vertical;
        navigation.Margin = new Thickness(0);
        foreach (var button in navigation.Children.OfType<Button>()) StyleNavigation(button);
        var navigationScroll = new ScrollViewer
        {
            Content = navigation, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled
        };
        rail.Children.Add(navigationScroll);
        body.Children.Add(new Border { Background = Brush("Rail"), CornerRadius = new CornerRadius(0, 20, 0, 0), Child = rail });
        var main = new DockPanel { Margin = new Thickness(16, 8, 20, 14), LastChildFill = true };
        Grid.SetColumn(main, 1);
        status.Margin = new Thickness(6, 8, 0, 0);
        DockPanel.SetDock(status, Dock.Bottom); main.Children.Add(status);
        page.HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled;
        main.Children.Add(page); body.Children.Add(main);
        var surface = new Border
        {
            Background = Brush("Base"), BorderBrush = Brush("Line"), BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(16), Child = frame
        };
        // Only the background receives Mica; content stays fully opaque.
        // Unsupported Windows versions, high contrast and disabled effects use the solid palette.
        window.SourceInitialized += (_, _) => TryBackdrop(window, surface);
        return surface;
    }

    internal static void StyleNavigation(Button button)
    {
        string name = button.Content?.ToString() ?? "";
        button.Uid = Glyph(name);
        button.Style = (Style)Application.Current.FindResource("AppNavigation");
        button.Margin = new Thickness(0, 0, 0, 9);
        button.ToolTip = name;
        AutomationProperties.SetName(button, name);
    }

    private static Button CaptionButton(string symbol, string name, Action action)
    {
        var button = new Button { Content = symbol,
            Style = (Style)Application.Current.FindResource("AppCaption"), ToolTip = name };
        AutomationProperties.SetName(button, name);
        WindowChrome.SetIsHitTestVisibleInChrome(button, true);
        button.Click += (_, _) => action(); return button;
    }

    private static void TryBackdrop(Window window, Border surface)
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22621) || SystemParameters.HighContrast
            || !SystemParameters.ClientAreaAnimation) return;
        if (PresentationSource.FromVisual(window) is not HwndSource source || source.CompositionTarget is null) return;
        int dark = 1, backdrop = 2;
        var margins = new FrameMargins { Left = -1, Right = -1, Top = -1, Bottom = -1 };
        _ = DwmSetWindowAttribute(source.Handle, 20, ref dark, sizeof(int));
        if (DwmSetWindowAttribute(source.Handle, 38, ref backdrop, sizeof(int)) != 0
            || DwmExtendFrameIntoClientArea(source.Handle, ref margins) != 0) return;
        source.CompositionTarget.BackgroundColor = Colors.Transparent;
        window.Background = Brushes.Transparent;
        surface.Background = new SolidColorBrush(Color.FromArgb(238, 16, 25, 35));
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FrameMargins { public int Left, Right, Top, Bottom; }
    [DllImport("dwmapi.dll", ExactSpelling = true)]
    private static extern int DwmSetWindowAttribute(IntPtr window, int attribute, ref int value, int size);
    [DllImport("dwmapi.dll", ExactSpelling = true)]
    private static extern int DwmExtendFrameIntoClientArea(IntPtr window, ref FrameMargins margins);
    private static Brush Brush(string key) => (Brush)Application.Current.FindResource(key);
}
