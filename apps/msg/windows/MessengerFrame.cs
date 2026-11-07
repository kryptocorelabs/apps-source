using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shell;

namespace KryptoCore.Desktop;

internal static class MessengerFrame
{
    internal static void ApplyTheme()
    {
        var source = new Uri("/KryptoCore-MSG;component/MessengerTheme.xaml", UriKind.Relative);
        var dictionaries = Application.Current.Resources.MergedDictionaries;
        if (!dictionaries.Any(dictionary => dictionary.Source == source))
            dictionaries.Add(new ResourceDictionary { Source = source });
    }

    internal static FrameworkElement Create(Window window, StackPanel navigation, ScrollViewer page, FrameworkElement status)
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
            Text = "KRYPTOCORE  /  MESSENGER", Foreground = Brush("Muted"), FontSize = 10,
            VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(5, 0, 0, 0)
        });
        frame.Children.Add(caption);
        var body = new Grid();
        body.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(96) });
        body.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        Grid.SetRow(body, 1);
        frame.Children.Add(body);

        var rail = new DockPanel { Margin = new Thickness(9, 10, 9, 14) };
        var emblem = new Border
        {
            Width = 46, Height = 46, CornerRadius = new CornerRadius(13),
            Background = new ImageBrush(window.Icon) { Stretch = Stretch.Uniform },
            Margin = new Thickness(0, 5, 0, 24), HorizontalAlignment = HorizontalAlignment.Center
        };
        DockPanel.SetDock(emblem, Dock.Top);
        rail.Children.Add(emblem);
        var brand = new TextBlock
        {
            Text = "LABS\nPC PREVIEW", TextAlignment = TextAlignment.Center, FontSize = 9,
            Foreground = Brush("Muted"), LineHeight = 17, Margin = new Thickness(0, 10, 0, 0)
        };
        DockPanel.SetDock(brand, Dock.Bottom);
        rail.Children.Add(brand);
        navigation.Orientation = Orientation.Vertical;
        navigation.Margin = new Thickness(0);
        foreach (var button in navigation.Children.OfType<Button>())
        {
            button.Style = (Style)Application.Current.FindResource("MessengerNavigation");
            button.Margin = new Thickness(0, 0, 0, 9);
            button.ToolTip = button.Content;
        }
        rail.Children.Add(navigation);
        body.Children.Add(new Border { Background = Brush("Rail"), CornerRadius = new CornerRadius(0, 20, 0, 0), Child = rail });
        var main = new DockPanel { Margin = new Thickness(16, 8, 20, 14), LastChildFill = true };
        Grid.SetColumn(main, 1);
        status.Margin = new Thickness(6, 8, 0, 0);
        DockPanel.SetDock(status, Dock.Bottom);
        main.Children.Add(status);
        main.Children.Add(page);
        body.Children.Add(main);
        return new Border
        {
            Background = Brush("Base"), BorderBrush = Brush("Line"), BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(16), Child = frame
        };
    }

    private static Button CaptionButton(string symbol, string name, Action action)
    {
        var button = new Button
        {
            Content = symbol, Style = (Style)Application.Current.FindResource("MessengerCaption"),
            ToolTip = name
        };
        AutomationProperties.SetName(button, name);
        WindowChrome.SetIsHitTestVisibleInChrome(button, true);
        button.Click += (_, _) => action();
        return button;
    }

    internal static Border Avatar(string name, double size = 40)
    {
        string initial = string.IsNullOrWhiteSpace(name) ? "?" : System.Globalization.StringInfo.GetNextTextElement(name.Trim()).ToUpperInvariant();
        return new Border
        {
            Width = size, Height = size, CornerRadius = new CornerRadius(size / 2),
            Background = Brush("SelectedCard"), Child = new TextBlock
            {
                Text = initial, Foreground = Brush("Mint"), FontSize = size * .38, FontWeight = FontWeights.SemiBold,
                HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center
            }
        };
    }

    private static Brush Brush(string key) => (Brush)Application.Current.FindResource(key);
}
