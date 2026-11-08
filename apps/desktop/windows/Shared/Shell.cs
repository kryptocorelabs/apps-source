using System.IO;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Microsoft.Win32;

namespace KryptoCore.Desktop;

internal abstract class Shell : Window
{
    private readonly StackPanel navigation = new() { Orientation = Orientation.Horizontal };
    private readonly ScrollViewer scroll = new() { VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
    private readonly TextBlock status = new();
    private readonly ProgressBar progress = new() { Width = 52, Height = 4, IsIndeterminate = true };
    private readonly Button cancel;
    private readonly List<Button> tabs = [];
    private readonly DockPanel footer;
    private CancellationTokenSource? cancellation;
    private bool busy;

    protected Shell(string product, string description, Brush? emblemArtwork = null, string? iconResource = null)
    {
        Title = $"KryptoCore {product}";
        if (iconResource is not null)
            Icon = BitmapFrame.Create(new Uri($"pack://application:,,,/{iconResource}"));
        Width = 960;
        Height = 770;
        MinWidth = 700;
        MinHeight = 555;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        FontFamily = new FontFamily("Segoe UI");
        FontSize = 14;
        Background = Brush("Base");
        Foreground = Brush("Ink");
        UseLayoutRounding = true;

        footer = new DockPanel { LastChildFill = true, Margin = new Thickness(0, 10, 0, 0) };
        cancel = Button("Abbrechen", () => cancellation?.Cancel());
        cancel.Visibility = Visibility.Collapsed;
        DockPanel.SetDock(cancel, Dock.Right);
        footer.Children.Add(cancel);
        progress.Visibility = Visibility.Collapsed;
        progress.Foreground = Brush("Mint");
        progress.Margin = new Thickness(0, 0, 10, 0);
        footer.Children.Add(progress);
        status.Margin = new Thickness(0, 6, 8, 6);
        status.VerticalAlignment = VerticalAlignment.Center;
        AutomationProperties.SetLiveSetting(status, AutomationLiveSetting.Polite);
        footer.Children.Add(status);
        SetStatus("Bereit · Windows-Vorschau");

        Content = DesktopFrame.Create(this, product == "MSG" ? "Messenger" : product, navigation, scroll, footer);
        Closing += (_, args) =>
        {
            if (busy)
            {
                args.Cancel = true;
                SetStatus(cancellation is null
                    ? "Warte, bis der laufende Vorgang abgeschlossen ist."
                    : "Brich den Vorgang ab oder warte auf den Abschluss.");
            }
        };
    }

    protected Action Tab(string name, FrameworkElement content, Action? onSelect = null)
    {
        void Show(Button selected)
        {
            scroll.Content = content;
            scroll.ScrollToTop();
            foreach (Button tab in tabs)
            {
                tab.Tag = tab == selected ? "selected" : "";
            }
            onSelect?.Invoke();
        }

        var button = new Button { Content = name };
        DesktopFrame.StyleNavigation(button);
        button.Click += (_, _) => Show(button);
        tabs.Add(button);
        navigation.Children.Add(button);
        if (tabs.Count == 1) Show(button);
        return () => Show(button);
    }

    protected void SetLayout(Func<StackPanel, ScrollViewer, FrameworkElement, FrameworkElement> compose)
    {
        if (Content is Panel previous) previous.Children.Clear();
        Content = compose(navigation, scroll, footer);
    }

    protected async Task<bool> Run(string waiting, Func<CancellationToken, Task<Reply>> operation,
        Action<Reply>? success = null, bool canCancel = false)
    {
        if (busy) return false;
        busy = true;
        scroll.IsEnabled = false;
        navigation.IsEnabled = false;
        progress.Visibility = Visibility.Visible;
        cancellation = canCancel ? new CancellationTokenSource() : null;
        cancel.Visibility = canCancel ? Visibility.Visible : Visibility.Collapsed;
        SetStatus(waiting);
        try
        {
            var reply = await operation(cancellation?.Token ?? CancellationToken.None);
            SetStatus(reply.Message, !reply.Ok);
            if (reply.Ok) success?.Invoke(reply);
            return reply.Ok;
        }
        catch (OperationCanceledException)
        {
            SetStatus("Vorgang abgebrochen.");
            return false;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException
            or System.ComponentModel.Win32Exception or System.Text.Json.JsonException)
        {
            SetStatus(error is System.Text.Json.JsonException
                ? "Die Antwort der Rust-Engine war ungültig."
                : error.Message, true);
            return false;
        }
        finally
        {
            cancellation?.Dispose();
            cancellation = null;
            cancel.Visibility = Visibility.Collapsed;
            progress.Visibility = Visibility.Collapsed;
            scroll.IsEnabled = true;
            navigation.IsEnabled = true;
            busy = false;
        }
    }

    protected void SetStatus(string message, bool error = false)
    {
        status.Text = message;
        status.Foreground = Brush(error ? "Problem" : "Mint");
    }

    protected static Brush Brush(string key) => (Brush)Application.Current.FindResource(key);
    protected static ImageBrush ProductEmblem(string resource)
    {
        var source = new BitmapImage();
        source.BeginInit();
        source.UriSource = new Uri($"pack://application:,,,/{resource}");
        source.DecodePixelWidth = 192;
        source.CacheOption = BitmapCacheOption.OnLoad;
        source.EndInit();
        return new ImageBrush(source)
        {
            Viewbox = new Rect(0.185, 0.035, 0.625, 0.625),
            Stretch = Stretch.Uniform
        };
    }

    protected static TextBlock Text(string value, double size = 14, bool muted = false) =>
        new() { Text = value, FontSize = size, Foreground = Brush(muted ? "Muted" : "Ink") };

    protected static Button Button(string label, Action action, bool primary = false)
    {
        var button = new Button { Content = label };
        if (primary)
        {
            button.Background = Brush("Mint");
            button.Foreground = Brush("Base");
            button.FontWeight = FontWeights.SemiBold;
        }
        button.Click += (_, _) => action();
        return button;
    }

    protected static WrapPanel Row(params UIElement[] children)
    {
        var row = new WrapPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 6, 0, 2) };
        foreach (UIElement element in children)
        {
            if (element is FrameworkElement control) control.Margin = new Thickness(0, 0, 8, 6);
            row.Children.Add(element);
        }
        return row;
    }

    protected static StackPanel Section(string title, string detail)
    {
        var content = new StackPanel();
        var heading = Text(title, 19);
        heading.FontWeight = FontWeights.SemiBold;
        content.Children.Add(heading);
        var note = Text(detail, 13, true);
        note.Margin = new Thickness(0, 3, 0, 10);
        content.Children.Add(note);
        return content;
    }

    protected static Border Card(FrameworkElement content) => new()
    {
        Background = Brush("Card"), BorderBrush = Brush("Line"), BorderThickness = new Thickness(1),
        CornerRadius = new CornerRadius(22), Padding = new Thickness(20),
        Margin = new Thickness(0, 0, 0, 16), Child = content
    };

    protected static Grid Columns(FrameworkElement left, FrameworkElement right)
    {
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition());
        grid.ColumnDefinitions.Add(new ColumnDefinition());
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        left.VerticalAlignment = right.VerticalAlignment = VerticalAlignment.Top;
        grid.Children.Add(left); grid.Children.Add(right);
        void ArrangeColumns()
        {
            bool stacked = grid.ActualWidth < 660;
            Grid.SetRow(right, stacked ? 1 : 0);
            Grid.SetColumn(right, stacked ? 0 : 1);
            Grid.SetColumnSpan(left, stacked ? 2 : 1);
            Grid.SetColumnSpan(right, stacked ? 2 : 1);
            left.Margin = new Thickness(0, 0, stacked ? 0 : 8, 16);
            right.Margin = new Thickness(stacked ? 0 : 8, 0, 0, 16);
        }
        grid.SizeChanged += (_, _) => ArrangeColumns();
        ArrangeColumns();
        return grid;
    }

    protected static T Field<T>(Panel panel, string label, T input, Action? browse = null) where T : Control
    {
        var caption = Text(label, 13);
        caption.Margin = new Thickness(0, 7, 0, 5);
        panel.Children.Add(caption);
        AutomationProperties.SetName(input, label);
        if (browse is null)
        {
            panel.Children.Add(input);
            return input;
        }
        var row = new DockPanel();
        var button = Button("Auswählen…", browse);
        AutomationProperties.SetName(button, label + " auswählen");
        button.Margin = new Thickness(7, 0, 0, 0);
        DockPanel.SetDock(button, Dock.Right);
        row.Children.Add(button);
        row.Children.Add(input);
        panel.Children.Add(row);
        return input;
    }

    protected TextBox PathField(Panel panel, string label, string filter, string? saveExtension = null)
    {
        var input = new TextBox();
        return Field(panel, label, input, () =>
        {
            FileDialog dialog = saveExtension is null
                ? new OpenFileDialog { CheckFileExists = true }
                : new SaveFileDialog { AddExtension = true, DefaultExt = saveExtension, OverwritePrompt = true };
            dialog.Filter = filter;
            if (dialog.ShowDialog(this) == true) input.Text = dialog.FileName;
        });
    }

    protected static string FullPath(TextBox input)
    {
        string value = input.Text.Trim();
        if (!Path.IsPathFullyQualified(value))
        {
            string name = AutomationProperties.GetName(input);
            throw new ArgumentException($"Wähle für „{name}“ einen vollständigen Pfad.");
        }
        return Path.GetFullPath(value);
    }

    protected static string Required(TextBox input)
    {
        string value = input.Text.Trim();
        if (value.Length == 0)
            throw new ArgumentException($"Fülle „{AutomationProperties.GetName(input)}“ aus.");
        return value;
    }
}
