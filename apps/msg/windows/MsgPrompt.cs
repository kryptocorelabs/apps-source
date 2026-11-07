using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace KryptoCore.Desktop;

internal enum PromptChoice { Dismissed, First, Second, Third }

internal sealed class MsgPrompt : Window
{
    private readonly TaskCompletionSource<PromptChoice> result =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    internal Task<PromptChoice> Result => result.Task;

    internal MsgPrompt(Window owner, string title, string detail,
        string first, string second, string third)
    {
        Owner = owner;
        Title = title;
        Width = 520;
        MaxHeight = SystemParameters.WorkArea.Height - 60;
        SizeToContent = SizeToContent.Height;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        ResizeMode = ResizeMode.NoResize;
        WindowStyle = WindowStyle.None;
        AllowsTransparency = true;
        Background = Brushes.Transparent;
        Foreground = (Brush)Application.Current.FindResource("Ink");
        FontFamily = new FontFamily("Segoe UI");
        FontSize = 14;
        Icon = owner.Icon;

        var body = new StackPanel();
        var heading = new TextBlock
        {
            Text = title, FontSize = 22, FontWeight = FontWeights.SemiBold,
            Focusable = true,
            Margin = new Thickness(0, 0, 0, 12), TextWrapping = TextWrapping.Wrap
        };
        heading.MouseLeftButtonDown += (_, args) =>
        {
            if (args.ButtonState == MouseButtonState.Pressed) DragMove();
        };
        body.Children.Add(heading);
        body.Children.Add(new TextBlock
        {
            Text = detail, TextWrapping = TextWrapping.Wrap,
            Foreground = (Brush)Application.Current.FindResource("Muted"),
            Margin = new Thickness(0, 0, 0, 18)
        });
        var actions = new WrapPanel();
        var primary = Choice(first, PromptChoice.First);
        primary.Background = (Brush)Application.Current.FindResource("Mint");
        primary.Foreground = (Brush)Application.Current.FindResource("Base");
        actions.Children.Add(primary);
        actions.Children.Add(Choice(second, PromptChoice.Second));
        var dismiss = Choice(third, PromptChoice.Third);
        actions.Children.Add(dismiss);
        body.Children.Add(actions);
        Content = new Border
        {
            Background = (Brush)Application.Current.FindResource("Card"),
            BorderBrush = (Brush)Application.Current.FindResource("Line"),
            BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(15),
            Padding = new Thickness(24), Child = body
        };
        PreviewKeyDown += (_, args) =>
        {
            if (args.Key == Key.Escape) Close();
        };
        Closed += (_, _) => result.TrySetResult(PromptChoice.Dismissed);
        Loaded += (_, _) => heading.Focus();
    }

    private Button Choice(string label, PromptChoice choice)
    {
        var button = new Button { Content = label, Margin = new Thickness(0, 0, 8, 7) };
        button.Click += (_, _) =>
        {
            result.TrySetResult(choice);
            Close();
        };
        return button;
    }

    internal void Display()
    {
        if (Owner.WindowState == WindowState.Minimized) Owner.WindowState = WindowState.Normal;
        Show();
        Activate();
    }
}
