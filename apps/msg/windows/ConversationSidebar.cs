using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;

namespace KryptoCore.Desktop;

internal sealed class ConversationSidebar : Border
{
    internal sealed record Item(string Key, string Name, string Detail, bool Active, string State);
    private readonly TextBox search = new() { MaxLength = 120 };
    private readonly StackPanel entries = new();
    private readonly TextBlock hint = new() { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 0) };
    private readonly TextBlock reachability = new() { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 8) };
    private readonly Func<string, Task> select;
    private readonly Button shareButton;
    private Item[] items = [];
    private bool selecting;

    internal ConversationSidebar(Func<string, Task> select, Action add, Action share)
    {
        this.select = select;
        Background = Brush("Card");
        BorderBrush = Brush("Line");
        BorderThickness = new Thickness(1);
        CornerRadius = new CornerRadius(24);
        Padding = new Thickness(14, 19, 14, 14);
        Margin = new Thickness(0, 0, 12, 0);
        AutomationProperties.SetName(this, "Chatübersicht");
        var panel = new DockPanel();
        var header = new StackPanel();
        header.Children.Add(new TextBlock { Text = "Chats", FontSize = 24, FontWeight = FontWeights.SemiBold, Margin = new Thickness(3, 0, 0, 5) });
        AutomationProperties.SetName(search, "Chats durchsuchen");
        search.ToolTip = "Nach Kontaktnamen suchen";
        var searchArea = new Grid { Margin = new Thickness(0, 8, 0, 12) };
        searchArea.Children.Add(search);
        var searchHint = new TextBlock
        {
            Text = "Chats durchsuchen", Foreground = Brush("Muted"), FontSize = 12,
            VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(10, 0, 0, 0), IsHitTestVisible = false
        };
        searchArea.Children.Add(searchHint);
        header.Children.Add(searchArea);
        var actions = new WrapPanel();
        actions.Children.Add(Action("Neuer Kontakt", add));
        shareButton = Action("Meine Adresse", share);
        shareButton.ToolTip = "Kopiert deine Tor-Adresse und erlaubt Kontaktanfragen für diese Sitzung";
        actions.Children.Add(shareButton);
        header.Children.Add(actions);
        reachability.FontSize = 12;
        header.Children.Add(reachability);
        DockPanel.SetDock(header, Dock.Top);
        panel.Children.Add(header);
        var footer = new TextBlock
        {
            Text = "Sitzungsverlauf · Beim Sperren verwerfen",
            Foreground = Brush("Muted"), FontSize = 11, TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 12, 0, 0)
        };
        DockPanel.SetDock(footer, Dock.Bottom);
        panel.Children.Add(footer);
        var list = new StackPanel();
        list.Children.Add(entries);
        hint.Foreground = Brush("Muted"); hint.FontSize = 13;
        list.Children.Add(hint);
        panel.Children.Add(new ScrollViewer { Content = list, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });
        Child = panel;
        search.TextChanged += (_, _) =>
        {
            searchHint.Visibility = search.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
            Render();
        };
    }

    internal void Update(Item[] next, bool reachable, bool canShare)
    {
        shareButton.IsEnabled = canShare;
        reachability.Text = reachable ? "● Für Anfragen erreichbar" : "Neue Anfragen sind ausgeschaltet";
        reachability.Foreground = Brush(reachable ? "Mint" : "Muted");
        if (items.SequenceEqual(next)) return;
        items = next;
        Render();
    }

    internal void Reset()
    {
        items = [];
        search.Clear();
        search.ClearUndo();
        Render();
    }

    private void Render()
    {
        entries.Children.Clear();
        string query = search.Text.Trim();
        var filtered = items.Where(item => item.Name.Contains(query, StringComparison.OrdinalIgnoreCase)).ToArray();
        hint.Text = items.Length == 0 ? "Füge einen Kontakt hinzu oder teile deine Adresse. Angenommene Kontakte erscheinen hier."
            : filtered.Length == 0 ? "Kein passender Kontakt." : "";
        foreach (var item in filtered)
        {
            var content = new StackPanel();
            content.Children.Add(new TextBlock { Text = item.Name, FontSize = 14, FontWeight = FontWeights.SemiBold, TextTrimming = TextTrimming.CharacterEllipsis, TextWrapping = TextWrapping.NoWrap });
            content.Children.Add(new TextBlock { Text = item.Detail, FontSize = 12, Foreground = Brush("Muted"), TextTrimming = TextTrimming.CharacterEllipsis, TextWrapping = TextWrapping.NoWrap, Margin = new Thickness(0, 4, 0, 0) });
            if (item.Active) content.Children.Add(new TextBlock { Text = item.State, FontSize = 10, Foreground = Brush("Mint"), Margin = new Thickness(0, 5, 0, 0), TextTrimming = TextTrimming.CharacterEllipsis, TextWrapping = TextWrapping.NoWrap });
            var row = new Grid();
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            var avatar = MessengerFrame.Avatar(item.Name, 38);
            avatar.Background = Brush("Field");
            avatar.Margin = new Thickness(0, 0, 10, 0);
            avatar.VerticalAlignment = VerticalAlignment.Center;
            row.Children.Add(avatar);
            Grid.SetColumn(content, 1);
            row.Children.Add(content);
            var button = new Button
            {
                Content = row, ContentTemplate = null, HorizontalContentAlignment = HorizontalAlignment.Stretch,
                Background = item.Active ? Brush("SelectedCard") : Brushes.Transparent,
                BorderBrush = item.Active ? new SolidColorBrush(Color.FromRgb(82, 127, 120)) : Brushes.Transparent,
                Padding = new Thickness(10, 12, 10, 12), Margin = new Thickness(0, 0, 0, 7),
                ToolTip = item.Name
            };
            AutomationProperties.SetName(button, $"Chat mit {item.Name}");
            button.Click += async (_, _) =>
            {
                if (selecting) return;
                selecting = true;
                IsEnabled = false;
                try { await select(item.Key); }
                finally { selecting = false; IsEnabled = true; }
            };
            entries.Children.Add(button);
        }
    }

    private static Button Action(string text, Action action)
    {
        var button = new Button { Content = text, Padding = new Thickness(9, 6, 9, 6), FontSize = 12, Margin = new Thickness(0, 0, 6, 6) };
        button.Click += (_, _) => action();
        return button;
    }

    private static Brush Brush(string key) => (Brush)Application.Current.FindResource(key);
}
