using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

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
