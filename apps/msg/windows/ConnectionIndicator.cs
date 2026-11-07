using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Effects;
using System.Windows.Shapes;

namespace KryptoCore.Desktop;

internal enum ChannelSecurity { Disconnected, Connecting, Encrypted, Failed }

internal sealed class ConnectionIndicator : Border
{
    private readonly Ellipse light = new() { Width = 7, Height = 7, Margin = new Thickness(0, 0, 7, 0), VerticalAlignment = VerticalAlignment.Center };
    private readonly TextBlock label = new() { FontSize = 11, VerticalAlignment = VerticalAlignment.Center };
    private bool initialized;
    internal ChannelSecurity Current { get; private set; }

    internal ConnectionIndicator()
    {
        var body = new StackPanel { Orientation = Orientation.Horizontal };
        body.Children.Add(light);
        body.Children.Add(label);
        Child = body;
        CornerRadius = new CornerRadius(9);
        Padding = new Thickness(8, 3, 8, 3);
        Margin = new Thickness(7, 3, 0, 0);
        AutomationProperties.SetLiveSetting(this, AutomationLiveSetting.Polite);
        Update(ChannelSecurity.Disconnected);
    }

    internal void Update(ChannelSecurity state)
    {
        if (initialized && Current == state) return;
        initialized = true;
        Current = state;
        var (text, color, detail) = state switch
        {
            ChannelSecurity.Encrypted => ("Ende-zu-Ende verschlüsselt", Color.FromRgb(125, 221, 171),
                "Der Kanal wurde mit dem ausgewählten Kontaktschlüssel und verschlüsselten Bestätigungen in beide Richtungen aufgebaut. Unterbrechungen können verzögert erkannt werden. Die Identität der Person kannst du zusätzlich über einen persönlichen Schlüsselabgleich prüfen."),
            ChannelSecurity.Connecting => ("Kanal wird geprüft", Color.FromRgb(235, 197, 120),
                "Noch kein bestätigter Kanal. Senden wird erst nach der kryptografischen Bestätigung freigeschaltet."),
            ChannelSecurity.Failed => ("Nicht bestätigt", Color.FromRgb(255, 174, 160),
                "Die Verbindung ist fehlgeschlagen. Es besteht kein bestätigter verschlüsselter Kanal."),
            _ => ("Nicht verbunden", Color.FromRgb(153, 174, 187),
                "Kein aktiver bestätigter Kanal. Tor-Erreichbarkeit allein aktiviert diese Anzeige nicht.")
        };
        light.Fill = new SolidColorBrush(color);
        label.Foreground = new SolidColorBrush(color);
        label.Text = text;
        Background = new SolidColorBrush(Color.FromArgb(state == ChannelSecurity.Encrypted ? (byte)22 : (byte)10, color.R, color.G, color.B));
        light.Effect = state == ChannelSecurity.Encrypted
            ? new DropShadowEffect { Color = color, BlurRadius = 8, ShadowDepth = 0, Opacity = .6 }
            : null;
        ToolTip = detail;
        AutomationProperties.SetName(this, "Verbindungsverschlüsselung: " + text);
        if (UIElementAutomationPeer.FromElement(this) is { } peer)
            peer.RaiseAutomationEvent(AutomationEvents.LiveRegionChanged);
    }
}
