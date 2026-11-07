using System.Windows;

namespace KryptoCore.Desktop;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        var app = new Application();
        app.Resources.MergedDictionaries.Add(new ResourceDictionary
        {
            Source = new Uri("/KryptoCore-Rescue;component/Theme.xaml", UriKind.Relative)
        });
        var window = new RescueWindow();
        if (args is ["--verify-package"])
        {
            var content = (FrameworkElement)window.Content;
            content.Measure(new Size(960, 770));
            content.Arrange(new Rect(0, 0, 960, 770));
            // A missing file must return a controlled reply from the embedded worker.
            var reply = Task.Run(() => Engine.Call(new { action = "inspect", input = "" })).GetAwaiter().GetResult();
            return !reply.Ok && reply.Message == "The selected file could not be read." ? 0 : 1;
        }
        return app.Run(window);
    }
}
