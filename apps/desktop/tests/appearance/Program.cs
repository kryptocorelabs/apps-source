using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        var app = new Application();
        SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(app.Dispatcher));
        var assembly = Assembly.LoadFrom(Path.GetFullPath(args[0]));
        string product = args[1];
        string output = Path.GetFullPath(args[2]); Directory.CreateDirectory(output);
        app.Resources.MergedDictionaries.Add(new ResourceDictionary
        { Source = new Uri($"/{assembly.GetName().Name};component/Theme.xaml", UriKind.Relative) });
        var type = assembly.GetType("KryptoCore.Desktop." + product + "Window", true)!;
        var window = (Window)Activator.CreateInstance(type, true)!;
        window.Left = -10000; window.Top = -10000; window.ShowInTaskbar = false; window.Show();
        try
        {
            if (window.WindowStyle != WindowStyle.None) throw new Exception("Native chrome unexpectedly restored.");
            var shell = type.BaseType!;
            var tabs = (List<Button>)shell.GetField("tabs", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(window)!;
            int index = 0;
            foreach (var tab in tabs)
            {
                tab.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                Pump();
                foreach (bool compact in new[] { false, true })
                {
                    window.Width = compact ? window.MinWidth : 1060;
                    window.Height = compact ? window.MinHeight : 820;
                    Pump(); window.UpdateLayout();
                    var root = (FrameworkElement)window.Content;
                    if (root.ActualWidth < 500 || root.ActualHeight < 400) throw new Exception("Invalid layout bounds.");
                    var bitmap = new RenderTargetBitmap((int)Math.Ceiling(root.ActualWidth), (int)Math.Ceiling(root.ActualHeight), 96, 96, PixelFormats.Pbgra32);
                    bitmap.Render(root);
                    var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
                    using var file = File.Create(Path.Combine(output, $"{product.ToLowerInvariant()}-{index}-{(compact ? "compact" : "desktop")}.png"));
                    encoder.Save(file);
                }
                Console.WriteLine($"Rendered {product}: {tab.Content}"); index++;
            }
            Console.WriteLine("Appearance smoke passed: all navigation pages at desktop and minimum window size.");
        }
        finally { window.Close(); }
    }

    private static void Pump()
    {
        var frame = new DispatcherFrame();
        Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() => frame.Continue = false));
        Dispatcher.PushFrame(frame);
    }
}
