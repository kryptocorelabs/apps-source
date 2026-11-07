using System.IO;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

internal static class Program
{
    private const BindingFlags Fields = BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public;
    [STAThread]
    private static void Main(string[] args)
    {
        var app = new Application();
        SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(app.Dispatcher));
        var assembly = Assembly.LoadFrom(Path.GetFullPath(args[0]));
        app.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = new Uri("/KryptoCore-Rescue;component/Theme.xaml", UriKind.Relative) });
        var type = assembly.GetType("KryptoCore.Desktop.RescueWindow", true)!;
        var writer = assembly.GetType("KryptoCore.Desktop.MetadataReport", true)!.GetMethod("Write", Fields | BindingFlags.Static)!;
        var root = Directory.CreateDirectory(Path.Combine(AppContext.BaseDirectory, "fixtures", Guid.NewGuid().ToString("N")));
        string source = Path.Combine(root.FullName, "marker-only.exe");
        byte[] bytes = new byte[221];
        Encoding.ASCII.GetBytes("KCV2\0").CopyTo(bytes, 0);
        File.WriteAllBytes(source, bytes);
        var window = (Window)Activator.CreateInstance(type, true)!;
        window.WindowStartupLocation = WindowStartupLocation.Manual;
        window.Left = -10000; window.Top = -10000; window.ShowInTaskbar = false;
        window.Show();
        Elements(window).OfType<Expander>().Single(x => Equals(x.Header, "Dateiprüfung und Metadaten")).IsExpanded = true;
        try
        {
            Inspect(source);
            if (!Text("Vault / KCV2") || !Text("Inhalte sind nicht authentifiziert.") || !Button("Diagnosebericht speichern …").IsEnabled)
                throw new Exception("Prototype confused recognition with authentication");
            string report = (string)type.GetField("report", Fields)!.GetValue(window)!;
            using var parsed = JsonDocument.Parse(report);
            string[] fields = ["schema_version", "format", "label", "file_bytes", "payload_offset", "payload_bytes", "credential_routes", "authenticity", "data_access_available"];
            if (parsed.RootElement.EnumerateObject().Any(property => !fields.Contains(property.Name))
                || parsed.RootElement.GetProperty("label").GetString() != "Vault / KCV2") throw new Exception("Unexpected diagnostic fields");
            if (report.Contains(source) || !report.Contains("not_verified") || !report.Contains("\"data_access_available\":false"))
                throw new Exception("Unexpected diagnostic disclosure or access claim");
            if (!File.ReadAllBytes(source).SequenceEqual(bytes) || root.GetFiles().Length != 1) throw new Exception("Inspection changed sources");
            Render(window);
            string output = Path.Combine(root.FullName, "report.json");
            Complete(Write(output, report, CancellationToken.None));
            if (File.ReadAllText(output) != report) throw new Exception("Report changed");
            bool collisionRejected = false;
            try { Complete(Write(output, "must not replace", CancellationToken.None)); }
            catch (IOException) { collisionRejected = true; }
            if (!collisionRejected || File.ReadAllText(output) != report) throw new Exception("Existing report overwritten");
            collisionRejected = false;
            try { Complete(Write(source, report, CancellationToken.None)); }
            catch (IOException) { collisionRejected = true; }
            if (!collisionRejected || !File.ReadAllBytes(source).SequenceEqual(bytes)) throw new Exception("Original source overwritten");
            string canceled = Path.Combine(root.FullName, "canceled.json");
            try { Complete(Write(canceled, report, new CancellationToken(true))); throw new Exception("Cancellation ignored"); }
            catch (OperationCanceledException) { }
            if (File.Exists(canceled) || root.GetFiles("*.tmp").Length != 0) throw new Exception("Canceled or failed staging was left behind");
            string vault = Path.Combine(root.FullName, "synthetic.kcv");
            byte[] encrypted = Convert.FromHexString(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "vault-v1.hex")).Trim());
            File.WriteAllBytes(vault, encrypted);
            Inspect(vault);
            var secret = (PasswordBox)type.GetField("secret", Fields)!.GetValue(window)!;
            var destination = (TextBox)type.GetField("destination", Fields)!.GetValue(window)!;
            var consent = (CheckBox)type.GetField("plaintext", Fields)!.GetValue(window)!;
            var restore = Button("Entschlüsseln und exportieren");
            string recovered = Path.Combine(root.FullName, "recovered.json");
            secret.Password = "wrong synthetic password";
            destination.Text = recovered;
            if (restore.IsEnabled) throw new Exception("Export enabled without plaintext confirmation");
            consent.IsChecked = true;
            if (!restore.IsEnabled) throw new Exception("Valid export request not enabled");
            ClickRestore();
            if (File.Exists(recovered) || secret.SecurePassword.Length != 0 || !Text("Kein erfolgreicher authentifizierter Export."))
                throw new Exception("Failed recovery leaked output or retained input");
            secret.Password = "synthetic rescue fixture password";
            ClickRestore();
            if (!File.Exists(recovered) || !File.ReadAllText(recovered).Contains("test secret")
                || !Text("Authentifiziert · 1 Einträge exportiert") || !File.ReadAllBytes(vault).SequenceEqual(encrypted))
                throw new Exception("Authenticated Vault export failed or changed source");
            secret.Password = "synthetic rescue fixture password";
            Inspect(source);
            if (secret.SecurePassword.Length != 0 || destination.Text.Length != 0 || consent.IsChecked == true || restore.IsEnabled)
                throw new Exception("Changing source retained recovery credentials, consent or destination");
            void ClickRestore()
            {
                restore.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Button.ClickEvent));
                Wait(() => !(bool)type.BaseType!.GetField("busy", Fields)!.GetValue(window)!);
            }
            string broken = Path.Combine(root.FullName, "broken.kcv");
            File.WriteAllText(broken, "not a supported file");
            Inspect(broken);
            if (Button("Diagnosebericht speichern …").IsEnabled || type.GetField("report", Fields)!.GetValue(window) is not null)
                throw new Exception("Failed probe kept a stale report enabled");
            Console.WriteLine("Rescue Windows passed: marker-only display, authenticated export, wrong password rejection, plaintext consent, input clearing, source preservation, path-free report, no overwrite, report cancellation cleanup and stale-state reset.");
        }
        finally { window.Close(); }

        Button Button(string name) => Elements(window).OfType<Button>().Single(button => Equals(button.Content, name));
        bool Text(string text) => Elements(window).OfType<TextBlock>().Any(block => block.Text == text);
        void Inspect(string path)
        {
            type.GetField("selected", Fields)!.SetValue(window, path);
            var again = Button("Erneut prüfen");
            again.IsEnabled = true;
            again.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Button.ClickEvent));
            Wait(() => !(bool)type.BaseType!.GetField("busy", Fields)!.GetValue(window)!);
        }
        Task Write(string target, string content, CancellationToken cancellation) =>
            (Task)writer.Invoke(null, [target, content, cancellation])!;
        void Complete(Task work) { Wait(() => work.IsCompleted); work.GetAwaiter().GetResult(); }
    }

    private static IEnumerable<DependencyObject> Elements(DependencyObject node)
    {
        yield return node;
        foreach (var child in LogicalTreeHelper.GetChildren(node).OfType<DependencyObject>())
            foreach (var descendant in Elements(child)) yield return descendant;
    }
    private static void Wait(Func<bool> ready)
    {
        var end = DateTime.UtcNow.AddSeconds(30);
        var frame = new DispatcherFrame();
        var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(25) };
        timer.Tick += (_, _) => { if (ready() || DateTime.UtcNow >= end) frame.Continue = false; };
        timer.Start(); Dispatcher.PushFrame(frame); timer.Stop();
        if (!ready()) throw new TimeoutException("Rescue UI operation");
    }
    private static void Render(Window window)
    {
        window.UpdateLayout();
        var bitmap = new RenderTargetBitmap((int)window.ActualWidth, (int)window.ActualHeight, 96, 96, System.Windows.Media.PixelFormats.Pbgra32);
        bitmap.Render(window);
        var png = new PngBitmapEncoder();
        png.Frames.Add(BitmapFrame.Create(bitmap));
        using var file = File.Create(Path.Combine(AppContext.BaseDirectory, "rescue.png"));
        png.Save(file);
    }
}
