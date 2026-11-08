using System.IO;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Threading;

internal static class Program
{
    private const BindingFlags Members = BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static;
    private const string KeyPassword = "synthetic signing password only";
    private const string ContainerPassword = "synthetic container password only";
    [STAThread]
    private static void Main(string[] args)
    {
        if (ScannerProbe.TryRun(args)) return;
        var app = new Application();
        SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(app.Dispatcher));
        var assembly = Assembly.LoadFrom(Path.GetFullPath(args[0]));
        app.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = new Uri("/KryptoCore-Container;component/Theme.xaml", UriKind.Relative) });
        var type = assembly.GetType("KryptoCore.Desktop.ContainerWindow", true)!;
        var engine = assembly.GetType("KryptoCore.Desktop.Engine", true)!;
        var call = engine.GetMethod("Call", Members)!;
        var root = Directory.CreateDirectory(Path.Combine(AppContext.BaseDirectory, "fixtures", Guid.NewGuid().ToString("N")));
        var window = (Window)Activator.CreateInstance(type, true)!;
        window.Left = -10000; window.Top = -10000; window.ShowInTaskbar = false; window.Show();
        try
        {
            Click("Signaturen");
            string key = Path.Combine(root.FullName, "synthetic.kcsk");
            Find<TextBox>("Neuer geschützter Schlüssel").Text = key;
            Find<PasswordBox>("Neues Schlüsselpasswort (mindestens 15 Zeichen)").Password = KeyPassword;
            Find<PasswordBox>("Schlüsselpasswort wiederholen").Password = KeyPassword;
            Click("Signierschlüssel anlegen");
            string code = Find<TextBox>("Öffentlicher Signiercode zum Weitergeben").Text;
            Assert(code.StartsWith("KCP1:") && new FileInfo(key).Length == 96, "Encrypted key/public-code generation failed");
            Assert(Find<PasswordBox>("Neues Schlüsselpasswort (mindestens 15 Zeichen)").SecurePassword.Length == 0, "Key password retained");
            string plain = Path.Combine(root.FullName, "synthetic.txt"); File.WriteAllText(plain, "synthetic attachment");
            string archive = Path.Combine(root.FullName, "synthetic.kcc");
            Assert(Ok(Call(new { action = "pack", output = archive, sources = new[] { plain }, opener = (string?)null }, ContainerPassword, true)), "Fixture pack failed");
            string signature = Path.Combine(root.FullName, "synthetic.kcsig");
            Find<TextBox>("Container für KryptoCore-Signatur").Text = archive;
            Find<TextBox>("Geschützter Signierschlüssel").Text = key;
            Find<PasswordBox>("Schlüsselpasswort").Password = KeyPassword;
            Find<TextBox>("Neue KryptoCore-Signatur").Text = signature;
            Click("Signatur erstellen");
            Assert(new FileInfo(signature).Length == 113, "Signature creation failed");
            Find<TextBox>("Signierten Container prüfen").Text = archive;
            Find<TextBox>("Empfangene KryptoCore-Signatur").Text = signature;
            Find<TextBox>("Vertrauenswürdig bestätigter öffentlicher Code").Text = code;
            Click("KryptoCore-Signatur prüfen");
            Assert(Text("Dateisignatur entspricht dem gewählten öffentlichen Schlüssel. Kein Virenscan durchgeführt."), "Signature-only result conflated with scan");
            string scanner = Path.Combine(AppContext.BaseDirectory, "Check.exe");
            byte[] before = File.ReadAllBytes(archive);
            foreach (int status in new[] { 1, 2, 0 })
            {
                string output = Path.Combine(root.FullName, "scan-" + status);
                Environment.SetEnvironmentVariable("KCV_TEST_SCAN_EXIT", status.ToString());
                object reply = Call(new { action = "unpack", input = archive, output, embedded = false,
                    native_signer = new { signature, expected_public = code }, scanner }, ContainerPassword);
                Assert(Ok(reply) == (status == 0) && Directory.Exists(output) == (status == 0), "Scan failure/detection did not block output");
            }
            byte[] sig = File.ReadAllBytes(signature); byte[] bad = (byte[])sig.Clone(); bad[^1] ^= 1; File.WriteAllBytes(signature, bad);
            string marker = Path.Combine(root.FullName, "must-not-scan.txt");
            Environment.SetEnvironmentVariable("KCV_TEST_SCAN_MARKER", marker);
            object rejected = Call(new { action = "unpack", input = archive, output = Path.Combine(root.FullName, "rejected"), embedded = false,
                native_signer = new { signature, expected_public = code }, scanner }, ContainerPassword);
            Assert(!Ok(rejected) && !File.Exists(marker) && !Directory.Exists(Path.Combine(root.FullName, "rejected")), "Invalid signature reached scanner/publication");
            File.WriteAllBytes(signature, sig);
            Assert(File.ReadAllBytes(archive).SequenceEqual(before), "Source archive changed");
            File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "native-fixture.json"), JsonSerializer.Serialize(new { archive, signature, expected_public = code, password = ContainerPassword }));
            Console.WriteLine("Container Windows passed: encrypted key creation, shared signature UI, exact signature verification, scan detection/error/no-detection gates, signature-before-scan ordering and source preservation. Scanner is a controlled test surrogate.");
        }
        finally { Environment.SetEnvironmentVariable("KCV_TEST_SCAN_EXIT", null); Environment.SetEnvironmentVariable("KCV_TEST_SCAN_MARKER", null); window.Close(); }

        T Find<T>(string name) where T : FrameworkElement => Elements(window).OfType<T>().Single(e => AutomationProperties.GetName(e) == name);
        bool Text(string value) => Elements(window).OfType<TextBlock>().Any(e => e.Text == value);
        void Click(string name)
        {
            Elements(window).OfType<Button>().Single(e => Equals(e.Content, name)).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            Wait(() => !(bool)type.BaseType!.GetField("busy", Members)!.GetValue(window)!);
        }
        object Call(object request, string password, bool confirm = false)
        {
            var task = (Task)call.Invoke(null, [request, Encoding.UTF8.GetBytes(password), confirm ? Encoding.UTF8.GetBytes(password) : null, CancellationToken.None, null, false])!;
            Wait(() => task.IsCompleted); task.GetAwaiter().GetResult();
            return task.GetType().GetProperty("Result")!.GetValue(task)!;
        }
    }
    private static bool Ok(object reply) => (bool)reply.GetType().GetProperty("Ok")!.GetValue(reply)!;
    private static void Assert(bool condition, string message) { if (!condition) throw new Exception(message); }
    private static IEnumerable<DependencyObject> Elements(DependencyObject node)
    {
        yield return node;
        foreach (var child in LogicalTreeHelper.GetChildren(node).OfType<DependencyObject>())
            foreach (var descendant in Elements(child)) yield return descendant;
    }
    private static void Wait(Func<bool> ready)
    {
        var end = DateTime.UtcNow.AddSeconds(45); var frame = new DispatcherFrame();
        var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(20) };
        timer.Tick += (_, _) => { if (ready() || DateTime.UtcNow >= end) frame.Continue = false; };
        timer.Start(); Dispatcher.PushFrame(frame); timer.Stop();
        if (!ready()) throw new TimeoutException("Container UI operation");
    }
}
