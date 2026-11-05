using System.Reflection;
using System.Windows;

namespace KryptoCore.Desktop;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        var application = new Application();
        string assembly = Assembly.GetExecutingAssembly().GetName().Name!;
        application.Resources.MergedDictionaries.Add(new ResourceDictionary
        {
            Source = new Uri($"/{assembly};component/Theme.xaml", UriKind.Relative)
        });
#if CONTAINER_APP
        string? embedded = ExecutableContainer.CurrentArchive();
        var window = embedded is null ? new ContainerWindow() : new ContainerWindow(embedded);
        if (embedded is null && args is [var archive] && archive != "--verify-package")
            window.OpenFromFile(archive);
        object probe = new { action = "generate" };
        const int expectedLength = 48;
#else
        if (args is ["--verify-tor"] or ["--verify-tor-offline"])
        {
            var test = System.IO.Directory.CreateTempSubdirectory("kryptocore-tor-check-");
            try
            {
                using var tor = new TorRuntime(test.FullName);
                bool online = args[0] == "--verify-tor";
                var endpoint = Task.Run(() => tor.StartAsync(null, CancellationToken.None, online)).GetAwaiter().GetResult();
                if (!endpoint.OnionAddress.EndsWith(".onion:49424", StringComparison.Ordinal)) return 1;
                if (online) return endpoint.SocksPort != 0 ? 0 : 1;
                tor.Dispose();
                var restarted = Task.Run(() => tor.StartAsync(null, CancellationToken.None, connectToNetwork: false))
                    .GetAwaiter().GetResult();
                if (endpoint.OnionAddress != restarted.OnionAddress) return 1;
                var rotated = Task.Run(() => tor.RotateAsync(CancellationToken.None, connectToNetwork: false))
                    .GetAwaiter().GetResult();
                if (rotated.OnionAddress == endpoint.OnionAddress) return 1;
                tor.Dispose();
                using var reopened = new TorRuntime(test.FullName);
                var persisted = Task.Run(() => reopened.StartAsync(null, CancellationToken.None, connectToNetwork: false))
                    .GetAwaiter().GetResult();
                return persisted.OnionAddress == rotated.OnionAddress ? 0 : 1;
            }
            catch (Exception error) when (error is System.IO.IOException or System.ComponentModel.Win32Exception)
            {
                return 1;
            }
            finally { test.Delete(recursive: true); }
        }
        var window = new MsgWindow();
        object probe = new { action = "read_contact", code = "KCM1-" + new string('a', 64) };
        const int expectedLength = 64;
#endif
        if (args is ["--verify-package"])
        {
            var content = (FrameworkElement)window.Content;
            content.Measure(new Size(960, 770));
            content.Arrange(new Rect(0, 0, 960, 770));
            var reply = Task.Run(() => Engine.Call(probe)).GetAwaiter().GetResult();
            return reply.Ok && reply.Text?.Length == expectedLength ? 0 : 1;
        }
        return application.Run(window);
    }
}
