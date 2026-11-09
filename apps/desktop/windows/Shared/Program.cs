using System.IO;
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
            var test = Directory.CreateTempSubdirectory("kryptocore-tor-check-");
            try
            {
                bool online = args[0] == "--verify-tor";
                Task.Run(() => VerifyTorAsync(test.FullName, online)).GetAwaiter().GetResult();
                return 0;
            }
            catch (Exception error) when (error is IOException or System.ComponentModel.Win32Exception)
            {
                Console.Error.WriteLine(error.Message);
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

#if !CONTAINER_APP
    private const string LegacyTorKeyFile = "hs_ed25519_secret_key";
    private const string ProtectedTorKeyFile = "hs_ed25519_secret_key.dpapi";

    private static async Task VerifyTorAsync(string profile, bool online)
    {
        using var tor = new TorRuntime(profile);
        var endpoint = await tor.StartAsync(null, CancellationToken.None, online);
        Require(endpoint.OnionAddress.EndsWith(".onion:49424", StringComparison.Ordinal), "Invalid onion endpoint.");
        if (online)
        {
            Require(endpoint.SocksPort != 0, "Tor did not open a SOCKS listener.");
            return;
        }

        Require(File.Exists(Path.Combine(profile, "onion", ProtectedTorKeyFile)), "New key was not protected.");
        tor.Dispose();
        var restarted = await tor.StartAsync(null, CancellationToken.None, connectToNetwork: false);
        Require(endpoint.OnionAddress == restarted.OnionAddress, "The new address changed on restart.");
        var rotated = await tor.RotateAsync(CancellationToken.None, connectToNetwork: false);
        Require(rotated.OnionAddress != endpoint.OnionAddress, "Rotation kept the same address.");
        tor.Dispose();
        using (var reopened = new TorRuntime(profile))
        {
            var persisted = await reopened.StartAsync(null, CancellationToken.None, connectToNetwork: false);
            Require(persisted.OnionAddress == rotated.OnionAddress, "The rotated address changed on restart.");
        }
        string active = File.ReadAllText(Path.Combine(profile, "onion-active"));
        Require(File.Exists(Path.Combine(profile, active, ProtectedTorKeyFile)), "Rotated key was not protected.");
        RequireNoPlaintextTorKeys(profile);

        await VerifyLegacyTorProfileAsync(Path.Combine(profile, "legacy-profile"));
    }

    private static async Task VerifyLegacyTorProfileAsync(string profile)
    {
        // Public RFC 8032 test keys 1 and 2 in Tor's legacy header + expanded key format.
        const string selectedService = "onion-11111111111111111111111111111111";
        const string selectedHost = "25njqamcweflpvkl73j4szahhihoc4xt3ktcgjnpaingr5yhkenl5sid.onion";
        const string retiredHost = "hvabpq7iioevvevxbktu2g36xsojqlgpf3cjndgazvk7ckxumygcmyyd.onion";
        byte[] selectedKey = Convert.FromBase64String(
            "PT0gZWQyNTUxOXYxLXNlY3JldDogdHlwZTAgPT0AAAAwfIOGTygzy0J6LvHACgE8/f8naNmAwKOlIPAGkE3pT5tPCv4oC3Rqd4aE51RCUCBXt0c6A/CPlvWjjpKH4B+P");
        byte[] retiredKey = Convert.FromBase64String(
            "PT0gZWQyNTUxOXYxLXNlY3JldDogdHlwZTAgPT0AAABovZ7XWILVKBWpdYXK9HkKf2xrO3+CHF4lmiSwLlAuUUVmhIKR2sryJcxj3rNI2jGOLC4XsAuBYPnOa/oEcpEd");
        string selected = Directory.CreateDirectory(Path.Combine(profile, selectedService)).FullName;
        string retired = Directory.CreateDirectory(Path.Combine(profile, "onion")).FullName;
        string selection = Path.Combine(profile, "onion-active");
        string legacy = Path.Combine(selected, LegacyTorKeyFile);
        string protectedKey = Path.Combine(selected, ProtectedTorKeyFile);
        File.WriteAllText(selection, selectedService);
        File.WriteAllText(Path.Combine(selected, "hostname"), selectedHost + "\n");
        File.WriteAllBytes(legacy, selectedKey);
        File.WriteAllText(Path.Combine(retired, "hostname"), retiredHost + "\n");
        File.WriteAllBytes(Path.Combine(retired, LegacyTorKeyFile), retiredKey);

        using var tor = new TorRuntime(profile);
        var migrated = await tor.StartAsync(null, CancellationToken.None, connectToNetwork: false);
        Require(migrated.OnionAddress == selectedHost + ":49424", "Migration changed the selected onion address.");
        Require(File.ReadAllText(selection) == selectedService, "Migration changed the selected service.");
        RequireNoPlaintextTorKeys(profile);
        byte[] saved = File.ReadAllBytes(protectedKey);
        Require(saved.Length > 0 && saved.AsSpan().IndexOf(selectedKey.AsSpan(32)) < 0,
            "Migrated file contains the plaintext key.");
        Require(File.Exists(Path.Combine(retired, ProtectedTorKeyFile)), "The retired key was not protected.");
        tor.Dispose();

        // Simulate a damaged protected file with plaintext left behind by an interrupted migration.
        byte[] damaged = (byte[])saved.Clone();
        damaged[^1] ^= 1;
        File.WriteAllBytes(protectedKey, damaged);
        File.WriteAllBytes(legacy, selectedKey);
        bool rejected = false;
        try { await tor.StartAsync(null, CancellationToken.None, connectToNetwork: false); }
        catch (IOException) { rejected = true; }
        Require(rejected, "Tor opened a damaged key or fell back to plaintext.");
        Require(File.ReadAllBytes(protectedKey).AsSpan().SequenceEqual(damaged), "Tor replaced the damaged key.");
        Require(File.ReadAllBytes(legacy).AsSpan().SequenceEqual(selectedKey), "Tor removed the legacy copy after failure.");

        File.WriteAllBytes(protectedKey, saved);
        var restored = await tor.StartAsync(null, CancellationToken.None, connectToNetwork: false);
        Require(restored.OnionAddress == migrated.OnionAddress, "Retry changed the migrated address.");
        RequireNoPlaintextTorKeys(profile);
    }

    private static void RequireNoPlaintextTorKeys(string profile) => Require(
        !Directory.EnumerateFiles(profile, LegacyTorKeyFile, SearchOption.AllDirectories).Any(),
        "A plaintext Tor key remains in the profile.");

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new IOException(message);
    }
#endif
}
