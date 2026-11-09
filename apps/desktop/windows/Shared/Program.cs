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
        var first = await CreateTestIdentityAsync(profile, "first");
        using var tor = new TorRuntime(profile);
        var endpoint = await tor.StartAsync(first, null, CancellationToken.None, online);
        Require(endpoint.OnionAddress.EndsWith(".onion:49424", StringComparison.Ordinal), "Invalid onion endpoint.");
        if (online)
        {
            Require(endpoint.SocksPort != 0, "Tor did not open a SOCKS listener.");
            return;
        }

        Require(File.Exists(first.Path + ".onion-key"), "The new key was not stored with its identity.");
        Require(!Directory.EnumerateFiles(profile, ProtectedTorKeyFile, SearchOption.AllDirectories).Any(),
            "A new onion key was stored under the Windows profile.");
        tor.Stop();
        var restarted = await tor.StartAsync(first, null, CancellationToken.None, connectToNetwork: false);
        Require(endpoint.OnionAddress == restarted.OnionAddress, "The new address changed on restart.");
        var second = await CreateTestIdentityAsync(profile, "second");
        var other = await tor.StartAsync(second, null, CancellationToken.None, connectToNetwork: false);
        Require(other.OnionAddress != endpoint.OnionAddress, "The second identity inherited the first onion address.");
        var rotated = await tor.RotateAsync(first, CancellationToken.None, connectToNetwork: false);
        Require(rotated.OnionAddress != endpoint.OnionAddress, "Rotation kept the same address.");
        var unchanged = await tor.StartAsync(second, null, CancellationToken.None, connectToNetwork: false);
        Require(other.OnionAddress == unchanged.OnionAddress, "Rotation changed the second identity's address.");
        tor.Stop();
        using (var reopened = new TorRuntime(profile))
        {
            var persisted = await reopened.StartAsync(first, null, CancellationToken.None, connectToNetwork: false);
            Require(persisted.OnionAddress == rotated.OnionAddress, "The rotated address changed on restart.");
        }
        await VerifyProtectedKeyFailureAsync(tor, first, second);
        await VerifyIdentityMoveAndCancellationAsync(profile, first, rotated.OnionAddress);
        RequireNoPlaintextTorKeys(profile);

        await VerifyLegacyTorProfileAsync(Path.Combine(profile, "legacy-profile"));
    }

    private static async Task<OnionIdentity> CreateTestIdentityAsync(string profile, string name)
    {
        Directory.CreateDirectory(profile);
        string path = Path.Combine(profile, name + ".kcmi");
        // This passphrase is used only for the identities generated in the test directory.
        static byte[] Password() => "onion self-test synthetic passphrase"u8.ToArray();
        var reply = await Engine.Call(new { action = "new_identity", path }, Password(), Password());
        if (!reply.Ok || reply.Text is not { Length: 64 } publicKey)
            throw new IOException("Could not create a synthetic MSG identity.");
        return new OnionIdentity(path, publicKey, Password);
    }

    private static async Task VerifyProtectedKeyFailureAsync(TorRuntime tor, OnionIdentity first, OnionIdentity second)
    {
        string firstStore = first.Path + ".onion-key";
        string secondStore = second.Path + ".onion-key";
        byte[] saved = File.ReadAllBytes(firstStore);
        byte[] damaged = (byte[])saved.Clone();
        damaged[^1] ^= 1;
        File.WriteAllBytes(firstStore, damaged);
        await RequireFailureAsync(() => tor.StartAsync(first, null, CancellationToken.None, connectToNetwork: false),
            "Tor opened or replaced a damaged identity key.");
        Require(File.ReadAllBytes(firstStore).AsSpan().SequenceEqual(damaged), "Tor replaced the damaged identity key.");

        byte[] otherKey = File.ReadAllBytes(secondStore);
        File.WriteAllBytes(firstStore, otherKey);
        await RequireFailureAsync(() => tor.StartAsync(first, null, CancellationToken.None, connectToNetwork: false),
            "An onion key copied from another identity was accepted.");
        Require(File.ReadAllBytes(firstStore).AsSpan().SequenceEqual(otherKey), "Tor replaced the foreign identity key.");
        File.WriteAllBytes(firstStore, saved);
    }

    private static async Task VerifyIdentityMoveAndCancellationAsync(string profile, OnionIdentity original, string address)
    {
        string destination = Directory.CreateDirectory(Path.Combine(profile, "moved")).FullName;
        string path = Path.Combine(destination, "restored.kcmi");
        File.Copy(original.Path, path);
        File.Copy(original.Path + ".onion-key", path + ".onion-key");
        using var tor = new TorRuntime(destination);
        var moved = await tor.StartAsync(original with { Path = path }, null, CancellationToken.None, connectToNetwork: false);
        Require(moved.OnionAddress == address, "Copying the encrypted identity files changed the address.");

        var cancelled = await CreateTestIdentityAsync(destination, "cancelled");
        try
        {
            await tor.StartAsync(cancelled, _ => tor.Stop(), CancellationToken.None, connectToNetwork: false);
            throw new IOException("Stopping Tor allowed the pending startup to finish.");
        }
        catch (OperationCanceledException) { }
        Require(!File.Exists(cancelled.Path + ".onion-key"), "Cancelled startup created a new onion key.");
        var retried = await tor.StartAsync(cancelled, null, CancellationToken.None, connectToNetwork: false);
        Require(retried.OnionAddress != address, "The next identity inherited a cancelled startup's address.");
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

        var first = await CreateTestIdentityAsync(profile, "import-owner");
        var second = await CreateTestIdentityAsync(profile, "other");
        using var tor = new TorRuntime(profile);
        Require(tor.HasLegacyKey, "The legacy address was not detected.");
        var fresh = await tor.StartAsync(first, null, CancellationToken.None, connectToNetwork: false);
        Require(fresh.OnionAddress != selectedHost + ":49424", "The previous address was imported without consent.");
        Require(tor.HasLegacyKey && File.Exists(protectedKey), "Normal startup did not protect and preserve the import source.");
        RequireNoPlaintextTorKeys(profile);
        Require(File.Exists(Path.Combine(retired, ProtectedTorKeyFile)), "The retired key was not protected.");
        // Resume a transfer interrupted between claiming the key and confirming the identity file.
        File.WriteAllText(Path.Combine(selected, "import-owner"), first.PublicKey);
        await RequireFailureAsync(() => tor.ImportLegacyAsync(second, CancellationToken.None, connectToNetwork: false),
            "Another identity could take over an interrupted import.");
        Require(tor.HasLegacyKey && File.Exists(protectedKey) && !File.Exists(second.Path + ".onion-key"),
            "A failed takeover changed the import source or the other identity.");
        var migrated = await tor.ImportLegacyAsync(first, CancellationToken.None, connectToNetwork: false);
        Require(migrated.OnionAddress == selectedHost + ":49424", "Import changed the selected onion address.");
        Require(!tor.HasLegacyKey && !File.Exists(protectedKey) && !File.Exists(Path.Combine(selected, "hostname")),
            "Import did not retire the previous storage.");
        byte[] stored = File.ReadAllBytes(first.Path + ".onion-key");
        Require(stored.AsSpan().IndexOf(selectedKey.AsSpan(32)) < 0, "The identity file contains the plaintext onion key.");
        await RequireFailureAsync(() => tor.ImportLegacyAsync(second, CancellationToken.None, connectToNetwork: false),
            "The same legacy address could be imported a second time.");
        Require(!File.Exists(second.Path + ".onion-key"), "A failed import created an onion key for the wrong identity.");
        var restored = await tor.StartAsync(first, null, CancellationToken.None, connectToNetwork: false);
        Require(restored.OnionAddress == migrated.OnionAddress, "Restart changed the imported address.");
        RequireNoPlaintextTorKeys(profile);
    }

    private static async Task RequireFailureAsync(Func<Task<OnionEndpoint>> operation, string message)
    {
        try { await operation(); }
        catch (IOException) { return; }
        throw new IOException(message);
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
