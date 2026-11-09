using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace KryptoCore.Desktop;

internal sealed class TorRuntime(string? dataRoot = null, bool networkEnabled = true) : IOnionTransport, IDisposable
{
    private const int PresencePort = 49425;
    private const int ContactRequestPort = 49426;
    private static readonly Regex Bootstrap = new(@"(?:^| )PROGRESS=(\d{1,3})(?: |$)", RegexOptions.CultureInvariant);
    private readonly string profile = dataRoot ?? Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "KryptoCore", "MSG");
    private readonly SemaphoreSlim operations = new(1, 1);
    private readonly object state = new();
    private CancellationTokenSource lifetime = new();
    private TorSession? running;
    private OnionIdentity? owner;
    private OnionEndpoint? ready;

    public bool HasLegacyKey => OnionKeyStore.HasLegacyKey(profile);

    Task<OnionEndpoint> IOnionTransport.StartAsync(OnionIdentity identity, Action<int>? onProgress,
        CancellationToken cancellation) => StartAsync(identity, onProgress, cancellation, networkEnabled);

    Task<OnionEndpoint> IOnionTransport.RotateAsync(OnionIdentity identity, CancellationToken cancellation)
        => RotateAsync(identity, cancellation, networkEnabled);

    Task<OnionEndpoint> IOnionTransport.ImportLegacyAsync(OnionIdentity identity, CancellationToken cancellation)
        => ImportLegacyAsync(identity, cancellation, networkEnabled);

    public void Stop() => Dispose();

    internal Task<OnionEndpoint> StartAsync(OnionIdentity identity, Action<int>? onProgress,
        CancellationToken cancellation, bool connectToNetwork = true)
        => ActivateAsync(identity, Change.Keep, onProgress, cancellation, connectToNetwork);

    internal Task<OnionEndpoint> RotateAsync(OnionIdentity identity, CancellationToken cancellation,
        bool connectToNetwork = true)
        => ActivateAsync(identity, Change.Rotate, null, cancellation, connectToNetwork);

    internal Task<OnionEndpoint> ImportLegacyAsync(OnionIdentity identity, CancellationToken cancellation,
        bool connectToNetwork = true)
        => ActivateAsync(identity, Change.Import, null, cancellation, connectToNetwork);

    private enum Change { Keep, Rotate, Import }

    private async Task<OnionEndpoint> ActivateAsync(OnionIdentity identity, Change change,
        Action<int>? onProgress, CancellationToken cancellation, bool connectToNetwork)
    {
        CancellationTokenSource request;
        lock (state)
            request = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token, cancellation);
        using (request)
        {
            await operations.WaitAsync(request.Token);
            try
            {
                lock (state)
                {
                    request.Token.ThrowIfCancellationRequested();
                    if (change == Change.Keep && ReferenceEquals(owner, identity) && ready is { } endpoint
                        && running is { IsRunning: true })
                        return endpoint;
                    Disconnect();
                }

                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(request.Token);
                timeout.CancelAfter(connectToNetwork ? TimeSpan.FromMinutes(2) : TimeSpan.FromSeconds(30));
                int progress = 0;
                try
                {
                    return await StartSessionAsync(identity, change, percent =>
                    {
                        progress = percent;
                        onProgress?.Invoke(percent);
                    }, timeout.Token, connectToNetwork);
                }
                catch (Exception error) when (request.IsCancellationRequested
                    && error is OperationCanceledException or IOException or System.ComponentModel.Win32Exception)
                {
                    throw new OperationCanceledException(request.Token);
                }
                catch (Exception error) when (timeout.IsCancellationRequested
                    && error is OperationCanceledException or IOException or System.ComponentModel.Win32Exception)
                {
                    throw new IOException($"Tor wurde nicht rechtzeitig bereit (zuletzt {progress} %).");
                }
            }
            finally { operations.Release(); }
        }
    }

    private async Task<OnionEndpoint> StartSessionAsync(OnionIdentity identity, Change change,
        Action<int> onProgress, CancellationToken token, bool connectToNetwork)
    {
        TorSession? session = new(profile);
        byte[]? previous = null;
        byte[]? candidate = null;
        try
        {
            using var abort = token.Register(session.Abort);
            previous = await ReadIdentityKeyAsync(identity, token);
            await session.OpenAsync(token);
            // Once Tor holds its data-directory lock, an older MSG instance cannot be using these files.
            OnionKeyStore.ProtectLegacyProfile(profile, token);
            OnionKeyStore? legacy = change == Change.Import ? OnionKeyStore.Active(profile) : null;
            if (legacy is not null)
            {
                legacy.CheckImportOwner(identity.PublicKey);
                candidate = legacy.ReadKey() ?? throw new IOException("Es gibt keine frühere Tor-Adresse zum Übernehmen.");
            }
            string? previousAddress = legacy?.ReadLegacyAddress();
            var (address, generated) = await RegisterOnionAsync(session.Control,
                change == Change.Keep ? previous : candidate, previousAddress, token);
            candidate ??= generated;
            if (change == Change.Keep)
            {
                Clear(previous);
                previous = null;
            }
            int port = await session.WaitForNetworkAsync(onProgress, token, connectToNetwork);

            if (candidate is not null)
            {
                if (legacy is not null) legacy.ClaimImport(identity.PublicKey);
                if (previous is null || !CryptographicOperations.FixedTimeEquals(previous, candidate))
                    await WriteIdentityKeyAsync(identity, candidate, previous, token);
                if (legacy is not null)
                {
                    byte[]? confirmed = await ReadIdentityKeyAsync(identity, token);
                    try
                    {
                        if (confirmed is null || !CryptographicOperations.FixedTimeEquals(confirmed, candidate))
                            throw new IOException("Die übernommene Tor-Adresse konnte nicht bestätigt werden.");
                        token.ThrowIfCancellationRequested();
                        legacy.RetireImportedKey(candidate);
                    }
                    finally { Clear(confirmed); }
                }
            }

            lock (state)
            {
                token.ThrowIfCancellationRequested();
                owner = identity;
                ready = new OnionEndpoint(port, $"{address}:{OnionEndpoint.ChatPort}");
                running = session;
                session = null;
                return ready;
            }
        }
        finally
        {
            Clear(previous);
            Clear(candidate);
            session?.Dispose();
        }
    }

    private static async Task<byte[]?> ReadIdentityKeyAsync(OnionIdentity identity, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var reply = await Engine.Call(new { action = "read_onion_key", path = identity.Path,
            identity_key = identity.PublicKey }, identity.PasswordBytes(), cancellation: token);
        if (reply.Ok && (reply.OnionKey is null || reply.OnionKey.Length == 64)) return reply.OnionKey;
        Clear(reply.OnionKey);
        throw new IOException("Der Tor-Schlüssel dieser Identität konnte nicht geöffnet werden.");
    }

    private static async Task WriteIdentityKeyAsync(OnionIdentity identity, byte[] key, byte[]? previous,
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        byte[] input = new byte[previous is null ? 64 : 128];
        try
        {
            key.CopyTo(input, 0);
            previous?.CopyTo(input, 64);
            var reply = await Engine.Call(new { action = "write_onion_key", path = identity.Path,
                identity_key = identity.PublicKey, replace = previous is not null }, identity.PasswordBytes(), input, token);
            Clear(reply.OnionKey);
            if (!reply.Ok) throw new IOException("Der Tor-Schlüssel dieser Identität konnte nicht gespeichert werden.");
        }
        finally { Clear(input); }
    }

    private static void Clear(byte[]? bytes)
    {
        if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
    }

    private static async Task<(string Address, byte[]? Generated)> RegisterOnionAsync(ControlConnection connection,
        byte[]? key, string? expectedAddress, CancellationToken token)
    {
        string torKey = key is null ? "NEW:ED25519-V3" : "ED25519-V3:" + Convert.ToBase64String(key);
        var response = await connection.CommandAsync($"ADD_ONION {torKey}"
            + $" Port={OnionEndpoint.ChatPort},127.0.0.1:{OnionEndpoint.ChatPort}"
            + $" Port={PresencePort},127.0.0.1:{PresencePort}"
            + $" Port={ContactRequestPort},127.0.0.1:{ContactRequestPort}", token);
        string address = response.GetValueOrDefault("ServiceID") + ".onion";
        if (!IsHostname(address) || (expectedAddress is not null && expectedAddress != address))
            throw new IOException("Tor hat eine unerwartete Onion-Adresse gemeldet.");
        return (address, key is null ? OnionKeyStore.DecodeTorKey(response.GetValueOrDefault("PrivateKey")) : null);
    }

    private static async Task ExtractAsync(string destination, CancellationToken token)
    {
        using var resource = typeof(TorRuntime).Assembly.GetManifestResourceStream("kryptocore-tor.exe")
            ?? throw new IOException("Diese MSG-Ausgabe enthält Tor noch nicht.");
        using var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None, 8192, useAsync: true);
        await resource.CopyToAsync(output, token);
    }

    internal static async Task VerifyExecutableAsync(Stream executable, string expected, CancellationToken token)
    {
        string actual = Convert.ToHexString(await SHA256.HashDataAsync(executable, token));
        if (!string.Equals(actual, expected, StringComparison.Ordinal))
            throw new IOException("Die Prüfsumme des eingebetteten Tor-Programms stimmt nicht. Tor wurde nicht gestartet.");
    }

    internal static bool IsHostname(string value) =>
        value.Length == 62 && value.EndsWith(".onion", StringComparison.Ordinal)
        && value[..56].All(c => c is >= 'a' and <= 'z' or >= '2' and <= '7');

    private static bool TryLocalPort(string endpoint, out int port)
    {
        port = 0;
        if (!IPEndPoint.TryParse(endpoint, out var address) || !address.Address.Equals(IPAddress.Loopback)
            || address.Port == 0) return false;
        port = address.Port;
        return true;
    }

    private static int FindSocksPort(string? listeners)
    {
        foreach (string item in (listeners ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries))
            if (TryLocalPort(item.Trim('"'), out int port)) return port;
        return 0;
    }

    public void Dispose()
    {
        lock (state)
        {
            lifetime.Cancel();
            lifetime.Dispose();
            lifetime = new();
            Disconnect();
        }
    }

    private void Disconnect()
    {
        ready = null;
        owner = null;
        running?.Dispose();
        running = null;
    }

    private sealed class TorSession : IDisposable
    {
        private readonly string profile;
        private readonly FileStream profileLock;
        private readonly object processLock = new();
        private DirectoryInfo? scratch;
        private Process? process;
        private ControlConnection? control;

        internal TorSession(string profile)
        {
            this.profile = profile;
            Directory.CreateDirectory(profile);
            profileLock = new FileStream(Path.Combine(profile, "onion-store.lock"), FileMode.OpenOrCreate,
                FileAccess.ReadWrite, FileShare.None);
        }

        internal bool IsRunning => process is { HasExited: false };
        internal ControlConnection Control => control ?? throw new IOException("Tor wurde noch nicht gestartet.");

        internal async Task OpenAsync(CancellationToken token)
        {
            scratch = Directory.CreateTempSubdirectory("kryptocore-tor-");
            string binary = Path.Combine(scratch.FullName, "tor.exe");
            string config = Path.Combine(scratch.FullName, "torrc");
            string portFile = Path.Combine(scratch.FullName, "control-port");
            string cookieFile = Path.Combine(scratch.FullName, "control-cookie");
            string data = Directory.CreateDirectory(Path.Combine(profile, "tor-data")).FullName;
            await ExtractAsync(binary, token);
            await File.WriteAllTextAsync(config, "# Dedicated KryptoCore MSG instance\n", token);

            var start = new ProcessStartInfo(binary)
            {
                UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = scratch.FullName,
                RedirectStandardOutput = true, RedirectStandardError = true
            };
            foreach (string argument in new[]
            {
                "-f", config, "--DataDirectory", data, "--DisableNetwork", "1",
                "--SocksPort", "auto ExtendedErrors", "--ControlPort", "auto", "--ControlPortWriteToFile", portFile,
                "--CookieAuthentication", "1", "--CookieAuthFile", cookieFile,
                "--__OwningControllerProcess", Environment.ProcessId.ToString(CultureInfo.InvariantCulture),
                "--Log", "warn stdout"
            }) start.ArgumentList.Add(argument);

            // Keep the verified file open without write or delete sharing until Windows starts it.
            using (var expected = typeof(TorRuntime).Assembly.GetManifestResourceStream("kryptocore-tor.sha256")
                ?? throw new IOException("Die Prüfsumme für das eingebettete Tor fehlt."))
            using (var digest = new StreamReader(expected, Encoding.ASCII))
            using (var executable = new FileStream(binary, FileMode.Open, FileAccess.Read, FileShare.Read, 8192, useAsync: true))
            {
                await VerifyExecutableAsync(executable, (await digest.ReadToEndAsync(token)).Trim(), token);
                lock (processLock)
                {
                    token.ThrowIfCancellationRequested();
                    process = Process.Start(start) ?? throw new IOException("Tor konnte nicht gestartet werden.");
                }
            }
            _ = process.StandardOutput.BaseStream.CopyToAsync(Stream.Null);
            _ = process.StandardError.BaseStream.CopyToAsync(Stream.Null);

            while (!File.Exists(portFile) || !File.Exists(cookieFile))
                await WaitForTorAsync(token);
            string published = (await File.ReadAllTextAsync(portFile, token)).Trim();
            if (!published.StartsWith("PORT=", StringComparison.Ordinal)
                || !TryLocalPort(published[5..], out int controlPort))
                throw new IOException("Tor hat keinen lokalen Steuerport gemeldet.");
            control = await ControlConnection.OpenAsync(controlPort, cookieFile, token);
        }

        internal async Task<int> WaitForNetworkAsync(Action<int> onProgress, CancellationToken token, bool online)
        {
            if (online) await Control.CommandAsync("SETCONF DisableNetwork=0", token);
            while (true)
            {
                var values = await Control.CommandAsync("GETINFO net/listeners/socks status/bootstrap-phase", token);
                var match = Bootstrap.Match(values.GetValueOrDefault("status/bootstrap-phase") ?? "");
                int percent = match.Success ? int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture) : 0;
                onProgress(percent);
                token.ThrowIfCancellationRequested();
                int port = FindSocksPort(values.GetValueOrDefault("net/listeners/socks"));
                if (!online || (percent == 100 && port != 0)) return port;
                await WaitForTorAsync(token);
            }
        }

        private async Task WaitForTorAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (!IsRunning)
                throw new IOException("Tor wurde beendet. Schließe gegebenenfalls eine andere MSG-Instanz.");
            await Task.Delay(300, token);
        }

        internal void Abort()
        {
            lock (processLock)
            {
                try { if (process is { HasExited: false }) process.Kill(entireProcessTree: true); }
                catch (InvalidOperationException) { }
                catch (System.ComponentModel.Win32Exception) { }
            }
        }

        public void Dispose()
        {
            control?.Dispose();
            lock (processLock)
            {
                if (process is not null)
                {
                    try
                    {
                        if (!process.WaitForExit(1000)) Abort();
                        process.WaitForExit(1000);
                    }
                    catch (InvalidOperationException) { }
                    catch (System.ComponentModel.Win32Exception) { }
                    process.Dispose();
                    process = null;
                }
            }
            if (scratch is not null)
            {
                try
                {
                    foreach (var file in scratch.GetFiles()) file.Delete();
                    scratch.Delete();
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
            profileLock.Dispose();
        }
    }

    private sealed class ControlConnection(TcpClient client) : IDisposable
    {
        private readonly StreamReader input = new(client.GetStream(), Encoding.ASCII, leaveOpen: true);

        internal static async Task<ControlConnection> OpenAsync(int port, string cookiePath, CancellationToken token)
        {
            var client = new TcpClient(AddressFamily.InterNetwork);
            ControlConnection? connection = null;
            try
            {
                await client.ConnectAsync(IPAddress.Loopback, port, token);
                connection = new ControlConnection(client);
                byte[] cookie = await File.ReadAllBytesAsync(cookiePath, token);
                try
                {
                    if (cookie.Length != 32) throw new IOException("Ungültiger Tor-Steuerschlüssel.");
                    await connection.CommandAsync("AUTHENTICATE " + Convert.ToHexString(cookie), token);
                }
                finally { CryptographicOperations.ZeroMemory(cookie); }
                await connection.CommandAsync("TAKEOWNERSHIP", token);
                return connection;
            }
            catch
            {
                if (connection is not null) connection.Dispose();
                else client.Dispose();
                throw;
            }
        }

        internal async Task<Dictionary<string, string>> CommandAsync(string command, CancellationToken token)
        {
            byte[] request = Encoding.ASCII.GetBytes(command + "\r\n");
            try { await client.GetStream().WriteAsync(request, token); }
            finally { CryptographicOperations.ZeroMemory(request); }
            var values = new Dictionary<string, string>(StringComparer.Ordinal);
            for (int count = 0; count < 16; count++)
            {
                string? line = await input.ReadLineAsync(token);
                if (line == "250 OK") return values;
                if (line is null || !line.StartsWith("250-", StringComparison.Ordinal)) break;
                int separator = line.IndexOf('=', 4);
                if (separator >= 0) values[line[4..separator]] = line[(separator + 1)..];
            }
            throw new IOException("Tor hat die lokale Steueranfrage abgelehnt.");
        }

        public void Dispose()
        {
            input.Dispose();
            client.Dispose();
        }
    }
}
