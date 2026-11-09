using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace KryptoCore.Desktop;

internal sealed class TorRuntime(string? dataRoot = null) : IOnionTransport, IDisposable
{
    private const int PresencePort = 49425;
    private const int ContactRequestPort = 49426;
    private static readonly Regex Bootstrap = new(@"(?:^| )PROGRESS=(\d{1,3})(?: |$)", RegexOptions.CultureInvariant);
    private readonly string profile = dataRoot ?? Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "KryptoCore", "MSG");
    private DirectoryInfo? scratch;
    private Process? process;
    private ControlConnection? control;
    private FileStream? profileLock;
    private OnionEndpoint? ready;
    private string? pendingService;

    Task<OnionEndpoint> IOnionTransport.StartAsync(Action<int>? onProgress, CancellationToken cancellation)
        => StartAsync(onProgress, cancellation);

    Task<OnionEndpoint> IOnionTransport.RotateAsync(CancellationToken cancellation)
        => RotateAsync(cancellation);

    void IOnionTransport.Stop() => Dispose();

    internal async Task<OnionEndpoint> StartAsync(Action<int>? onProgress, CancellationToken cancellation,
        bool connectToNetwork = true)
    {
        if (ready is { } existing && process is { HasExited: false }) return existing;
        Dispose();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        timeout.CancelAfter(connectToNetwork ? TimeSpan.FromMinutes(2) : TimeSpan.FromSeconds(15));
        var token = timeout.Token;
        int percentage = 0;
        try
        {
            Directory.CreateDirectory(profile);
            profileLock = new FileStream(Path.Combine(profile, "onion-store.lock"), FileMode.OpenOrCreate,
                FileAccess.ReadWrite, FileShare.None);
            string service = pendingService ?? ReadActiveService();
            var keys = new OnionKeyStore(Path.Combine(profile, service));
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
                "-f", config, "--DataDirectory", data,
                "--SocksPort", "auto ExtendedErrors", "--ControlPort", "auto", "--ControlPortWriteToFile", portFile,
                "--CookieAuthentication", "1", "--CookieAuthFile", cookieFile,
                "--__OwningControllerProcess", Environment.ProcessId.ToString(CultureInfo.InvariantCulture),
                "--Log", "warn stdout"
            }) start.ArgumentList.Add(argument);
            if (!connectToNetwork)
            {
                start.ArgumentList.Add("--DisableNetwork");
                start.ArgumentList.Add("1");
            }
            // Hold the verified file open without write or delete sharing until Windows starts it.
            using (var expected = typeof(TorRuntime).Assembly.GetManifestResourceStream("kryptocore-tor.sha256")
                ?? throw new IOException("Die Prüfsumme für das eingebettete Tor fehlt."))
            using (var digest = new StreamReader(expected, Encoding.ASCII))
            using (var executable = new FileStream(binary, FileMode.Open, FileAccess.Read, FileShare.Read, 8192, useAsync: true))
            {
                await VerifyExecutableAsync(executable, (await digest.ReadToEndAsync(token)).Trim(), token);
                token.ThrowIfCancellationRequested();
                process = Process.Start(start) ?? throw new IOException("Tor konnte nicht gestartet werden.");
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
            string onion = await RegisterOnionAsync(control, keys,
                requireExisting: pendingService is null && service != "onion", token);
            foreach (string directory in Directory.EnumerateDirectories(profile, "onion*"))
            {
                string name = Path.GetFileName(directory);
                if (!IsServiceName(name) || string.Equals(name, service, StringComparison.OrdinalIgnoreCase)) continue;
                token.ThrowIfCancellationRequested();
                new OnionKeyStore(directory).MigrateRetiredKey();
            }
            while (true)
            {
                var values = await control.CommandAsync("GETINFO net/listeners/socks status/bootstrap-phase", token);
                var match = Bootstrap.Match(values.GetValueOrDefault("status/bootstrap-phase") ?? "");
                if (match.Success)
                    percentage = int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture);
                onProgress?.Invoke(percentage);
                int port = FindSocksPort(values.GetValueOrDefault("net/listeners/socks"));
                if (!connectToNetwork || (percentage == 100 && port != 0))
                {
                    ready = new OnionEndpoint(port, $"{onion}:{OnionEndpoint.ChatPort}");
                    return ready;
                }
                await WaitForTorAsync(token);
            }
        }
        catch (OperationCanceledException) when (!cancellation.IsCancellationRequested)
        {
            Dispose();
            throw new IOException($"Tor wurde innerhalb von zwei Minuten nicht bereit (zuletzt {percentage} %). Prüfe unter „Verbindung → Tor starten und prüfen“, ob dein Netz Tor zulässt.");
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    private static async Task<string> RegisterOnionAsync(ControlConnection connection, OnionKeyStore keys,
        bool requireExisting, CancellationToken token)
    {
        string? previousAddress = keys.ReadLegacyAddress();
        byte[]? key = keys.ReadKey();
        try
        {
            if (key is null && (requireExisting || previousAddress is not null))
                throw new IOException("Der Schlüssel der gespeicherten Tor-Adresse fehlt.");
            string torKey = key is null ? "NEW:ED25519-V3" : "ED25519-V3:" + Convert.ToBase64String(key);
            var response = await connection.CommandAsync($"ADD_ONION {torKey}"
                + $" Port={OnionEndpoint.ChatPort},127.0.0.1:{OnionEndpoint.ChatPort}"
                + $" Port={PresencePort},127.0.0.1:{PresencePort}"
                + $" Port={ContactRequestPort},127.0.0.1:{ContactRequestPort}", token);
            string onion = response.GetValueOrDefault("ServiceID") + ".onion";
            if (!IsHostname(onion) || (previousAddress is not null && previousAddress != onion))
                throw new IOException("Tor hat eine unerwartete Onion-Adresse gemeldet.");
            key ??= OnionKeyStore.DecodeTorKey(response.GetValueOrDefault("PrivateKey"));
            token.ThrowIfCancellationRequested();
            keys.ProtectAndRetireLegacy(key);
            return onion;
        }
        finally
        {
            if (key is not null) CryptographicOperations.ZeroMemory(key);
        }
    }

    private string ReadActiveService()
    {
        string name;
        try { name = File.ReadAllText(Path.Combine(profile, "onion-active")); }
        catch (FileNotFoundException) { return "onion"; }
        if (IsServiceName(name) && name != "onion")
            return name;
        throw new IOException("Die gespeicherte Auswahl der Tor-Adresse ist beschädigt.");
    }

    private static bool IsServiceName(string name) => name == "onion"
        || (name.StartsWith("onion-", StringComparison.Ordinal) && Guid.TryParseExact(name[6..], "N", out _));

    internal async Task<OnionEndpoint> RotateAsync(CancellationToken token, bool connectToNetwork = true)
    {
        Dispose();
        pendingService = $"onion-{Guid.NewGuid():N}";
        string selection = Path.Combine(profile, "onion-active");
        string staged = Path.Combine(profile, $"{pendingService}.selection");
        try
        {
            OnionEndpoint endpoint = await StartAsync(null, token, connectToNetwork);
            await File.WriteAllTextAsync(staged, pendingService, token);
            token.ThrowIfCancellationRequested();
            File.Move(staged, selection, overwrite: true);
            return endpoint;
        }
        catch
        {
            Dispose();
            throw;
        }
        finally
        {
            pendingService = null;
            try { File.Delete(staged); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    private async Task WaitForTorAsync(CancellationToken token)
    {
        if (process is null || process.HasExited)
            throw new IOException("Tor wurde beendet. Schließe gegebenenfalls eine andere laufende MSG- oder Tor-Instanz mit demselben Profil.");
        await Task.Delay(300, token);
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
        ready = null;
        control?.Dispose();
        control = null;
        if (process is not null)
        {
            try
            {
                if (!process.WaitForExit(1000)) process.Kill(entireProcessTree: true);
                process.WaitForExit(1000);
            }
            catch (InvalidOperationException) { }
            catch (System.ComponentModel.Win32Exception) { }
            process.Dispose();
            process = null;
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
            scratch = null;
        }
        profileLock?.Dispose();
        profileLock = null;
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
