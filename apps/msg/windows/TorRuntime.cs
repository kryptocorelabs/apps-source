using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
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
            scratch = Directory.CreateTempSubdirectory("kryptocore-tor-");
            string binary = Path.Combine(scratch.FullName, "tor.exe");
            string config = Path.Combine(scratch.FullName, "torrc");
            string portFile = Path.Combine(scratch.FullName, "control-port");
            string cookieFile = Path.Combine(scratch.FullName, "control-cookie");
            string data = Directory.CreateDirectory(Path.Combine(profile, "tor-data")).FullName;
            string service = Path.Combine(profile, pendingService ?? ReadActiveService());
            string hostname = Path.Combine(service, "hostname");
            await ExtractAsync(binary, token);
            await File.WriteAllTextAsync(config, "# Dedicated KryptoCore MSG instance\n", token);

            var start = new ProcessStartInfo(binary)
            {
                UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = scratch.FullName,
                RedirectStandardOutput = true, RedirectStandardError = true
            };
            foreach (string argument in new[]
            {
                "-f", config, "--DataDirectory", data, "--HiddenServiceDir", service,
                "--HiddenServicePort", $"{OnionEndpoint.ChatPort} 127.0.0.1:{OnionEndpoint.ChatPort}",
                "--HiddenServicePort", $"{PresencePort} 127.0.0.1:{PresencePort}",
                "--HiddenServicePort", $"{ContactRequestPort} 127.0.0.1:{ContactRequestPort}",
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
            process = Process.Start(start) ?? throw new IOException("Tor konnte nicht gestartet werden.");
            _ = process.StandardOutput.BaseStream.CopyToAsync(Stream.Null);
            _ = process.StandardError.BaseStream.CopyToAsync(Stream.Null);

            while (!File.Exists(portFile) || !File.Exists(cookieFile))
                await WaitForTorAsync(token);
            string published = (await File.ReadAllTextAsync(portFile, token)).Trim();
            if (!published.StartsWith("PORT=", StringComparison.Ordinal)
                || !TryLocalPort(published[5..], out int controlPort))
                throw new IOException("Tor hat keinen lokalen Steuerport gemeldet.");
            control = await ControlConnection.OpenAsync(controlPort, cookieFile, token);
            while (true)
            {
                var values = await control.CommandAsync("GETINFO net/listeners/socks status/bootstrap-phase", token);
                var match = Bootstrap.Match(values.GetValueOrDefault("status/bootstrap-phase") ?? "");
                if (match.Success)
                    percentage = int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture);
                onProgress?.Invoke(percentage);
                if ((!connectToNetwork || percentage == 100) && File.Exists(hostname))
                {
                    string onion = (await File.ReadAllTextAsync(hostname, token)).Trim();
                    if (!IsHostname(onion))
                        throw new IOException("Tor hat keine gültige Onion-Adresse erzeugt.");
                    int port = FindSocksPort(values.GetValueOrDefault("net/listeners/socks"));
                    if (port != 0 || !connectToNetwork)
                    {
                        ready = new OnionEndpoint(port, $"{onion}:{OnionEndpoint.ChatPort}");
                        return ready;
                    }
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

    private string ReadActiveService()
    {
        string name;
        try { name = File.ReadAllText(Path.Combine(profile, "onion-active")); }
        catch (FileNotFoundException) { return "onion"; }
        if (name.StartsWith("onion-", StringComparison.Ordinal) && Guid.TryParseExact(name[6..], "N", out _))
            return name;
        throw new IOException("Die gespeicherte Auswahl der Tor-Adresse ist beschädigt.");
    }

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
                finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(cookie); }
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
            await client.GetStream().WriteAsync(Encoding.ASCII.GetBytes(command + "\r\n"), token);
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
