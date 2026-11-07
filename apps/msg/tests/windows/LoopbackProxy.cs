using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

// Test-only SOCKS bridge. Never included in the application build.
internal sealed class LoopbackProxy : IDisposable
{
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource stopped = new();
    internal HashSet<string> Hosts { get; } = new(StringComparer.Ordinal);
    internal int Port => ((IPEndPoint)listener.LocalEndpoint).Port;

    internal LoopbackProxy()
    {
        listener.Start();
        _ = Accept();
    }

    private async Task Accept()
    {
        try
        {
            while (!stopped.IsCancellationRequested)
                _ = Relay(await listener.AcceptTcpClientAsync(stopped.Token));
        }
        catch (Exception error) when (error is OperationCanceledException or SocketException or ObjectDisposedException) { }
    }

    private async Task Relay(TcpClient client)
    {
        using (client)
        {
            try
            {
                var stream = client.GetStream();
                byte[] greeting = new byte[3];
                await stream.ReadExactlyAsync(greeting, stopped.Token);
                if (!greeting.SequenceEqual(new byte[] { 5, 1, 0 })) return;
                await stream.WriteAsync(new byte[] { 5, 0 }, stopped.Token);
                byte[] request = new byte[5];
                await stream.ReadExactlyAsync(request, stopped.Token);
                if (!request.AsSpan(0, 4).SequenceEqual(new byte[] { 5, 1, 0, 3 })) return;
                byte[] target = new byte[request[4] + 2];
                await stream.ReadExactlyAsync(target, stopped.Token);
                string host = Encoding.ASCII.GetString(target, 0, request[4]);
                int port = (target[^2] << 8) | target[^1];
                if (!Hosts.Contains(host) || port is not (49424 or 49426)) return;
                using var remote = new TcpClient();
                try { await remote.ConnectAsync(IPAddress.Loopback, port, stopped.Token); }
                catch (SocketException)
                {
                    await stream.WriteAsync(new byte[] { 5, 5, 0, 1, 127, 0, 0, 1, 0, 0 }, stopped.Token);
                    return;
                }
                await stream.WriteAsync(new byte[] { 5, 0, 0, 1, 127, 0, 0, 1, 0, 0 }, stopped.Token);
                using var connection = CancellationTokenSource.CreateLinkedTokenSource(stopped.Token);
                Task outgoing = stream.CopyToAsync(remote.GetStream(), connection.Token);
                Task incoming = remote.GetStream().CopyToAsync(stream, connection.Token);
                await Task.WhenAny(outgoing, incoming);
                connection.Cancel();
                await Task.WhenAll(outgoing, incoming);
            }
            catch (Exception error) when (error is IOException or SocketException or OperationCanceledException or ObjectDisposedException) { }
        }
    }

    public void Dispose()
    {
        stopped.Cancel();
        listener.Stop();
    }
}
