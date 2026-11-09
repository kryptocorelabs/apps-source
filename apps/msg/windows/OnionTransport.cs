namespace KryptoCore.Desktop;

internal sealed record OnionEndpoint(int SocksPort, string OnionAddress)
{
    internal const int ChatPort = 49424;
}

// The window needs an onion address and a loopback SOCKS endpoint for the
// worker. Process startup, control authentication and storage belong here.
internal interface IOnionTransport
{
    Task<OnionEndpoint> StartAsync(Action<int>? onProgress, CancellationToken cancellation);
    Task<OnionEndpoint> RotateAsync(CancellationToken cancellation);

    // Stop the running transport. A later StartAsync may use the same profile.
    void Stop();
}
