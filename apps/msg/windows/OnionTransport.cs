namespace KryptoCore.Desktop;

internal sealed record OnionEndpoint(int SocksPort, string OnionAddress)
{
    internal const int ChatPort = 49424;
}

internal sealed record OnionIdentity(string Path, string PublicKey, Func<byte[]> PasswordBytes);

// The window needs an onion address and a loopback SOCKS endpoint for the
// worker. Process startup, control authentication and storage belong here.
internal interface IOnionTransport
{
    Task<OnionEndpoint> StartAsync(OnionIdentity identity, Action<int>? onProgress, CancellationToken cancellation);
    Task<OnionEndpoint> RotateAsync(OnionIdentity identity, CancellationToken cancellation);
    Task<OnionEndpoint> ImportLegacyAsync(OnionIdentity identity, CancellationToken cancellation);
    bool HasLegacyKey { get; }

    // Stop publication and cancel any startup for the previous identity.
    void Stop();
}
