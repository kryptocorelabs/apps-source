using System.Diagnostics.CodeAnalysis;
using System.IO;

namespace KryptoCore.Desktop;

internal static class ExecutableContainer
{
    [UnconditionalSuppressMessage("SingleFile", "IL3000", Justification =
        "An empty Assembly.Location deliberately detects the published single-file build.")]
    internal static string? OpenerPath => typeof(ExecutableContainer).Assembly.Location.Length == 0
        ? Environment.ProcessPath : null;

    internal static string? CurrentArchive()
    {
        if (OpenerPath is not { } path) return null;
        try
        {
            using var file = File.OpenRead(path);
            Span<byte> marker = stackalloc byte[16];
            if (file.Length < 24) return null;
            file.Seek(-marker.Length, SeekOrigin.End);
            file.ReadExactly(marker);
            return marker.SequenceEqual("KCC-WIN64-EXE-v1"u8) ? path : null;
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }
}
