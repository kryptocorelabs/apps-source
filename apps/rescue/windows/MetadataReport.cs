using System.IO;
using System.Text;

namespace KryptoCore.Desktop;

internal static class MetadataReport
{
    internal static async Task Write(string target, string contents, CancellationToken cancellation)
    {
        target = Path.GetFullPath(target);
        string stage = Path.Combine(Path.GetDirectoryName(target)!, ".rescue-report-" + Guid.NewGuid().ToString("N") + ".tmp");
        bool owned = false;
        try
        {
            await using (var stream = new FileStream(stage, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                owned = true;
                await stream.WriteAsync(Encoding.UTF8.GetBytes(contents), cancellation);
                await stream.FlushAsync(cancellation);
                stream.Flush(flushToDisk: true);
            }
            cancellation.ThrowIfCancellationRequested();
            File.Move(stage, target, overwrite: false);
            owned = false;
        }
        finally
        {
            if (owned)
                try { File.Delete(stage); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }
}
