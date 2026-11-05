using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows.Controls;

namespace KryptoCore.Desktop;

internal sealed record Reply(
    [property: JsonPropertyName("ok")] bool Ok,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("text")] string? Text,
    [property: JsonPropertyName("address")] string? Address,
    [property: JsonPropertyName("acknowledged")] bool? Acknowledged,
    [property: JsonPropertyName("saved_file")] string? SavedFile = null,
    [property: JsonPropertyName("ticket")] string? Ticket = null,
    [property: JsonPropertyName("two_codes")] bool? TwoCodes = null,
    [property: JsonPropertyName("invitation_index")] int? InvitationIndex = null);

internal static class Engine
{
    private const string BinaryName = "kryptocore-desktop-engine.exe";
    private static readonly Encoding Utf8 = new UTF8Encoding(false, true);

    internal static async Task<Reply> Call(object request, byte[]? first = null,
        byte[]? second = null, CancellationToken cancellation = default, Action<string>? onProgress = null,
        bool keepInputOpen = false) =>
        await Run(request, first, second, cancellation, onProgress, keepInputOpen, null, null);

    internal static Task<Reply> Chat(object request, byte[] password, CancellationToken cancellation,
        Action<JsonElement> onEvent, Action<Func<object, Task>> onInput) =>
        Run(request, password, null, cancellation, null, true, onEvent, onInput);

    private static async Task<Reply> Run(object request, byte[]? first, byte[]? second,
        CancellationToken cancellation, Action<string>? onProgress, bool keepInputOpen,
        Action<JsonElement>? onEvent, Action<Func<object, Task>>? onInput)
    {
        try
        {
            byte[] metadata = JsonSerializer.SerializeToUtf8Bytes(request);
            if (metadata.Length > 1024 * 1024 || first?.Length > 1024 || second?.Length > 4096)
                throw new ArgumentException("Die Eingabe ist zu lang.");

            using var worker = WorkerFile.Prepare();
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo(worker.Path)
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    StandardOutputEncoding = Utf8
                }
            };
            if (!process.Start())
                throw new IOException("Die Rust-Engine konnte nicht gestartet werden.");
            using var registration = cancellation.Register(() =>
            {
                try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
                catch (InvalidOperationException) { }
                catch (System.ComponentModel.Win32Exception) { }
            });
            Task<Reply?> output = onEvent is null
                ? ReadReply(process.StandardOutput, cancellation, onProgress)
                : ReadEvents(process.StandardOutput, cancellation, null, onEvent);
            // Drain external-tool diagnostics without retaining them.
            Task diagnostics = process.StandardError.BaseStream.CopyToAsync(Stream.Null);
            using Stream input = process.StandardInput.BaseStream;
            await Frame(input, metadata, cancellation);
            await Frame(input, first ?? [], cancellation);
            await Frame(input, second ?? [], cancellation);
            if (!keepInputOpen) input.Close();
            if (first is not null) CryptographicOperations.ZeroMemory(first);
            if (second is not null) CryptographicOperations.ZeroMemory(second);
            using var writes = new SemaphoreSlim(1);
            onInput?.Invoke(async command =>
            {
                byte[] data = JsonSerializer.SerializeToUtf8Bytes(command);
                try
                {
                    await writes.WaitAsync(cancellation);
                    try { await Frame(input, data, cancellation); }
                    finally { writes.Release(); }
                }
                finally { CryptographicOperations.ZeroMemory(data); }
            });
            await process.WaitForExitAsync();
            cancellation.ThrowIfCancellationRequested();
            await diagnostics;
            if (process.ExitCode != 0)
                throw new IOException("Die Rust-Engine hat den Vorgang abgebrochen.");
            return await output
                ?? throw new IOException("Die Rust-Engine hat keine Antwort geliefert.");
        }
        catch (IOException) when (cancellation.IsCancellationRequested)
        {
            throw new OperationCanceledException(cancellation);
        }
        finally
        {
            if (first is not null) CryptographicOperations.ZeroMemory(first);
            if (second is not null) CryptographicOperations.ZeroMemory(second);
        }
    }

    private static async Task<Reply?> ReadReply(StreamReader reader, CancellationToken cancellation,
        Action<string>? onProgress) => await ReadEvents(reader, cancellation, onProgress, null);

    private static async Task<Reply?> ReadEvents(StreamReader reader, CancellationToken cancellation,
        Action<string>? onProgress, Action<JsonElement>? onEvent)
    {
        while (await reader.ReadLineAsync() is { } line)
        {
            using var frame = JsonDocument.Parse(line);
            if (!frame.RootElement.TryGetProperty("event", out var value))
                return frame.RootElement.Deserialize<Reply>();
            if (cancellation.IsCancellationRequested) continue;
            onEvent?.Invoke(frame.RootElement);
            if (value.GetString() is { } status) onProgress?.Invoke(status);
        }
        return null;
    }

    private sealed class WorkerFile(string path, DirectoryInfo? directory = null) : IDisposable
    {
        public string Path { get; } = path;

        public static WorkerFile Prepare()
        {
            using var resource = typeof(Engine).Assembly.GetManifestResourceStream(BinaryName);
            if (resource is null)
            {
                string file = System.IO.Path.Combine(AppContext.BaseDirectory, BinaryName);
                if (!File.Exists(file)) throw new IOException("Die Rust-Engine fehlt. Baue die Desktop-App erneut.");
                return new WorkerFile(file);
            }

            var scratch = Directory.CreateTempSubdirectory("kryptocore-worker-");
            var worker = new WorkerFile(System.IO.Path.Combine(scratch.FullName, BinaryName), scratch);
            try
            {
                using var file = new FileStream(worker.Path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                resource.CopyTo(file);
                return worker;
            }
            catch
            {
                worker.Dispose();
                throw;
            }
        }

        public void Dispose()
        {
            if (directory is null) return;
            try
            {
                File.Delete(Path);
                directory.Delete();
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static async Task Frame(Stream output, byte[] data, CancellationToken cancellation)
    {
        var length = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(length, (uint)data.Length);
        await output.WriteAsync(length, cancellation);
        await output.WriteAsync(data, cancellation);
    }

    internal static byte[] TakePassword(PasswordBox box)
    {
        using var password = box.SecurePassword;
        box.Clear();
        return PasswordBytes(password);
    }

    internal static byte[] PasswordBytes(System.Security.SecureString password)
    {
        var chars = new char[password.Length];
        nint pointer = Marshal.SecureStringToGlobalAllocUnicode(password);
        try
        {
            Marshal.Copy(pointer, chars, 0, chars.Length);
            return Utf8.GetBytes(chars);
        }
        finally
        {
            Array.Clear(chars);
            Marshal.ZeroFreeGlobalAllocUnicode(pointer);
        }
    }

    internal static byte[] TextBytes(string text) => Utf8.GetBytes(text);

    internal static async Task<Reply> WithPassword(object request, PasswordBox password,
        PasswordBox? confirmation = null, string? message = null, CancellationToken cancellation = default,
        Action<string>? onProgress = null, bool keepInputOpen = false)
    {
        byte[] first = TakePassword(password);
        byte[]? second = null;
        try
        {
            if (first.Length == 0) throw new ArgumentException("Gib die Passphrase ein.");
            second = confirmation is not null ? TakePassword(confirmation)
                : message is not null ? TextBytes(message) : null;
            return await Call(request, first, second, cancellation, onProgress, keepInputOpen);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(first);
            if (second is not null) CryptographicOperations.ZeroMemory(second);
        }
    }
}
