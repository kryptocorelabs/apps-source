using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace KryptoCore.Desktop;

internal sealed class OnionKeyStore(string directory)
{
    private const int KeySize = 64;
    private const int LegacyHeaderSize = 32;
    private static readonly byte[] Entropy = "KryptoCore MSG onion key v1"u8.ToArray();
    private readonly string legacyPath = Path.Combine(directory, "hs_ed25519_secret_key");
    private readonly string protectedPath = Path.Combine(directory, "hs_ed25519_secret_key.dpapi");
    private readonly string importOwnerPath = Path.Combine(directory, "import-owner");

    internal static OnionKeyStore Active(string profile)
    {
        byte[]? selection = ReadFile(Path.Combine(profile, "onion-active"), 38);
        string name = selection is null ? "onion" : Encoding.ASCII.GetString(selection);
        if (!IsServiceName(name)) throw new IOException("Die gespeicherte Auswahl der Tor-Adresse ist beschädigt.");
        return new OnionKeyStore(Path.Combine(profile, name));
    }

    internal static bool HasLegacyKey(string profile)
    {
        try
        {
            var keys = Active(profile);
            return CheckPath(keys.protectedPath) || CheckPath(keys.legacyPath);
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }

    internal static void ProtectLegacyProfile(string profile, CancellationToken token)
    {
        foreach (string path in Directory.EnumerateDirectories(profile, "onion*"))
        {
            token.ThrowIfCancellationRequested();
            if (IsServiceName(Path.GetFileName(path))) new OnionKeyStore(path).MigrateRetiredKey();
        }
    }

    private static bool IsServiceName(string name) => name == "onion"
        || (name.StartsWith("onion-", StringComparison.Ordinal) && Guid.TryParseExact(name[6..], "N", out _));

    internal void CheckImportOwner(string identity)
    {
        CheckPath(directory);
        byte[]? recorded = ReadFile(importOwnerPath, 64);
        if (recorded is not null && !recorded.AsSpan().SequenceEqual(Encoding.ASCII.GetBytes(identity)))
            throw new IOException("Die Übernahme dieser früheren Tor-Adresse wurde mit einer anderen Identität begonnen.");
    }

    internal void ClaimImport(string identity)
    {
        CheckImportOwner(identity);
        if (!CheckPath(importOwnerPath)) WriteNewFile(importOwnerPath, Encoding.ASCII.GetBytes(identity));
    }

    internal void RetireImportedKey(byte[] key)
    {
        ProtectAndRetireLegacy(key);
        byte[] stored = ReadProtectedKey();
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(key, stored))
                throw new IOException("Die frühere Tor-Adresse hat sich geändert.");
            foreach (string name in new[] { "hostname", "hs_ed25519_public_key" })
            {
                string path = Path.Combine(directory, name);
                if (CheckPath(path)) File.Delete(path);
            }
            File.Delete(protectedPath);
            File.Delete(importOwnerPath);
        }
        finally { CryptographicOperations.ZeroMemory(stored); }
    }

    internal string? ReadLegacyAddress()
    {
        CheckPath(directory);
        string path = Path.Combine(directory, "hostname");
        byte[]? bytes = ReadFile(path, 64);
        if (bytes is null) return null;
        string address = Encoding.ASCII.GetString(bytes).Trim();
        if (!TorRuntime.IsHostname(address))
            throw new IOException("Die gespeicherte Tor-Adresse ist beschädigt.");
        return address;
    }

    internal byte[]? ReadKey()
    {
        CheckPath(directory);
        return CheckPath(protectedPath) ? ReadProtectedKey() : ReadLegacyKey();
    }

    private void MigrateRetiredKey()
    {
        CheckPath(directory);
        byte[]? key = ReadLegacyKey();
        if (key is null) return;
        try { ProtectAndRetireLegacy(key); }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    private void ProtectAndRetireLegacy(byte[] key)
    {
        CheckPath(directory);
        byte[]? legacy = ReadLegacyKey();
        try
        {
            if (legacy is not null && !CryptographicOperations.FixedTimeEquals(key, legacy))
                throw new IOException("Der alte und der geschützte Tor-Schlüssel stimmen nicht überein.");
            bool alreadyProtected = CheckPath(protectedPath);
            if (!alreadyProtected) WriteProtectedKey(key);
            if (alreadyProtected && legacy is null) return;

            byte[] saved = ReadProtectedKey();
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(key, saved))
                    throw new IOException("Der geschützte Tor-Schlüssel konnte nicht bestätigt werden.");
                if (legacy is not null) File.Delete(legacyPath);
            }
            finally { CryptographicOperations.ZeroMemory(saved); }
        }
        finally
        {
            if (legacy is not null) CryptographicOperations.ZeroMemory(legacy);
        }
    }

    internal static byte[] DecodeTorKey(string? value)
    {
        const string prefix = "ED25519-V3:";
        if (value is null || value.Length != prefix.Length + 88 || !value.StartsWith(prefix, StringComparison.Ordinal))
            throw new IOException("Tor hat keinen gültigen Onion-Schlüssel geliefert.");
        byte[] key = new byte[KeySize];
        if (Convert.TryFromBase64Chars(value.AsSpan(prefix.Length), key, out int count) && count == KeySize)
            return key;
        CryptographicOperations.ZeroMemory(key);
        throw new IOException("Tor hat keinen gültigen Onion-Schlüssel geliefert.");
    }

    private byte[]? ReadLegacyKey()
    {
        byte[]? bytes = ReadFile(legacyPath, LegacyHeaderSize + KeySize);
        if (bytes is null) return null;
        try
        {
            if (bytes.Length != LegacyHeaderSize + KeySize
                || !bytes.AsSpan(0, LegacyHeaderSize).SequenceEqual("== ed25519v1-secret: type0 ==\0\0\0"u8))
                throw new IOException("Der alte Tor-Schlüssel ist beschädigt.");
            return bytes.AsSpan(LegacyHeaderSize).ToArray();
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private byte[] ReadProtectedKey()
    {
        byte[] bytes = ReadFile(protectedPath, 4096)
            ?? throw new IOException("Der geschützte Tor-Schlüssel fehlt.");
        try
        {
            byte[] key = ProtectedData.Unprotect(bytes, Entropy, DataProtectionScope.CurrentUser);
            if (key.Length == KeySize) return key;
            CryptographicOperations.ZeroMemory(key);
            throw new IOException("Der geschützte Tor-Schlüssel ist beschädigt.");
        }
        catch (CryptographicException error)
        {
            throw new IOException("Windows konnte den Tor-Schlüssel mit diesem Benutzerprofil nicht öffnen.", error);
        }
    }

    private void WriteProtectedKey(byte[] key)
    {
        byte[] bytes;
        try { bytes = ProtectedData.Protect(key, Entropy, DataProtectionScope.CurrentUser); }
        catch (CryptographicException error)
        {
            throw new IOException("Windows konnte den Tor-Schlüssel nicht schützen.", error);
        }
        Directory.CreateDirectory(directory);
        WriteNewFile(protectedPath, bytes);
    }

    private void WriteNewFile(string destination, byte[] bytes)
    {
        string staged = Path.Combine(directory, $".key-{Guid.NewGuid():N}.tmp");
        bool created = false;
        try
        {
            using (var file = new FileStream(staged, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                created = true;
                file.Write(bytes);
                file.Flush(flushToDisk: true);
            }
            File.Move(staged, destination);
        }
        finally
        {
            if (created) File.Delete(staged);
        }
    }

    private static byte[]? ReadFile(string path, int maxLength)
    {
        if (!CheckPath(path)) return null;
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        long length = file.Length;
        if (length > maxLength) throw new IOException("Eine Tor-Profildatei überschreitet die erwartete Größe.");
        byte[] bytes = new byte[(int)length];
        try
        {
            file.ReadExactly(bytes);
            return bytes;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw;
        }
    }

    private static bool CheckPath(string path)
    {
        try
        {
            if (File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))
                throw new IOException("Verknüpfte Tor-Profildateien und -ordner werden nicht geöffnet.");
            return true;
        }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
    }
}
