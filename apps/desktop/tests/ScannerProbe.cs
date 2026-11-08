using System.IO;

// Test-only process surrogate. Never shipped as a scanner or in an app package.
internal static class ScannerProbe
{
    internal static bool TryRun(string[] args)
    {
        if (args.Length == 0 || args[0] != "--recursive=yes") return false;
        string[] expected = ["--recursive=yes", "--alert-exceeds-max=yes", "--alert-encrypted=yes",
            "--max-filesize=100M", "--max-scansize=400M", "--max-dir-recursion=64",
            "--follow-dir-symlinks=0", "--follow-file-symlinks=0"];
        if (args.Length != 9 || !args.Take(8).SequenceEqual(expected)
            || !(File.Exists(args[^1]) || Directory.Exists(args[^1]))) { Environment.ExitCode = 2; return true; }
        if (Environment.GetEnvironmentVariable("KCV_TEST_SCAN_MARKER") is { Length: > 0 } marker)
            File.WriteAllText(marker, "Test scanner invoked");
        Environment.ExitCode = int.TryParse(Environment.GetEnvironmentVariable("KCV_TEST_SCAN_EXIT"), out int result) ? result : 2;
        return true;
    }
}
