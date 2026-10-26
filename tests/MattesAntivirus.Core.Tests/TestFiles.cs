using System.Security.Cryptography;
using System.Text;

namespace MattesAntivirus.Core.Tests;

/// <summary>A temporary directory that is removed after the test.</summary>
internal sealed class TempDirectory : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "mattes-av-tests", Guid.NewGuid().ToString("N"));

    public TempDirectory() => Directory.CreateDirectory(Path);

    public string WriteFile(string relativePath, string content)
    {
        var path = System.IO.Path.Combine(Path, relativePath);
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
        return path;
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (IOException)
        {
        }
    }
}

internal static class TestData
{
    /// <summary>Harmless content standing in for malware in tests.</summary>
    public const string FakeMalware = "Mattes Antivirus test sample 7f3c9e";

    /// <summary>
    /// The EICAR test string, assembled at runtime and only kept in memory so no antivirus on the
    /// build machine removes files from the repository or test run.
    /// </summary>
    public static byte[] Eicar => Encoding.ASCII.GetBytes("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

    public static string Sha256(string content) => Sha256(Encoding.UTF8.GetBytes(content));

    public static string Sha256(byte[] content) => Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
}
