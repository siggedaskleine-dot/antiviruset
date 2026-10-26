using System.Text.Json;

namespace MattesAntivirus.Core;

public sealed record ScanSummary(DateTimeOffset FinishedAt, string ScanType, long FilesScanned, int ThreatsFound, bool Cancelled);

/// <summary>Remembers the latest scan so the program can show when the computer was last checked.</summary>
public sealed class ScanHistory(string filePath)
{
    public static ScanHistory For(AppPaths paths) => new(Path.Combine(paths.DataDirectory, "last-scan.json"));

    public ScanSummary? Load()
    {
        try
        {
            return File.Exists(filePath) ? JsonSerializer.Deserialize<ScanSummary>(File.ReadAllText(filePath)) : null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    public void Save(ScanSummary summary)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(filePath)!);
        File.WriteAllText(filePath, JsonSerializer.Serialize(summary));
    }
}
