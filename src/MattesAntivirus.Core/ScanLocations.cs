namespace MattesAntivirus.Core;

/// <summary>The folders covered by the predefined scan types.</summary>
public static class ScanLocations
{
    /// <summary>Places where malware usually lands or starts from.</summary>
    public static IReadOnlyList<string> QuickScan()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var candidates = new[]
        {
            Path.Combine(home, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        };
        return candidates
            .Where(p => !string.IsNullOrEmpty(p) && Directory.Exists(p))
            .Select(p => Path.TrimEndingDirectorySeparator(Path.GetFullPath(p)))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>Every fixed drive on the computer.</summary>
    public static IReadOnlyList<string> FullScan() =>
        DriveInfo.GetDrives()
            .Where(d => d.DriveType == DriveType.Fixed && d.IsReady)
            .Select(d => d.RootDirectory.FullName)
            .ToList();
}
