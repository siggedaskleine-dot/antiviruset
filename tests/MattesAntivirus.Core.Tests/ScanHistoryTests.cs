namespace MattesAntivirus.Core.Tests;

public class ScanHistoryTests
{
    [Fact]
    public void SavesAndLoadsLatestScan()
    {
        using var dir = new TempDirectory();
        var history = ScanHistory.For(new AppPaths(Path.Combine(dir.Path, "data")));
        Assert.Null(history.Load());

        var summary = new ScanSummary(DateTimeOffset.Now, "Snabbskanning", 42, 1, false);
        history.Save(summary);

        Assert.Equal(summary, history.Load());
    }

    [Fact]
    public void IgnoresDamagedFile()
    {
        using var dir = new TempDirectory();
        var file = dir.WriteFile("last-scan.json", "{ not json");
        Assert.Null(new ScanHistory(file).Load());
    }
}
