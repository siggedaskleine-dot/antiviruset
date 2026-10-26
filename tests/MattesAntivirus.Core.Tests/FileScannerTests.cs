using MattesAntivirus.Core.Engines;

namespace MattesAntivirus.Core.Tests;

public class FileScannerTests
{
    private static FileScanner CreateScanner(ScanOptions? options = null)
    {
        var database = new HashSignatureDatabase();
        database.Add(TestData.Sha256(TestData.FakeMalware), "Test.Malware");
        return new FileScanner([database], options);
    }

    [Fact]
    public void FindsMalwareInSubdirectories()
    {
        using var dir = new TempDirectory();
        dir.WriteFile("clean.txt", "hello");
        var infected = dir.WriteFile(Path.Combine("deep", "er", "bad.exe"), TestData.FakeMalware);

        var report = CreateScanner().Scan([dir.Path]);

        var detection = Assert.Single(report.Detections);
        Assert.Equal(infected, detection.FilePath);
        Assert.Equal("Test.Malware", detection.ThreatName);
        Assert.Equal("Hash", detection.Engine);
        Assert.Equal(2, report.FilesScanned);
        Assert.False(report.Cancelled);
    }

    [Fact]
    public void ScansSingleFiles()
    {
        using var dir = new TempDirectory();
        var infected = dir.WriteFile("bad.exe", TestData.FakeMalware);

        var report = CreateScanner().Scan([infected]);

        Assert.Single(report.Detections);
    }

    [Fact]
    public void ReportsMissingPaths()
    {
        using var dir = new TempDirectory();

        var report = CreateScanner().Scan([Path.Combine(dir.Path, "missing")]);

        Assert.Empty(report.Detections);
        Assert.Single(report.Errors);
    }

    [Fact]
    public void SkipsExcludedDirectories()
    {
        using var dir = new TempDirectory();
        dir.WriteFile(Path.Combine("quarantine", "bad.exe"), TestData.FakeMalware);
        var infected = dir.WriteFile(Path.Combine("quarantine-other", "bad.exe"), TestData.FakeMalware);

        var report = CreateScanner(new ScanOptions { ExcludedDirectories = [Path.Combine(dir.Path, "quarantine")] }).Scan([dir.Path]);

        Assert.Equal(infected, Assert.Single(report.Detections).FilePath);
    }

    [Fact]
    public void SkipsFilesAboveSizeLimit()
    {
        using var dir = new TempDirectory();
        dir.WriteFile("bad.exe", TestData.FakeMalware);

        var report = CreateScanner(new ScanOptions { MaxFileBytes = 4 }).Scan([dir.Path]);

        Assert.Empty(report.Detections);
        Assert.Equal(1, report.FilesSkipped);
    }

    [Fact]
    public void HashesLargeFilesWithoutLoadingContent()
    {
        using var dir = new TempDirectory();
        dir.WriteFile("bad.exe", TestData.FakeMalware);
        var engine = new RecordingEngine();

        new FileScanner([engine], new ScanOptions { MaxContentScanBytes = 4 }).Scan([dir.Path]);

        var call = Assert.Single(engine.Calls);
        Assert.Equal(TestData.Sha256(TestData.FakeMalware), call.Sha256);
        Assert.Null(call.Content);
    }

    [Fact]
    public void StopsWhenCancelled()
    {
        using var dir = new TempDirectory();
        dir.WriteFile("a.txt", "a");
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        var report = CreateScanner().Scan([dir.Path], cancellationToken: cancellation.Token);

        Assert.True(report.Cancelled);
    }

    private sealed class RecordingEngine : IDetectionEngine
    {
        public List<(string Sha256, byte[]? Content)> Calls { get; } = [];

        public string Name => "Recording";

        public IEnumerable<Detection> Inspect(string filePath, string sha256, byte[]? content)
        {
            lock (Calls)
                Calls.Add((sha256, content));
            return [];
        }
    }
}
