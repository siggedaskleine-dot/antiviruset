using MattesAntivirus.Core.Quarantine;

namespace MattesAntivirus.Core.Tests;

public class QuarantineStoreTests
{
    [Fact]
    public void MovesFileIntoQuarantineAndRestoresIt()
    {
        using var dir = new TempDirectory();
        var infected = dir.WriteFile("bad.exe", TestData.FakeMalware);
        var store = new QuarantineStore(Path.Combine(dir.Path, "q"));

        var entry = store.Add(new Detection(infected, "Test.Malware", "Hash", TestData.Sha256(TestData.FakeMalware)));

        Assert.False(File.Exists(infected));
        var stored = Assert.Single(Directory.GetFiles(store.Directory, "*.bin"));
        Assert.NotEqual(TestData.FakeMalware, File.ReadAllText(stored));
        Assert.Equal(entry, Assert.Single(store.List()));

        var restored = store.Restore(entry);

        Assert.Equal(infected, restored);
        Assert.Equal(TestData.FakeMalware, File.ReadAllText(infected));
        Assert.Empty(store.List());
        Assert.Empty(Directory.GetFiles(store.Directory));
    }

    [Fact]
    public void DeletesForGood()
    {
        using var dir = new TempDirectory();
        var infected = dir.WriteFile("bad.exe", TestData.FakeMalware);
        var store = new QuarantineStore(Path.Combine(dir.Path, "q"));
        var entry = store.Add(new Detection(infected, "Test.Malware", "Hash", ""));

        store.Delete(entry);

        Assert.Empty(store.List());
        Assert.False(File.Exists(infected));
        Assert.Empty(Directory.GetFiles(store.Directory));
    }

    [Fact]
    public void RestoreDoesNotOverwriteExistingFile()
    {
        using var dir = new TempDirectory();
        var infected = dir.WriteFile("bad.exe", TestData.FakeMalware);
        var store = new QuarantineStore(Path.Combine(dir.Path, "q"));
        var entry = store.Add(new Detection(infected, "Test.Malware", "Hash", ""));
        File.WriteAllText(infected, "new file");

        Assert.Throws<IOException>(() => store.Restore(entry));
        Assert.Equal("new file", File.ReadAllText(infected));
        Assert.Single(store.List());
    }

    [Fact]
    public void FindsEntriesByIdPrefix()
    {
        using var dir = new TempDirectory();
        var store = new QuarantineStore(Path.Combine(dir.Path, "q"));
        var entry = store.Add(new Detection(dir.WriteFile("bad.exe", TestData.FakeMalware), "Test.Malware", "Hash", ""));

        Assert.Equal(entry, store.Find(entry.Id[..8]));
        Assert.Null(store.Find("zzzz"));
    }

    [Fact]
    public void EmptyWhenDirectoryIsMissing()
    {
        using var dir = new TempDirectory();
        Assert.Empty(new QuarantineStore(Path.Combine(dir.Path, "missing")).List());
    }
}
