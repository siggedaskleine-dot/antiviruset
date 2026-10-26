using MattesAntivirus.Core.Engines;

namespace MattesAntivirus.Core.Tests;

public class HashSignatureDatabaseTests
{
    private const string Hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    [Fact]
    public void ReadsHashesWithAndWithoutNames()
    {
        var database = new HashSignatureDatabase();
        database.AddLine(Hash + ";Trojan.Test");
        database.AddLine("  BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB  ");

        Assert.Equal(2, database.Count);
        Assert.True(database.TryMatch(Hash, out var named));
        Assert.Equal("Trojan.Test", named);
        Assert.True(database.TryMatch(new string('b', 64), out var unnamed));
        Assert.Equal(HashSignatureDatabase.DefaultThreatName, unnamed);
    }

    [Theory]
    [InlineData("")]
    [InlineData("# comment " + Hash)]
    [InlineData("not a hash")]
    [InlineData("abc123")]
    [InlineData("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")]
    public void IgnoresCommentsAndInvalidLines(string line)
    {
        var database = new HashSignatureDatabase();
        database.AddLine(line);
        Assert.Equal(0, database.Count);
    }

    [Fact]
    public void ReadsQuotedCsvLines()
    {
        var database = new HashSignatureDatabase();
        database.AddLine($"\"{Hash}\",\"Ransom.Test\"");
        Assert.True(database.TryMatch(Hash, out var name));
        Assert.Equal("Ransom.Test", name);
    }

    [Fact]
    public void LoadsAllTextFilesFromDirectories()
    {
        using var first = new TempDirectory();
        using var second = new TempDirectory();
        first.WriteFile("a.txt", Hash + "\n# comment\n");
        second.WriteFile("b.txt", new string('c', 64));
        second.WriteFile("ignored.md", new string('d', 64));

        var database = HashSignatureDatabase.LoadDirectories(first.Path, second.Path, Path.Combine(second.Path, "missing"));

        Assert.Equal(2, database.Count);
    }

    [Fact]
    public void BundledSignaturesRecogniseEicar()
    {
        var database = HashSignatureDatabase.LoadDirectories(AppPaths.BundledSignaturesDirectory);

        Assert.True(database.TryMatch(TestData.Sha256(TestData.Eicar), out var name));
        Assert.Equal("EICAR-Test-File", name);
    }
}
