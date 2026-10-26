using System.Text;
using MattesAntivirus.Core.Engines;

namespace MattesAntivirus.Core.Tests;

/// <summary>The bundled YARA library is Windows-only, so these tests only run on Windows.</summary>
public class YaraEngineTests
{
    private const string TestRule = """
        rule Test_Rule
        {
            meta:
                threat_name = "Test.Yara"
            strings:
                $a = "test sample 7f3c9e"
            condition:
                $a
        }

        rule Rule_Without_Name
        {
            strings:
                $a = "Mattes Antivirus"
            condition:
                $a
        }
        """;

    [Fact]
    public void MatchesContentAndUsesThreatNameMeta()
    {
        if (!OperatingSystem.IsWindows())
            return;

        using var engine = YaraEngine.FromSource(TestRule);
        var detections = engine.Inspect("file.exe", "hash", Encoding.UTF8.GetBytes(TestData.FakeMalware)).ToList();

        Assert.Equal(["Rule_Without_Name", "Test.Yara"], detections.Select(d => d.ThreatName).Order());
        Assert.All(detections, d => Assert.Equal("YARA", d.Engine));
    }

    [Fact]
    public void IgnoresCleanContent()
    {
        if (!OperatingSystem.IsWindows())
            return;

        using var engine = YaraEngine.FromSource(TestRule);
        Assert.Empty(engine.Inspect("file.txt", "hash", Encoding.UTF8.GetBytes("hello")));
        Assert.Empty(engine.Inspect("big.bin", "hash", null));
    }

    [Fact]
    public void ReportsInvalidRules()
    {
        if (!OperatingSystem.IsWindows())
            return;

        Assert.Throws<YaraLoadException>(() => YaraEngine.FromSource("rule Broken { condition: }"));
    }

    [Fact]
    public void BundledRulesCompileAndRecogniseEicar()
    {
        if (!OperatingSystem.IsWindows())
            return;

        using var engine = YaraEngine.LoadDirectories(AppPaths.BundledRulesDirectory);

        Assert.True(engine.RuleCount >= 2);
        var detection = Assert.Single(engine.Inspect("eicar.com", "hash", TestData.Eicar));
        Assert.Equal("EICAR-Test-File", detection.ThreatName);
    }

    [Fact]
    public void ReportsMissingLibraryOnOtherSystems()
    {
        if (OperatingSystem.IsWindows())
            return;

        Assert.Throws<YaraLoadException>(() => YaraEngine.FromSource(TestRule));
    }
}
