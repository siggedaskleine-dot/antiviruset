using MattesAntivirus.Core.Engines;

namespace MattesAntivirus.Core;

/// <summary>The detection engines loaded from the bundled and downloaded signatures and rules.</summary>
public sealed class EngineSet : IDisposable
{
    private EngineSet(HashSignatureDatabase hashes, YaraEngine? yara, string? yaraError)
    {
        Hashes = hashes;
        Yara = yara;
        YaraError = yaraError;
        Engines = yara is null ? [hashes] : [hashes, yara];
    }

    public HashSignatureDatabase Hashes { get; }

    /// <summary>Null when the YARA rules could not be loaded; <see cref="YaraError"/> says why.</summary>
    public YaraEngine? Yara { get; }

    public string? YaraError { get; }

    public IReadOnlyList<IDetectionEngine> Engines { get; }

    public static EngineSet Load(AppPaths paths)
    {
        var hashes = HashSignatureDatabase.LoadDirectories(AppPaths.BundledSignaturesDirectory, paths.SignaturesDirectory);
        try
        {
            return new EngineSet(hashes, YaraEngine.LoadDirectories(AppPaths.BundledRulesDirectory, paths.RulesDirectory), null);
        }
        catch (YaraLoadException e)
        {
            return new EngineSet(hashes, null, e.Message);
        }
    }

    /// <summary>A scanner that leaves the program's own files and quarantine alone.</summary>
    public FileScanner CreateScanner(AppPaths paths) =>
        new(Engines, new ScanOptions { ExcludedDirectories = [paths.DataDirectory, AppContext.BaseDirectory] });

    public void Dispose() => Yara?.Dispose();
}
