namespace MattesAntivirus.Core;

/// <summary>Where Mattes Antivirus keeps signatures, rules and quarantined files.</summary>
public sealed record AppPaths(string DataDirectory)
{
    public static AppPaths Default { get; } = new(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "MattesAntivirus"));

    public string SignaturesDirectory => Path.Combine(DataDirectory, "Signatures");

    public string RulesDirectory => Path.Combine(DataDirectory, "Rules");

    public string QuarantineDirectory => Path.Combine(DataDirectory, "Quarantine");

    /// <summary>Signatures and rules shipped next to the program.</summary>
    public static string BundledSignaturesDirectory => Path.Combine(AppContext.BaseDirectory, "signatures");

    public static string BundledRulesDirectory => Path.Combine(AppContext.BaseDirectory, "rules");
}
