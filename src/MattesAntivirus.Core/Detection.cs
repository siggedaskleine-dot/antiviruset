namespace MattesAntivirus.Core;

/// <summary>A threat found in a file by one of the detection engines.</summary>
public sealed record Detection(string FilePath, string ThreatName, string Engine, string Sha256);
