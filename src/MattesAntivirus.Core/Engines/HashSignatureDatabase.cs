namespace MattesAntivirus.Core.Engines;

/// <summary>
/// Matches files against SHA-256 hashes of known malware.
/// Signature files are plain text with one entry per line: <c>sha256</c> or <c>sha256;ThreatName</c>.
/// Lines starting with <c>#</c> are comments, which also makes MalwareBazaar's hash exports load as-is.
/// </summary>
public sealed class HashSignatureDatabase : IDetectionEngine
{
    public const string DefaultThreatName = "Malware.KnownHash";

    private readonly Dictionary<string, string?> _signatures = new(StringComparer.OrdinalIgnoreCase);

    public string Name => "Hash";

    public int Count => _signatures.Count;

    public static HashSignatureDatabase LoadDirectories(params string[] directories)
    {
        var database = new HashSignatureDatabase();
        foreach (var directory in directories.Where(Directory.Exists))
        {
            foreach (var file in Directory.EnumerateFiles(directory, "*.txt").Order(StringComparer.Ordinal))
                database.LoadFile(file);
        }
        return database;
    }

    public void LoadFile(string path)
    {
        foreach (var line in File.ReadLines(path))
            AddLine(line);
    }

    public void AddLine(string line)
    {
        var span = line.AsSpan().Trim();
        if (span.IsEmpty || span[0] == '#')
            return;

        var separator = span.IndexOfAny(';', ',');
        var hash = (separator < 0 ? span : span[..separator]).Trim().Trim('"');
        if (!IsSha256(hash))
            return;

        string? name = null;
        if (separator >= 0)
        {
            var rest = span[(separator + 1)..].Trim().Trim('"');
            if (!rest.IsEmpty)
                name = rest.ToString();
        }
        Add(hash.ToString(), name);
    }

    public void Add(string sha256, string? threatName = null)
    {
        if (!IsSha256(sha256))
            throw new ArgumentException("Not a SHA-256 hash.", nameof(sha256));
        _signatures[sha256] = threatName;
    }

    public bool TryMatch(string sha256, out string threatName)
    {
        if (_signatures.TryGetValue(sha256, out var name))
        {
            threatName = name ?? DefaultThreatName;
            return true;
        }
        threatName = "";
        return false;
    }

    public IEnumerable<Detection> Inspect(string filePath, string sha256, byte[]? content)
    {
        if (TryMatch(sha256, out var threatName))
            yield return new Detection(filePath, threatName, Name, sha256);
    }

    private static bool IsSha256(ReadOnlySpan<char> value)
    {
        if (value.Length != 64)
            return false;
        foreach (var c in value)
        {
            if (!char.IsAsciiHexDigit(c))
                return false;
        }
        return true;
    }
}
