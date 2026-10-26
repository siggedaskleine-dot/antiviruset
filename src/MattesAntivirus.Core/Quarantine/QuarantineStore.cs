using System.Text.Json;

namespace MattesAntivirus.Core.Quarantine;

public sealed record QuarantineEntry(
    string Id,
    string OriginalPath,
    string ThreatName,
    string Engine,
    string Sha256,
    DateTimeOffset QuarantinedAt);

/// <summary>
/// Moves infected files out of the way. The content is XOR-encoded on disk so it cannot be run
/// by accident and other antivirus programs don't flag the quarantine folder.
/// Each entry is a <c>{id}.bin</c> file with a <c>{id}.json</c> description next to it.
/// </summary>
public sealed class QuarantineStore(string directory)
{
    private const byte XorKey = 0x5A;

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public string Directory { get; } = directory;

    public QuarantineEntry Add(Detection detection)
    {
        System.IO.Directory.CreateDirectory(Directory);
        var entry = new QuarantineEntry(
            Guid.NewGuid().ToString("N"),
            Path.GetFullPath(detection.FilePath),
            detection.ThreatName,
            detection.Engine,
            detection.Sha256,
            DateTimeOffset.Now);

        var content = File.ReadAllBytes(entry.OriginalPath);
        Xor(content);
        File.WriteAllBytes(DataPath(entry.Id), content);
        try
        {
            File.Delete(entry.OriginalPath);
        }
        catch
        {
            // The original is still in place (for example locked by a running process), so don't keep a copy.
            File.Delete(DataPath(entry.Id));
            throw;
        }
        File.WriteAllText(MetadataPath(entry.Id), JsonSerializer.Serialize(entry, JsonOptions));
        return entry;
    }

    public IReadOnlyList<QuarantineEntry> List()
    {
        if (!System.IO.Directory.Exists(Directory))
            return [];

        var entries = new List<QuarantineEntry>();
        foreach (var file in System.IO.Directory.EnumerateFiles(Directory, "*.json"))
        {
            try
            {
                if (JsonSerializer.Deserialize<QuarantineEntry>(File.ReadAllText(file)) is { } entry && File.Exists(DataPath(entry.Id)))
                    entries.Add(entry);
            }
            catch (JsonException)
            {
                // Skip damaged descriptions instead of hiding every other entry.
            }
        }
        return entries.OrderByDescending(e => e.QuarantinedAt).ToList();
    }

    /// <summary>Finds an entry by its id or a unique start of it.</summary>
    public QuarantineEntry? Find(string id)
    {
        var matches = List().Where(e => e.Id.StartsWith(id, StringComparison.OrdinalIgnoreCase)).Take(2).ToList();
        return matches.Count == 1 ? matches[0] : null;
    }

    /// <summary>Puts the file back where it was found, or at <paramref name="targetPath"/> when given.</summary>
    public string Restore(QuarantineEntry entry, string? targetPath = null, bool overwrite = false)
    {
        var target = Path.GetFullPath(targetPath ?? entry.OriginalPath);
        if (File.Exists(target) && !overwrite)
            throw new IOException($"Filen finns redan: {target}");

        var content = File.ReadAllBytes(DataPath(entry.Id));
        Xor(content);
        System.IO.Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        File.WriteAllBytes(target, content);
        Remove(entry);
        return target;
    }

    /// <summary>Deletes the quarantined file for good.</summary>
    public void Delete(QuarantineEntry entry) => Remove(entry);

    private void Remove(QuarantineEntry entry)
    {
        File.Delete(DataPath(entry.Id));
        File.Delete(MetadataPath(entry.Id));
    }

    private string DataPath(string id) => Path.Combine(Directory, id + ".bin");

    private string MetadataPath(string id) => Path.Combine(Directory, id + ".json");

    private static void Xor(byte[] content)
    {
        for (var i = 0; i < content.Length; i++)
            content[i] ^= XorKey;
    }
}
