namespace MattesAntivirus.Core.Engines;

/// <summary>
/// A detection engine inspects one file at a time. The scanner reads the file once and hands
/// every engine the hash and, when the file is small enough, its full content.
/// </summary>
public interface IDetectionEngine
{
    string Name { get; }

    /// <param name="content">The file's bytes, or null when the file is too large to load into memory.</param>
    IEnumerable<Detection> Inspect(string filePath, string sha256, byte[]? content);
}
