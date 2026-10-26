using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using MattesAntivirus.Core.Engines;

namespace MattesAntivirus.Core;

public sealed class ScanOptions
{
    /// <summary>Files larger than this are only checked by hash, not loaded into memory for content engines.</summary>
    public long MaxContentScanBytes { get; init; } = 64L * 1024 * 1024;

    /// <summary>Files larger than this are skipped entirely.</summary>
    public long MaxFileBytes { get; init; } = 1024L * 1024 * 1024;

    public int MaxDegreeOfParallelism { get; init; } = Math.Clamp(Environment.ProcessorCount, 1, 8);

    /// <summary>Directories that are never scanned, such as the program's own rules and quarantine.</summary>
    public IReadOnlyList<string> ExcludedDirectories { get; init; } = [];
}

public sealed record ScanProgress(long FilesScanned, int ThreatsFound, string? CurrentFile);

public sealed record ScanReport(
    IReadOnlyList<Detection> Detections,
    long FilesScanned,
    long FilesSkipped,
    IReadOnlyList<string> Errors,
    TimeSpan Duration,
    bool Cancelled);

/// <summary>Walks files and directories and runs every detection engine on each file.</summary>
public sealed class FileScanner(IReadOnlyList<IDetectionEngine> engines, ScanOptions? options = null)
{
    private const int MaxReportedErrors = 1000;

    private readonly ScanOptions _options = options ?? new ScanOptions();

    public ScanReport Scan(IEnumerable<string> paths, IProgress<ScanProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();
        var detections = new ConcurrentBag<Detection>();
        var errors = new ConcurrentQueue<string>();
        long scanned = 0, skipped = 0;
        var cancelled = false;

        try
        {
            Parallel.ForEach(
                EnumerateFiles(paths, errors).Where(f => !IsExcluded(f)),
                new ParallelOptions { MaxDegreeOfParallelism = _options.MaxDegreeOfParallelism, CancellationToken = cancellationToken },
                file =>
                {
                    var found = ScanFile(file, errors);
                    if (found is null)
                    {
                        Interlocked.Increment(ref skipped);
                        return;
                    }
                    foreach (var detection in found)
                        detections.Add(detection);
                    var count = Interlocked.Increment(ref scanned);
                    progress?.Report(new ScanProgress(count, detections.Count, file));
                });
        }
        catch (OperationCanceledException)
        {
            cancelled = true;
        }

        return new ScanReport(
            detections.OrderBy(d => d.FilePath, StringComparer.OrdinalIgnoreCase).ToList(),
            scanned,
            skipped,
            errors.ToList(),
            stopwatch.Elapsed,
            cancelled);
    }

    /// <summary>Scans a single file. Returns null when the file could not be read or was skipped.</summary>
    private List<Detection>? ScanFile(string path, ConcurrentQueue<string> errors)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1, FileOptions.SequentialScan);
            var length = stream.Length;
            if (length > _options.MaxFileBytes)
                return null;

            byte[]? content = null;
            string sha256;
            if (length <= _options.MaxContentScanBytes)
            {
                content = new byte[length];
                stream.ReadExactly(content);
                sha256 = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
            }
            else
            {
                sha256 = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
            }

            var found = new List<Detection>();
            foreach (var engine in engines)
                found.AddRange(engine.Inspect(path, sha256, content));
            return found;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            AddError(errors, $"{path}: {e.Message}");
            return null;
        }
    }

    private bool IsExcluded(string file)
    {
        foreach (var directory in _options.ExcludedDirectories)
        {
            var prefix = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory)) + Path.DirectorySeparatorChar;
            if (file.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static IEnumerable<string> EnumerateFiles(IEnumerable<string> paths, ConcurrentQueue<string> errors)
    {
        // Scan hidden and system files too, but don't follow junctions and symlinks (avoids loops and cloud-only placeholders).
        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint,
        };

        foreach (var path in paths)
        {
            if (File.Exists(path))
            {
                yield return Path.GetFullPath(path);
            }
            else if (Directory.Exists(path))
            {
                foreach (var file in Directory.EnumerateFiles(Path.GetFullPath(path), "*", options))
                    yield return file;
            }
            else
            {
                AddError(errors, $"{path}: Hittades inte.");
            }
        }
    }

    private static void AddError(ConcurrentQueue<string> errors, string message)
    {
        if (errors.Count < MaxReportedErrors)
            errors.Enqueue(message);
    }
}
