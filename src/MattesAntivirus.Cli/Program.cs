using System.Text;
using MattesAntivirus.Core;
using MattesAntivirus.Core.Quarantine;

Console.OutputEncoding = Encoding.UTF8;

var arguments = args.ToList();
var paths = AppPaths.Default;
var dataIndex = arguments.IndexOf("--data");
if (dataIndex >= 0 && dataIndex + 1 < arguments.Count)
{
    paths = new AppPaths(Path.GetFullPath(arguments[dataIndex + 1]));
    arguments.RemoveRange(dataIndex, 2);
}

try
{
    return arguments.FirstOrDefault()?.ToLowerInvariant() switch
    {
        "scan" => Scan(arguments.Skip(1).ToList()),
        "quarantine" => QuarantineCommand(arguments.Skip(1).ToList()),
        "info" => Info(),
        _ => Usage(),
    };
}
catch (Exception e) when (e is IOException or UnauthorizedAccessException)
{
    Console.Error.WriteLine($"Fel: {e.Message}");
    return 2;
}

int Usage()
{
    Console.WriteLine("""
        Mattes Antivirus

        Användning:
          mattes-av scan <fil eller mapp>... [--quarantine]
          mattes-av scan --quick [--quarantine]     Snabbskanning av vanliga platser för malware
          mattes-av scan --full [--quarantine]      Skanna alla hårddiskar
          mattes-av quarantine list
          mattes-av quarantine restore <id>
          mattes-av quarantine delete <id>
          mattes-av info

        Flaggor:
          --data <mapp>    Använd en annan datamapp än %ProgramData%\MattesAntivirus

        Avslutningskod: 0 = inga hot, 1 = hot hittades, 2 = fel
        """);
    return 2;
}

int Info()
{
    using var engines = EngineSet.Load(paths);
    Console.WriteLine($"Datamapp:       {paths.DataDirectory}");
    Console.WriteLine($"Hash-signaturer: {engines.Hashes.Count}");
    Console.WriteLine(engines.Yara is { } yara ? $"YARA-regler:     {yara.RuleCount}" : $"YARA:            ej tillgänglig ({engines.YaraError})");
    Console.WriteLine($"I karantän:     {new QuarantineStore(paths.QuarantineDirectory).List().Count}");
    return 0;
}

int Scan(List<string> options)
{
    var quarantine = options.Remove("--quarantine");
    List<string> targets;
    if (options.Remove("--quick"))
        targets = [.. ScanLocations.QuickScan()];
    else if (options.Remove("--full"))
        targets = [.. ScanLocations.FullScan()];
    else
        targets = options;

    if (targets.Count == 0 || targets.Any(t => t.StartsWith("--", StringComparison.Ordinal)))
        return Usage();

    using var engines = EngineSet.Load(paths);
    if (engines.YaraError is not null)
        Console.Error.WriteLine($"Varning: {engines.YaraError} Skannar bara med hash-signaturer.");

    Console.WriteLine($"Skannar {string.Join(", ", targets)}");
    using var cancellation = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) =>
    {
        e.Cancel = true;
        cancellation.Cancel();
    };

    var lastReport = DateTime.MinValue;
    var progress = new Progress<ScanProgress>(p =>
    {
        if (Console.IsOutputRedirected || (DateTime.UtcNow - lastReport).TotalMilliseconds < 250)
            return;
        lastReport = DateTime.UtcNow;
        Console.Write($"\r{p.FilesScanned} filer skannade, {p.ThreatsFound} hot   ");
    });

    var report = engines.CreateScanner(paths).Scan(targets, progress, cancellation.Token);
    if (!Console.IsOutputRedirected)
        Console.Write("\r" + new string(' ', 60) + "\r");

    foreach (var detection in report.Detections)
        Console.WriteLine($"HOT: {detection.ThreatName}  ({detection.Engine})  {detection.FilePath}");

    if (quarantine)
    {
        var store = new QuarantineStore(paths.QuarantineDirectory);
        foreach (var file in report.Detections.GroupBy(d => d.FilePath, StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var entry = store.Add(file.First());
                Console.WriteLine($"Flyttad till karantän ({entry.Id[..8]}): {file.Key}");
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                Console.Error.WriteLine($"Kunde inte flytta {file.Key} till karantän: {e.Message}");
            }
        }
    }

    Console.WriteLine();
    Console.WriteLine(report.Cancelled ? "Skanningen avbröts." : "Skanningen är klar.");
    Console.WriteLine($"Skannade filer: {report.FilesScanned}, överhoppade: {report.FilesSkipped}, hot: {report.Detections.Count}, tid: {report.Duration:hh\\:mm\\:ss}");
    if (report.Errors.Count > 0)
    {
        Console.WriteLine($"{report.Errors.Count} filer kunde inte läsas (till exempel låsta systemfiler):");
        foreach (var error in report.Errors.Take(5))
            Console.WriteLine($"  {error}");
    }

    return report.Detections.Count > 0 ? 1 : 0;
}

int QuarantineCommand(List<string> options)
{
    var store = new QuarantineStore(paths.QuarantineDirectory);
    switch (options.FirstOrDefault()?.ToLowerInvariant())
    {
        case "list":
            var entries = store.List();
            if (entries.Count == 0)
                Console.WriteLine("Karantänen är tom.");
            foreach (var e in entries)
                Console.WriteLine($"{e.Id[..8]}  {e.QuarantinedAt:yyyy-MM-dd HH:mm}  {e.ThreatName}  {e.OriginalPath}");
            return 0;

        case "restore" when options.Count == 2:
            if (store.Find(options[1]) is not { } restoreEntry)
                return NotFound(options[1]);
            Console.WriteLine($"Återställd: {store.Restore(restoreEntry)}");
            return 0;

        case "delete" when options.Count == 2:
            if (store.Find(options[1]) is not { } deleteEntry)
                return NotFound(options[1]);
            store.Delete(deleteEntry);
            Console.WriteLine($"Raderad för gott: {deleteEntry.OriginalPath}");
            return 0;

        default:
            return Usage();
    }
}

static int NotFound(string id)
{
    Console.Error.WriteLine($"Hittade ingen enskild post i karantänen med id {id}.");
    return 2;
}
