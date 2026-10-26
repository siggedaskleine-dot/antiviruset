using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MattesAntivirus.Core;

namespace MattesAntivirus.App.ViewModels;

public sealed partial class ScanViewModel(MainViewModel main) : PageViewModel("Skanning", "")
{
    private CancellationTokenSource? _cancellation;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CancelCommand))]
    [NotifyCanExecuteChangedFor(nameof(QuarantineSelectedCommand))]
    private bool _isScanning;

    [ObservableProperty]
    private bool _hasResults;

    [ObservableProperty]
    private string _scanTitle = "Ingen skanning pågår";

    [ObservableProperty]
    private string _statusText = "Starta en skanning från översikten.";

    [ObservableProperty]
    private long _filesScanned;

    [ObservableProperty]
    private int _threatsFound;

    [ObservableProperty]
    private string _currentFile = "";

    [ObservableProperty]
    private string _elapsed = "";

    public ObservableCollection<DetectionItem> Detections { get; } = [];

    public int UnhandledThreats => Detections.Count(d => !d.IsHandled);

    public async Task RunAsync(string scanType, IReadOnlyList<string> targets)
    {
        if (IsScanning)
            return;

        IsScanning = true;
        HasResults = false;
        ScanTitle = scanType;
        StatusText = "Laddar signaturer…";
        FilesScanned = 0;
        ThreatsFound = 0;
        CurrentFile = "";
        Elapsed = "";
        Detections.Clear();
        _cancellation = new CancellationTokenSource();

        var progress = new LatestProgress();
        var stopwatch = Stopwatch.StartNew();
        var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(200) };
        timer.Tick += (_, _) => ShowProgress(progress.Latest, stopwatch.Elapsed);

        try
        {
            var engines = await main.Engines;
            StatusText = "Skannar…";
            timer.Start();
            var token = _cancellation.Token;
            var report = await Task.Run(() => engines.CreateScanner(main.Paths).Scan(targets, progress, token));
            timer.Stop();
            ShowReport(scanType, report);
        }
        catch (Exception e)
        {
            StatusText = $"Skanningen misslyckades: {e.Message}";
        }
        finally
        {
            timer.Stop();
            IsScanning = false;
            _cancellation.Dispose();
            _cancellation = null;
            main.Home.UpdateStatus();
        }
    }

    private void ShowProgress(ScanProgress? progress, TimeSpan elapsed)
    {
        Elapsed = elapsed.ToString(@"hh\:mm\:ss");
        if (progress is null)
            return;
        FilesScanned = progress.FilesScanned;
        ThreatsFound = progress.ThreatsFound;
        CurrentFile = progress.CurrentFile ?? "";
    }

    private void ShowReport(string scanType, ScanReport report)
    {
        FilesScanned = report.FilesScanned;
        Elapsed = report.Duration.ToString(@"hh\:mm\:ss");
        CurrentFile = "";

        foreach (var file in report.Detections.GroupBy(d => d.FilePath, StringComparer.OrdinalIgnoreCase))
            Detections.Add(new DetectionItem(file.ToList()));
        ThreatsFound = Detections.Count;
        HasResults = true;
        QuarantineSelectedCommand.NotifyCanExecuteChanged();

        var unreadable = report.Errors.Count > 0 ? $" {report.Errors.Count} filer kunde inte läsas." : "";
        StatusText = (report.Cancelled, Detections.Count) switch
        {
            (true, _) => "Skanningen avbröts." + unreadable,
            (false, 0) => "Inga hot hittades." + unreadable,
            (false, 1) => "1 hot hittades. Flytta det till karantän så att det inte kan göra skada." + unreadable,
            (false, var n) => $"{n} hot hittades. Flytta dem till karantän så att de inte kan göra skada." + unreadable,
        };

        try
        {
            main.History.Save(new ScanSummary(DateTimeOffset.Now, scanType, report.FilesScanned, Detections.Count, report.Cancelled));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Not being able to remember the scan doesn't affect the result shown.
        }
    }

    private bool CanCancel() => IsScanning;

    [RelayCommand(CanExecute = nameof(CanCancel))]
    private void Cancel()
    {
        _cancellation?.Cancel();
        StatusText = "Avbryter…";
    }

    private bool CanQuarantineSelected() => !IsScanning && Detections.Any(d => !d.IsHandled);

    [RelayCommand(CanExecute = nameof(CanQuarantineSelected))]
    private async Task QuarantineSelected()
    {
        var items = Detections.Where(d => d.IsSelected && !d.IsHandled).ToList();
        foreach (var item in items)
        {
            try
            {
                await Task.Run(() => main.QuarantineStore.Add(item.Detections[0]));
                item.IsHandled = true;
                item.IsSelected = false;
                item.Status = "I karantän";
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                item.Status = e is UnauthorizedAccessException
                    ? "Nekad: starta programmet som administratör"
                    : $"Fel: {e.Message}";
            }
        }

        QuarantineSelectedCommand.NotifyCanExecuteChanged();
        main.Quarantine.Refresh();
        main.Home.UpdateStatus();
    }

    /// <summary>Keeps only the newest progress report; a timer shows it a few times per second.</summary>
    private sealed class LatestProgress : IProgress<ScanProgress>
    {
        private volatile ScanProgress? _latest;

        public ScanProgress? Latest => _latest;

        public void Report(ScanProgress value) => _latest = value;
    }
}
