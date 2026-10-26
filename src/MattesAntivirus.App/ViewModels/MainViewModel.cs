using CommunityToolkit.Mvvm.ComponentModel;
using MattesAntivirus.Core;
using MattesAntivirus.Core.Quarantine;

namespace MattesAntivirus.App.ViewModels;

public sealed partial class MainViewModel : ObservableObject
{
    [ObservableProperty]
    private PageViewModel _currentPage;

    public MainViewModel()
    {
        Paths = AppPaths.Default;
        QuarantineStore = new QuarantineStore(Paths.QuarantineDirectory);
        History = ScanHistory.For(Paths);

        // Large signature lists take a moment to load, so do it in the background while the window opens.
        Engines = Task.Run(() => EngineSet.Load(Paths));

        Home = new HomeViewModel(this);
        Scan = new ScanViewModel(this);
        Quarantine = new QuarantineViewModel(this);
        Pages = [Home, Scan, Quarantine];
        _currentPage = Home;

        Quarantine.Refresh();
        _ = Home.RefreshAsync();
    }

    public AppPaths Paths { get; }

    public QuarantineStore QuarantineStore { get; }

    public ScanHistory History { get; }

    public Task<EngineSet> Engines { get; }

    public HomeViewModel Home { get; }

    public ScanViewModel Scan { get; }

    public QuarantineViewModel Quarantine { get; }

    public IReadOnlyList<PageViewModel> Pages { get; }

    public void StartScan(string scanType, IReadOnlyList<string> targets)
    {
        CurrentPage = Scan;
        _ = Scan.RunAsync(scanType, targets);
    }
}
