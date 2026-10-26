using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MattesAntivirus.Core;
using Microsoft.Win32;

namespace MattesAntivirus.App.ViewModels;

public enum ProtectionLevel
{
    Ok,
    Warning,
    Alert,
}

public sealed partial class HomeViewModel(MainViewModel main) : PageViewModel("Översikt", "")
{
    private static readonly TimeSpan ScanReminder = TimeSpan.FromDays(7);

    [ObservableProperty]
    private ProtectionLevel _level = ProtectionLevel.Warning;

    [ObservableProperty]
    private string _statusTitle = "Startar…";

    [ObservableProperty]
    private string _statusDetail = "";

    [ObservableProperty]
    private string _lastScanText = "";

    [ObservableProperty]
    private string _signatureText = "Laddar signaturer…";

    [ObservableProperty]
    private string _quarantineText = "";

    public async Task RefreshAsync()
    {
        UpdateStatus();
        try
        {
            var engines = await main.Engines;
            var yara = engines.Yara is { } rules ? $"{rules.RuleCount} YARA-regler" : $"YARA ej tillgängligt ({engines.YaraError})";
            SignatureText = $"{engines.Hashes.Count:N0} hash-signaturer · {yara}";
        }
        catch (Exception e)
        {
            SignatureText = $"Signaturerna kunde inte laddas: {e.Message}";
        }
    }

    public void UpdateStatus()
    {
        var last = main.History.Load();
        var pending = main.Scan.UnhandledThreats;
        var quarantined = main.Quarantine.Entries.Count;
        QuarantineText = quarantined == 1 ? "1 fil i karantän" : $"{quarantined} filer i karantän";
        LastScanText = last is null
            ? "Ingen skanning har gjorts ännu."
            : $"Senaste skanning: {last.ScanType.ToLowerInvariant()} {last.FinishedAt.LocalDateTime:d MMMM yyyy 'kl.' HH:mm}" +
              $", {last.FilesScanned:N0} filer, {(last.ThreatsFound == 1 ? "1 hot" : $"{last.ThreatsFound} hot")}" +
              (last.Cancelled ? " (avbruten)" : "");

        if (pending > 0)
        {
            Level = ProtectionLevel.Alert;
            StatusTitle = pending == 1 ? "1 hot hittades" : $"{pending} hot hittades";
            StatusDetail = "Gå till Skanning och flytta hoten till karantän.";
        }
        else if (last is null)
        {
            Level = ProtectionLevel.Warning;
            StatusTitle = "Datorn har inte skannats";
            StatusDetail = "Kör en snabbskanning för att kontrollera datorn.";
        }
        else if (last.ThreatsFound > 0 && !main.Scan.HasResults)
        {
            Level = ProtectionLevel.Warning;
            StatusTitle = "Senaste skanningen hittade hot";
            StatusDetail = "Skanna igen för att kontrollera att alla hot är åtgärdade.";
        }
        else if (DateTimeOffset.Now - last.FinishedAt > ScanReminder)
        {
            Level = ProtectionLevel.Warning;
            StatusTitle = "Dags att skanna igen";
            StatusDetail = "Det har gått mer än en vecka sedan datorn skannades.";
        }
        else
        {
            Level = ProtectionLevel.Ok;
            StatusTitle = "Datorn är skyddad";
            StatusDetail = "Inga kända hot hittades.";
        }
    }

    [RelayCommand]
    private void QuickScan() => main.StartScan("Snabbskanning", ScanLocations.QuickScan());

    [RelayCommand]
    private void FullScan() => main.StartScan("Fullständig skanning", ScanLocations.FullScan());

    [RelayCommand]
    private void CustomScan()
    {
        var dialog = new OpenFolderDialog { Title = "Välj mappar att skanna", Multiselect = true };
        if (dialog.ShowDialog() == true && dialog.FolderNames.Length > 0)
            main.StartScan("Anpassad skanning", dialog.FolderNames);
    }
}
