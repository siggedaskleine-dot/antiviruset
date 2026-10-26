using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MattesAntivirus.Core.Quarantine;

namespace MattesAntivirus.App.ViewModels;

public sealed partial class QuarantineViewModel(MainViewModel main) : PageViewModel("Karantän", "")
{
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RestoreCommand))]
    [NotifyCanExecuteChangedFor(nameof(DeleteCommand))]
    private QuarantineEntry? _selectedEntry;

    [ObservableProperty]
    private bool _isEmpty = true;

    [ObservableProperty]
    private string _errorText = "";

    public ObservableCollection<QuarantineEntry> Entries { get; } = [];

    public void Refresh()
    {
        Entries.Clear();
        try
        {
            foreach (var entry in main.QuarantineStore.List())
                Entries.Add(entry);
            ErrorText = "";
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            ErrorText = $"Karantänen kunde inte läsas: {e.Message}";
        }
        IsEmpty = Entries.Count == 0;
    }

    private bool HasSelection() => SelectedEntry is not null;

    [RelayCommand(CanExecute = nameof(HasSelection))]
    private void Restore()
    {
        if (SelectedEntry is not { } entry)
            return;

        var answer = MessageBox.Show(
            $"Filen klassades som {entry.ThreatName} och kan skada datorn.\n\nVill du ändå återställa den till\n{entry.OriginalPath}?",
            "Återställ från karantän",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes)
            return;

        Run(() => main.QuarantineStore.Restore(entry));
    }

    [RelayCommand(CanExecute = nameof(HasSelection))]
    private void Delete()
    {
        if (SelectedEntry is not { } entry)
            return;

        var answer = MessageBox.Show(
            $"Radera {Path.GetFileName(entry.OriginalPath)} för gott? Det går inte att ångra.",
            "Radera från karantän",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question,
            MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes)
            return;

        Run(() => main.QuarantineStore.Delete(entry));
    }

    private void Run(Action action)
    {
        try
        {
            action();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show(e.Message, "Mattes Antivirus", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        Refresh();
        main.Home.UpdateStatus();
    }
}
