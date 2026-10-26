using CommunityToolkit.Mvvm.ComponentModel;

namespace MattesAntivirus.App.ViewModels;

/// <summary>A page in the navigation list on the left of the window.</summary>
public abstract class PageViewModel(string title, string glyph) : ObservableObject
{
    public string Title { get; } = title;

    /// <summary>Icon character from the Segoe Fluent Icons font.</summary>
    public string Glyph { get; } = glyph;
}
