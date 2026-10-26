using CommunityToolkit.Mvvm.ComponentModel;
using MattesAntivirus.Core;

namespace MattesAntivirus.App.ViewModels;

/// <summary>One infected file in the scan results, with every detection that matched it.</summary>
public sealed partial class DetectionItem(IReadOnlyList<Detection> detections) : ObservableObject
{
    [ObservableProperty]
    private bool _isSelected = true;

    [ObservableProperty]
    private bool _isHandled;

    [ObservableProperty]
    private string _status = "Ej åtgärdad";

    public IReadOnlyList<Detection> Detections { get; } = detections;

    public string FilePath => Detections[0].FilePath;

    public string ThreatName => string.Join(", ", Detections.Select(d => d.ThreatName).Distinct());

    public string Engine => string.Join(", ", Detections.Select(d => d.Engine).Distinct());
}
