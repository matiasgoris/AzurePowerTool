using System.Text.Json;
using System.Text.Json.Serialization;

namespace AzurePowerTool.Core.Storage;

/// <summary>
/// Everything the tool remembers: acknowledgements and the activity log. Stored as one JSON document
/// (in the browser: a file the user picks, e.g. in OneDrive).
/// </summary>
public sealed class AppData
{
    public int Version { get; set; } = 1;

    /// <summary>Report → lowercase resource id → acknowledgement.</summary>
    public Dictionary<string, Dictionary<string, Acknowledgement>> Acknowledgements { get; set; } = [];

    /// <summary>Oldest first (appended).</summary>
    public List<AuditEntry> Audit { get; set; } = [];

    public static AppData Parse(string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return new AppData();
        try
        {
            return JsonSerializer.Deserialize(json, AppDataJsonContext.Default.AppData) ?? new AppData();
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"Het logbestand is geen geldig Azure PowerTool-bestand: {ex.Message}", ex);
        }
    }

    public string Serialize() => JsonSerializer.Serialize(this, AppDataJsonContext.Default.AppData);
}

/// <summary>Where <see cref="AppData"/> lives. Not available = acknowledging and deleting are disabled (nothing changes without a log).</summary>
public interface IAppDataStore
{
    bool IsAvailable { get; }

    /// <summary>Raised when the store becomes (un)available.</summary>
    event Action? Changed;

    Task<AppData> ReadAsync(CancellationToken ct = default);

    /// <summary>Reads the latest version, applies <paramref name="change"/> and writes it back.</summary>
    Task UpdateAsync(Action<AppData> change, CancellationToken ct = default);
}

[JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(AppData))]
internal sealed partial class AppDataJsonContext : JsonSerializerContext;
