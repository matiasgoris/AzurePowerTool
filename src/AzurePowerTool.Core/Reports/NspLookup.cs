using System.Collections.Concurrent;
using AzurePowerTool.Core.Clients;
using AzurePowerTool.Core.Http;
using AzurePowerTool.Core.Models;

namespace AzurePowerTool.Core.Reports;

/// <summary>
/// Which resources sit in a network security perimeter (NSP). Perimeters come from Resource Graph,
/// their associations from ARM (Resource Graph doesn't index them).
/// </summary>
internal static class NspLookup
{
    private const string PerimeterQuery = """
        resources
        | where type =~ 'microsoft.network/networksecurityperimeters'
        | project id, name
        """;

    /// <summary>Resource id → association. A resource in several perimeters gets the Enforced one.</summary>
    public static async Task<(Dictionary<string, NspAssociation> Associations, List<string> Warnings)> GetAssociationsAsync(
        ResourceGraphClient resourceGraph, ArmClient arm, IProgress<string>? progress, CancellationToken ct)
    {
        progress?.Report("Network security perimeters ophalen…");
        var perimeters = await resourceGraph.QueryAsync(PerimeterQuery, ct: ct);

        var associations = new ConcurrentDictionary<string, NspAssociation>(StringComparer.OrdinalIgnoreCase);
        var failed = new ConcurrentBag<string>();

        await Parallel.ForEachAsync(perimeters, new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = ct }, async (perimeter, token) =>
        {
            var perimeterName = perimeter.Str("name") ?? "";
            try
            {
                await foreach (var a in arm.GetNspAssociationsAsync(perimeter.Str("id") ?? "", token))
                {
                    if (!a.TryGetProperty("properties", out var props)) continue;
                    var resourceId = props.TryGetProperty("privateLinkResource", out var plr) ? plr.Str("id") : null;
                    if (string.IsNullOrEmpty(resourceId)) continue;

                    var association = new NspAssociation(a.Str("id") ?? "", perimeterName, props.Str("accessMode") ?? "Learning");
                    associations.AddOrUpdate(resourceId, association, (_, existing) => existing.IsEnforced ? existing : association);
                }
            }
            catch (AzureApiException)
            {
                failed.Add(perimeterName);
            }
        });

        var warnings = new List<string>();
        if (perimeters.Count > 0)
        {
            warnings.Add($"{perimeters.Count} network security perimeters gelezen, {associations.Count} gekoppelde resources " +
                         $"({associations.Values.Count(a => a.IsEnforced)} Enforced).");
        }
        if (!failed.IsEmpty)
        {
            warnings.Add($"{failed.Count} NSP('s) konden niet gelezen worden ({string.Join(", ", failed.Order().Take(10))}). " +
                         "Netwerkbevindingen voor resources in die perimeters kunnen onterecht zijn.");
        }

        return (new Dictionary<string, NspAssociation>(associations, StringComparer.OrdinalIgnoreCase), warnings);
    }
}
