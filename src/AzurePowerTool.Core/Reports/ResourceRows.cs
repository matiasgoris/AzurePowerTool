using System.Text.Json;
using AzurePowerTool.Core.Clients;
using AzurePowerTool.Core.Http;
using AzurePowerTool.Core.Models;

namespace AzurePowerTool.Core.Reports;

/// <summary>Shared helpers for reports that read resources from Resource Graph.</summary>
internal static class ResourceRows
{
    public static async Task<Dictionary<string, string>> SubscriptionNamesAsync(ArmClient arm, CancellationToken ct) =>
        (await arm.GetSubscriptionsAsync(ct))
            .ToDictionary(s => s.SubscriptionId, s => s.DisplayName, StringComparer.OrdinalIgnoreCase);

    /// <summary>Expects the columns id, name, type, subscriptionId, resourceGroup, location.</summary>
    public static ResourceRef ToRef(JsonElement row, IReadOnlyDictionary<string, string> subscriptionNames)
    {
        var subscriptionId = row.Str("subscriptionId") ?? "";
        return new ResourceRef(
            Id: row.Str("id") ?? "",
            Name: row.Str("name") ?? "",
            Type: row.Str("type") ?? "",
            SubscriptionId: subscriptionId,
            SubscriptionName: subscriptionNames.GetValueOrDefault(subscriptionId, subscriptionId),
            ResourceGroup: row.Str("resourceGroup") ?? "",
            Location: row.Str("location") ?? "");
    }
}
