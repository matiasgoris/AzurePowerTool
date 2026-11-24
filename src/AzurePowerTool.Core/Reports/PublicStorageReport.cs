using System.Text.Json;
using AzurePowerTool.Core.Clients;
using AzurePowerTool.Core.Http;
using AzurePowerTool.Core.Models;

namespace AzurePowerTool.Core.Reports;

/// <summary>
/// Storage accounts with public network access that nothing shields: not in a network security perimeter (NSP)
/// in Enforced mode, not tagged as a deliberate exception, and without an approved private endpoint.
/// A perimeter in Learning / Audit mode only logs, so those accounts are reported too (with the perimeter).
/// </summary>
public sealed class PublicStorageReport(ResourceGraphClient resourceGraph, ArmClient arm)
{
    /// <summary>Exclusion tag: <c>nsp = excluded</c>. A tag named <c>nsp:excluded</c> (any value but "false") counts too.</summary>
    public const string ExcludeTagName = "nsp";
    public const string ExcludeTagValue = "excluded";

    private const string Query = """
        resources
        | where type =~ 'microsoft.storage/storageaccounts'
        | project id, name, type, kind, subscriptionId, resourceGroup, location, tags,
            skuName = tostring(sku.name),
            publicNetworkAccess = tostring(properties.publicNetworkAccess),
            networkDefaultAction = tostring(properties.networkAcls.defaultAction),
            ipRuleCount = coalesce(array_length(properties.networkAcls.ipRules), 0),
            vnetRuleCount = coalesce(array_length(properties.networkAcls.virtualNetworkRules), 0),
            allowBlobPublicAccess = properties.allowBlobPublicAccess,
            privateEndpointConnections = properties.privateEndpointConnections
        """;

    public async Task<ReportResult<PublicStorageAccount>> RunAsync(IProgress<string>? progress = null, CancellationToken ct = default)
    {
        progress?.Report("Subscriptions ophalen…");
        var subscriptionNames = await ResourceRows.SubscriptionNamesAsync(arm, ct);

        progress?.Report("Storage accounts ophalen via Resource Graph…");
        var rows = await resourceGraph.QueryAsync(Query, ct: ct);

        var (perimeters, perimeterWarnings) = await NspLookup.GetAssociationsAsync(resourceGraph, arm, progress, ct);

        var items = new List<PublicStorageAccount>();
        int notPublic = 0, inNsp = 0, inNspNotEnforced = 0, excluded = 0, withPrivateEndpoint = 0;

        foreach (var row in rows)
        {
            // Null on older accounts means Enabled. SecuredByPerimeter: only the perimeter lets traffic in.
            var pna = row.Str("publicNetworkAccess") ?? "";
            if (pna.Equals("Disabled", StringComparison.OrdinalIgnoreCase) || pna.Equals("SecuredByPerimeter", StringComparison.OrdinalIgnoreCase))
            {
                notPublic++;
                continue;
            }

            var resource = ResourceRows.ToRef(row, subscriptionNames);
            var nsp = perimeters.GetValueOrDefault(resource.Id);
            if (nsp is { IsEnforced: true })
            {
                inNsp++;
                continue;
            }

            var tags = row.StringMap("tags");
            if (IsExcluded(tags))
            {
                excluded++;
                continue;
            }

            var (approved, unapproved) = CountPrivateEndpoints(row);
            if (approved > 0)
            {
                withPrivateEndpoint++;
                continue;
            }

            var ipRules = row.Int("ipRuleCount") ?? 0;
            var vnetRules = row.Int("vnetRuleCount") ?? 0;
            var exposure = !"Deny".Equals(row.Str("networkDefaultAction"), StringComparison.OrdinalIgnoreCase) ? StorageExposure.AllNetworks
                : ipRules + vnetRules > 0 ? StorageExposure.SelectedNetworks
                : StorageExposure.NoRules;

            items.Add(new PublicStorageAccount(
                resource,
                exposure,
                exposure switch
                {
                    StorageExposure.AllNetworks => Severity.High,
                    StorageExposure.SelectedNetworks => Severity.Medium,
                    _ => Severity.Low,
                },
                ipRules,
                vnetRules,
                unapproved,
                // Null on older accounts means "allowed".
                AnonymousBlobAccess: row.Bool("allowBlobPublicAccess") != false,
                row.Str("kind"),
                row.Str("skuName"),
                tags)
            {
                Nsp = nsp,
            });
            if (nsp is not null) inNspNotEnforced++;
        }

        var ordered = items
            .OrderByDescending(i => i.Severity)
            .ThenBy(i => i.Resource.SubscriptionName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(i => i.Resource.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var warnings = new List<string>
        {
            $"{rows.Count} storage accounts gecontroleerd: {ordered.Count} publiek zonder NSP in Enforced-modus, uitzonderingstag of private endpoint. " +
            $"Niet gemeld: {notPublic} zonder publieke toegang, {inNsp} in een NSP op Enforced, {excluded} met tag {ExcludeTagName}={ExcludeTagValue}, {withPrivateEndpoint} met private endpoint.",
        };
        if (inNspNotEnforced > 0)
        {
            warnings.Add($"{inNspNotEnforced} gemelde account(s) zitten in een NSP die nog niet op Enforced staat: de perimeter logt dan alleen. " +
                         "De fix is daar de koppeling op Enforced zetten (controleer eerst de NSP-logs).");
        }
        if (withPrivateEndpoint > 0)
        {
            warnings.Add($"Let op: bij de {withPrivateEndpoint} account(s) met een private endpoint staat de publieke toegang nog aan. Een private endpoint sluit het publieke endpoint niet af.");
        }
        warnings.AddRange(perimeterWarnings);

        return new ReportResult<PublicStorageAccount>(ordered, warnings, DateTimeOffset.Now);
    }

    internal static bool IsExcluded(IReadOnlyDictionary<string, string> tags) =>
        tags.Any(t =>
            (t.Key.Trim().Equals(ExcludeTagName, StringComparison.OrdinalIgnoreCase) && t.Value.Trim().Equals(ExcludeTagValue, StringComparison.OrdinalIgnoreCase))
            || (t.Key.Trim().Equals($"{ExcludeTagName}:{ExcludeTagValue}", StringComparison.OrdinalIgnoreCase) && !t.Value.Trim().Equals("false", StringComparison.OrdinalIgnoreCase)));

    private static (int Approved, int Unapproved) CountPrivateEndpoints(JsonElement row)
    {
        if (!row.TryGetProperty("privateEndpointConnections", out var connections) || connections.ValueKind != JsonValueKind.Array) return (0, 0);

        int approved = 0, unapproved = 0;
        foreach (var connection in connections.EnumerateArray())
        {
            var status = connection.TryGetProperty("properties", out var props) && props.TryGetProperty("privateLinkServiceConnectionState", out var state)
                ? state.Str("status")
                : null;
            if ("Approved".Equals(status, StringComparison.OrdinalIgnoreCase)) approved++; else unapproved++;
        }
        return (approved, unapproved);
    }
}
