using System.Collections.Concurrent;
using System.Text.Json;
using AzurePowerTool.Core.Clients;
using AzurePowerTool.Core.Http;
using AzurePowerTool.Core.Models;

namespace AzurePowerTool.Core.Reports;

/// <summary>
/// Resources that are attached to nothing: unattached disks, public IPs, NICs, NSGs and empty App Service plans.
/// They cost money (disks, IPs, plans) and clutter the environment. One Resource Graph query.
/// Storage accounts are judged on usage instead: no transactions at all in the last 30 days (Azure Monitor metrics).
/// </summary>
public sealed class UnusedResourcesReport(ResourceGraphClient resourceGraph, ArmClient arm)
{
    private const string Query = """
        resources
        | where (type =~ 'microsoft.compute/disks' and properties.diskState =~ 'Unattached')
            or (type =~ 'microsoft.network/publicipaddresses' and isnull(properties.ipConfiguration) and isnull(properties.natGateway))
            or (type =~ 'microsoft.network/networkinterfaces' and isnull(properties.virtualMachine) and isnull(properties.privateEndpoint) and isnull(properties.privateLinkService))
            or (type =~ 'microsoft.network/networksecuritygroups' and coalesce(array_length(properties.subnets), 0) == 0 and coalesce(array_length(properties.networkInterfaces), 0) == 0)
            or (type =~ 'microsoft.web/serverfarms' and toint(properties.numberOfSites) == 0)
        | project id, name, type, subscriptionId, resourceGroup, location, managedBy, tags,
            skuName = tostring(sku.name),
            diskSizeGB = toint(properties.diskSizeGB),
            ipAddress = tostring(properties.ipAddress),
            timeCreated = tostring(properties.timeCreated)
        """;

    private const string StorageQuery = """
        resources
        | where type =~ 'microsoft.storage/storageaccounts'
        | project id, name, type, subscriptionId, resourceGroup, location, managedBy, tags,
            skuName = tostring(sku.name), kind,
            timeCreated = tostring(properties.creationTime)
        """;

    /// <summary>Accounts with no transactions in this window count as unused. Younger accounts are skipped.</summary>
    private const int StorageIdleDays = 30;

    public async Task<ReportResult<UnusedResource>> RunAsync(IProgress<string>? progress = null, CancellationToken ct = default)
    {
        progress?.Report("Subscriptions ophalen…");
        var subscriptionNames = await ResourceRows.SubscriptionNamesAsync(arm, ct);

        progress?.Report($"Resource Graph doorzoeken ({subscriptionNames.Count} subscriptions)…");
        var rows = await resourceGraph.QueryAsync(Query, ct: ct);

        var items = rows
            .Select(r =>
            {
                var resource = ResourceRows.ToRef(r, subscriptionNames);
                var (kind, detail) = Describe(resource.Type, r.Str("skuName"), r.Int("diskSizeGB"), r.Str("ipAddress"));
                return new UnusedResource(resource, kind, detail, r.Str("managedBy") is { Length: > 0 } m ? m : null, r.Date("timeCreated"), r.StringMap("tags"));
            })
            .ToList();

        var warnings = new List<string>();
        items.AddRange(await FindIdleStorageAccountsAsync(subscriptionNames, warnings, progress, ct));
        items = items
            .OrderBy(i => i.Kind)
            .ThenBy(i => i.Resource.SubscriptionName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(i => i.Resource.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        warnings.InsertRange(0, new List<string>
        {
            string.Join(", ", items.GroupBy(i => i.Kind).OrderBy(g => g.Key).Select(g => $"{g.Count()} {g.Key.ToLowerInvariant()}"))
                is { Length: > 0 } summary ? $"Gevonden: {summary}." : "Geen ongebruikte resources gevonden.",
        });
        if (items.Any(i => i.ManagedBy is not null))
        {
            warnings.Add("Resources met 'Managed by' worden beheerd door een andere dienst (bv. Azure Site Recovery, AKS). Verwijder die niet zomaar.");
        }

        return new ReportResult<UnusedResource>(items, warnings, DateTimeOffset.Now);
    }

    private async Task<List<UnusedResource>> FindIdleStorageAccountsAsync(
        IReadOnlyDictionary<string, string> subscriptionNames, List<string> warnings, IProgress<string>? progress, CancellationToken ct)
    {
        progress?.Report("Storage accounts ophalen…");
        var rows = await resourceGraph.QueryAsync(StorageQuery, ct: ct);
        var now = DateTimeOffset.UtcNow;
        var cutoff = now.AddDays(-StorageIdleDays);

        // Too young for a full window: can't say anything yet.
        var candidates = rows.Where(r => r.Date("timeCreated") is not { } created || created <= cutoff).ToList();
        var tooYoung = rows.Count - candidates.Count;

        var timespan = $"{cutoff:yyyy-MM-ddTHH:mm:ssZ}/{now:yyyy-MM-ddTHH:mm:ssZ}";
        var found = new ConcurrentBag<UnusedResource>();
        var forbidden = 0;
        var failed = 0;
        var done = 0;

        await Parallel.ForEachAsync(candidates, new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = ct }, async (r, token) =>
        {
            var resource = ResourceRows.ToRef(r, subscriptionNames);
            try
            {
                var metrics = await arm.GetMetricsAsync(resource.Id, "Transactions,UsedCapacity", timespan, "P1D", "Total,Average", token);
                var transactions = Sum(metrics, "Transactions", "total");
                if (transactions == 0)
                {
                    var bytes = Last(metrics, "UsedCapacity", "average");
                    var detail = Join($"0 transacties in {StorageIdleDays} dagen", bytes is { } b ? FormatBytes(b) : null, r.Str("kind"), r.Str("skuName"));
                    found.Add(new UnusedResource(resource, "Storage account", detail,
                        r.Str("managedBy") is { Length: > 0 } m ? m : null, r.Date("timeCreated"), r.StringMap("tags")));
                }
            }
            catch (AzureApiException ex) when (ex.IsForbidden)
            {
                Interlocked.Increment(ref forbidden);
            }
            catch (AzureApiException)
            {
                Interlocked.Increment(ref failed);
            }

            var count = Interlocked.Increment(ref done);
            if (count % 10 == 0) progress?.Report($"Gebruik van storage accounts controleren… {count}/{candidates.Count}");
        });

        if (found.Count > 0)
            warnings.Add($"Storage accounts zonder transacties kunnen nog data bevatten (archief, back-ups): kijk de capaciteit na voor je iets verwijdert.");
        if (tooYoung > 0)
            warnings.Add($"{tooYoung} storage account(s) jonger dan {StorageIdleDays} dagen zijn niet beoordeeld.");
        if (forbidden > 0)
            warnings.Add($"Voor {forbidden} storage account(s) mocht je de metrics niet lezen (nodig: Reader of Monitoring Reader).");
        if (failed > 0)
            warnings.Add($"Voor {failed} storage account(s) konden de metrics niet opgehaald worden.");

        return found.ToList();
    }

    /// <summary>Sum of one aggregation over all data points (missing = 0).</summary>
    private static double Sum(JsonElement metrics, string metric, string aggregation) =>
        Points(metrics, metric).Sum(p => p.TryGetProperty(aggregation, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetDouble() : 0);

    /// <summary>Most recent value of one aggregation, or null.</summary>
    private static double? Last(JsonElement metrics, string metric, string aggregation) =>
        Points(metrics, metric)
            .Select(p => p.TryGetProperty(aggregation, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetDouble() : (double?)null)
            .LastOrDefault(v => v is not null);

    private static IEnumerable<JsonElement> Points(JsonElement metrics, string metric)
    {
        if (!metrics.TryGetProperty("value", out var values)) yield break;
        foreach (var m in values.EnumerateArray())
        {
            if (!m.TryGetProperty("name", out var name) || !string.Equals(name.Str("value"), metric, StringComparison.OrdinalIgnoreCase)) continue;
            if (!m.TryGetProperty("timeseries", out var series)) continue;
            foreach (var ts in series.EnumerateArray())
            {
                if (!ts.TryGetProperty("data", out var data)) continue;
                foreach (var point in data.EnumerateArray()) yield return point;
            }
        }
    }

    private static string FormatBytes(double bytes) => bytes switch
    {
        >= 1L << 40 => $"{bytes / (1L << 40):0.#} TB",
        >= 1L << 30 => $"{bytes / (1L << 30):0.#} GB",
        >= 1L << 20 => $"{bytes / (1L << 20):0.#} MB",
        >= 1L << 10 => $"{bytes / (1L << 10):0.#} KB",
        _ => $"{bytes:0} B",
    };

    private static (string Kind, string? Detail) Describe(string type, string? sku, int? diskSizeGb, string? ip) => type.ToLowerInvariant() switch
    {
        "microsoft.compute/disks" => ("Disk", Join(diskSizeGb is { } gb ? $"{gb} GB" : null, sku)),
        "microsoft.network/publicipaddresses" => ("Public IP", Join(ip, sku)),
        "microsoft.network/networkinterfaces" => ("Netwerkinterface", null),
        "microsoft.network/networksecuritygroups" => ("NSG", null),
        "microsoft.web/serverfarms" => ("App Service plan", Join(sku, "0 apps")),
        _ => (type, null),
    };

    private static string? Join(params string?[] parts) =>
        parts.Where(p => !string.IsNullOrEmpty(p)).ToList() is { Count: > 0 } list ? string.Join(" · ", list) : null;
}
