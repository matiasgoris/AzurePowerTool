using System.Collections.Concurrent;
using System.Text.Json;
using AzurePowerTool.Core.Clients;
using AzurePowerTool.Core.Http;
using AzurePowerTool.Core.Models;

namespace AzurePowerTool.Core.Reports;

/// <summary>
/// Storage accounts where SAS tokens can be used, and whether they really are: the Azure Monitor "Transactions"
/// metric split by its Authentication dimension (AccountKey, SAS, DelegationSas, OAuth, Anonymous).
/// Account and service SAS are signed with the account key, so they are "enabled" as long as shared key access is
/// allowed. User delegation SAS is signed with Entra ID and keeps working when shared key access is off.
/// </summary>
public sealed class StorageSasUsageReport(ResourceGraphClient resourceGraph, ArmClient arm)
{
    /// <summary>Azure Monitor keeps platform metrics for 93 days.</summary>
    public const int MaxDays = 90;

    private const string Query = """
        resources
        | where type =~ 'microsoft.storage/storageaccounts'
        | project id, name, type, kind, subscriptionId, resourceGroup, location, tags,
            skuName = tostring(sku.name),
            allowSharedKeyAccess = properties.allowSharedKeyAccess,
            sasExpirationPeriod = tostring(properties.sasPolicy.sasExpirationPeriod)
        """;

    public async Task<ReportResult<StorageSasUsage>> RunAsync(int days = 30, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        days = Math.Clamp(days, 1, MaxDays);

        progress?.Report("Subscriptions ophalen…");
        var subscriptionNames = await ResourceRows.SubscriptionNamesAsync(arm, ct);

        progress?.Report("Storage accounts ophalen via Resource Graph…");
        var rows = await resourceGraph.QueryAsync(Query, ct: ct);

        var now = DateTimeOffset.UtcNow;
        var timespan = $"{now.AddDays(-days):yyyy-MM-ddTHH:mm:ssZ}/{now:yyyy-MM-ddTHH:mm:ssZ}";
        var found = new ConcurrentBag<StorageSasUsage>();
        int forbidden = 0, failed = 0, done = 0, sasOff = 0;

        await Parallel.ForEachAsync(rows, new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = ct }, async (row, token) =>
        {
            var resource = ResourceRows.ToRef(row, subscriptionNames);
            // Null on older accounts means "allowed".
            var sharedKeyAllowed = row.Bool("allowSharedKeyAccess") != false;
            var period = row.Str("sasExpirationPeriod") is { Length: > 0 } p ? p : null;
            var tags = row.StringMap("tags");

            StorageSasUsage? usage = null;
            try
            {
                var metrics = await arm.GetMetricsAsync(resource.Id, "Transactions", timespan, "P1D", "Total", token, filter: "Authentication eq '*'");
                var (totals, lastSas) = ByAuthentication(metrics);

                long Count(string type) => (long)totals.GetValueOrDefault(type);
                var sas = Count("SAS");
                var delegation = Count("DelegationSas");
                var key = Count("AccountKey");
                var state = sas + delegation > 0 ? SasUsageState.SasUsed
                    : key > 0 ? SasUsageState.KeyOnly
                    : SasUsageState.NotUsed;

                usage = new StorageSasUsage(resource, state, sharedKeyAllowed, period, sas, delegation, key,
                    Count("OAuth"), Count("Anonymous"), lastSas, row.Str("kind"), row.Str("skuName"), tags);
            }
            catch (AzureApiException ex)
            {
                if (ex.IsForbidden) Interlocked.Increment(ref forbidden); else Interlocked.Increment(ref failed);
                usage = new StorageSasUsage(resource, SasUsageState.Unknown, sharedKeyAllowed, period, 0, 0, 0, 0, 0, null, row.Str("kind"), row.Str("skuName"), tags);
            }

            // Shared key off and no (user delegation) SAS seen: SAS is neither enabled nor used.
            if (usage.SharedKeyAllowed || usage.State == SasUsageState.SasUsed) found.Add(usage);
            else Interlocked.Increment(ref sasOff);

            var count = Interlocked.Increment(ref done);
            if (count % 10 == 0) progress?.Report($"Authenticatie-metrics ophalen… {count}/{rows.Count}");
        });

        var items = found
            .OrderBy(i => i.State)
            .ThenByDescending(i => i.TotalSasRequests)
            .ThenByDescending(i => i.AccountKeyRequests)
            .ThenBy(i => i.Resource.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        int Of(SasUsageState state) => items.Count(i => i.State == state);
        var warnings = new List<string>
        {
            $"{rows.Count} storage accounts gecontroleerd over de laatste {days} dagen: {Of(SasUsageState.SasUsed)} met SAS-gebruik, " +
            $"{Of(SasUsageState.KeyOnly)} met alleen account key-gebruik, {Of(SasUsageState.NotUsed)} waar keys en SAS aan staan maar niet gebruikt worden.",
        };
        if (sasOff > 0)
            warnings.Add($"{sasOff} account(s) niet getoond: shared key-toegang staat uit en er is geen user delegation SAS gebruikt.");
        if (items.Any(i => i.State == SasUsageState.NotUsed))
            warnings.Add($"'Geen key- of SAS-gebruik' geldt alleen voor de gemeten {days} dagen. Jobs die minder vaak draaien (kwartaal, jaar) zie je hier niet.");
        if (forbidden > 0)
            warnings.Add($"Voor {forbidden} storage account(s) mocht je de metrics niet lezen (nodig: Reader of Monitoring Reader).");
        if (failed > 0)
            warnings.Add($"Voor {failed} storage account(s) konden de metrics niet opgehaald worden.");

        return new ReportResult<StorageSasUsage>(items, warnings, DateTimeOffset.Now);
    }

    /// <summary>Total requests per Authentication value, and the last day with SAS requests.</summary>
    private static (Dictionary<string, double> Totals, DateTimeOffset? LastSas) ByAuthentication(JsonElement metrics)
    {
        var totals = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        DateTimeOffset? lastSas = null;
        if (!metrics.TryGetProperty("value", out var values)) return (totals, lastSas);

        foreach (var metric in values.EnumerateArray())
        {
            if (!metric.TryGetProperty("timeseries", out var series)) continue;
            foreach (var ts in series.EnumerateArray())
            {
                string? authentication = null;
                if (ts.TryGetProperty("metadatavalues", out var metadata))
                {
                    foreach (var m in metadata.EnumerateArray())
                    {
                        if (m.TryGetProperty("name", out var name) && "authentication".Equals(name.Str("value"), StringComparison.OrdinalIgnoreCase))
                            authentication = m.Str("value");
                    }
                }
                if (authentication is null || !ts.TryGetProperty("data", out var data)) continue;

                var isSas = authentication.Contains("sas", StringComparison.OrdinalIgnoreCase);
                foreach (var point in data.EnumerateArray())
                {
                    if (!point.TryGetProperty("total", out var total) || total.ValueKind != JsonValueKind.Number || total.GetDouble() <= 0) continue;
                    totals[authentication] = totals.GetValueOrDefault(authentication) + total.GetDouble();
                    if (isSas && point.Date("timeStamp") is { } when && (lastSas is null || when > lastSas)) lastSas = when;
                }
            }
        }
        return (totals, lastSas);
    }
}
