using System.Collections.Concurrent;
using AzurePowerTool.Core.Clients;
using AzurePowerTool.Core.Http;
using AzurePowerTool.Core.Models;

namespace AzurePowerTool.Core.Reports;

/// <summary>
/// Report 1: resource groups without resources.
/// Step 1 finds candidates via Resource Graph (fast, all subscriptions at once).
/// Step 2 double-checks every candidate directly against ARM, because the Resource Graph
/// index can lag behind and doesn't index every resource type.
/// </summary>
public sealed class EmptyResourceGroupsReport(ResourceGraphClient resourceGraph, ArmClient arm)
{
    private const string Query = """
        resourcecontainers
        | where type =~ 'microsoft.resources/subscriptions/resourcegroups'
        | extend rgKey = strcat(subscriptionId, '/', tolower(name))
        | join kind=leftouter (
            resources
            | extend rgKey = strcat(subscriptionId, '/', tolower(resourceGroup))
            | summarize resourceCount = count() by rgKey
          ) on rgKey
        | where isnull(resourceCount) or resourceCount == 0
        | project id, name, subscriptionId, location, managedBy, tags
        """;

    public async Task<ReportResult<EmptyResourceGroup>> RunAsync(IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var warnings = new List<string>();

        progress?.Report("Subscriptions ophalen…");
        var subscriptions = await arm.GetSubscriptionsAsync(ct);
        var subscriptionNames = subscriptions.ToDictionary(s => s.SubscriptionId, s => s.DisplayName, StringComparer.OrdinalIgnoreCase);

        progress?.Report($"Resource Graph doorzoeken ({subscriptions.Count} subscriptions)…");
        var rows = await resourceGraph.QueryAsync(Query, ct: ct);

        var candidates = rows.Select(r => new EmptyResourceGroup(
                Id: r.Str("id") ?? "",
                Name: r.Str("name") ?? "",
                SubscriptionId: r.Str("subscriptionId") ?? "",
                SubscriptionName: subscriptionNames.GetValueOrDefault(r.Str("subscriptionId") ?? "", r.Str("subscriptionId") ?? ""),
                Location: r.Str("location") ?? "",
                ManagedBy: r.Str("managedBy"),
                Tags: r.StringMap("tags"),
                Verification: VerificationStatus.NotVerified))
            .ToList();

        progress?.Report($"{candidates.Count} kandidaten verifiëren via ARM…");
        var verified = new ConcurrentBag<EmptyResourceGroup>();
        var notEmpty = 0;
        var done = 0;

        await Parallel.ForEachAsync(candidates, new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = ct }, async (rg, token) =>
        {
            try
            {
                if (await arm.ResourceGroupHasResourcesAsync(rg.SubscriptionId, rg.Name, token))
                {
                    Interlocked.Increment(ref notEmpty);
                }
                else
                {
                    verified.Add(rg with { Verification = VerificationStatus.ConfirmedEmpty });
                }
            }
            catch (AzureApiException)
            {
                verified.Add(rg with { Verification = VerificationStatus.Failed });
            }

            var count = Interlocked.Increment(ref done);
            if (count % 10 == 0) progress?.Report($"Verifiëren via ARM… {count}/{candidates.Count}");
        });

        if (notEmpty > 0)
        {
            warnings.Add($"{notEmpty} resourcegroep(en) leken leeg volgens Resource Graph maar bevatten toch resources (bv. types die Resource Graph niet indexeert). Die zijn weggelaten.");
        }
        if (verified.Any(v => v.Verification == VerificationStatus.Failed))
        {
            warnings.Add("Een aantal resourcegroepen kon niet geverifieerd worden via ARM (zie kolom Status).");
        }

        progress?.Report("Creatiedatums ophalen…");
        var createdTimes = new ConcurrentDictionary<string, Dictionary<string, DateTimeOffset>>(StringComparer.OrdinalIgnoreCase);
        var subscriptionIds = verified.Select(v => v.SubscriptionId).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var datesFailed = 0;

        await Parallel.ForEachAsync(subscriptionIds, new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = ct }, async (subscriptionId, token) =>
        {
            try
            {
                createdTimes[subscriptionId] = await arm.GetResourceGroupCreatedTimesAsync(subscriptionId, token);
            }
            catch (AzureApiException)
            {
                Interlocked.Increment(ref datesFailed);
            }
        });

        if (datesFailed > 0)
        {
            warnings.Add($"Voor {datesFailed} subscription(s) kon de creatiedatum niet opgehaald worden.");
        }

        var items = verified
            .Select(rg => createdTimes.TryGetValue(rg.SubscriptionId, out var times) && times.TryGetValue(rg.Name, out var created)
                ? rg with { CreatedTime = created }
                : rg)
            .OrderBy(r => r.SubscriptionName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new ReportResult<EmptyResourceGroup>(items, warnings, DateTimeOffset.Now);
    }
}
