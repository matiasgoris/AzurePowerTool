using System.Net;
using System.Text.Json;
using AzurePowerTool.Core.Auth;
using AzurePowerTool.Core.Http;
using AzurePowerTool.Core.Models;

namespace AzurePowerTool.Core.Clients;

/// <summary>Azure Resource Manager (management.azure.com).</summary>
public sealed class ArmClient(HttpClient http, IAzureSession session)
    : AzureRestClient(http, session, AzureScopes.Arm)
{
    public const string Endpoint = "https://management.azure.com";

    public async Task<IReadOnlyList<TenantInfo>> GetTenantsAsync(CancellationToken ct = default)
    {
        var tenants = new List<TenantInfo>();
        await foreach (var item in GetPagedAsync($"{Endpoint}/tenants?api-version=2022-12-01", "nextLink", ct))
        {
            tenants.Add(new TenantInfo(item.Str("tenantId") ?? "", item.Str("displayName"), item.Str("defaultDomain")));
        }
        return tenants.OrderBy(t => t.DisplayName ?? t.TenantId, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public async Task<IReadOnlyList<SubscriptionInfo>> GetSubscriptionsAsync(CancellationToken ct = default)
    {
        var subscriptions = new List<SubscriptionInfo>();
        await foreach (var item in GetPagedAsync($"{Endpoint}/subscriptions?api-version=2022-12-01", "nextLink", ct))
        {
            subscriptions.Add(new SubscriptionInfo(
                item.Str("subscriptionId") ?? "",
                item.Str("displayName") ?? "",
                item.Str("state") ?? "",
                item.Str("tenantId")));
        }
        return subscriptions.OrderBy(s => s.DisplayName, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>Authoritative check (directly against ARM, not the Resource Graph index).</summary>
    /// <summary>Resource associations of a network security perimeter (not indexed by Resource Graph).</summary>
    public IAsyncEnumerable<JsonElement> GetNspAssociationsAsync(string perimeterId, CancellationToken ct = default) =>
        GetPagedAsync($"{Endpoint}{perimeterId}/resourceAssociations?api-version=2024-07-01", "nextLink", ct);

    /// <summary>All record sets of a DNS zone (not indexed by Resource Graph). Private zones use "aRecords", public zones "ARecords".</summary>
    public IAsyncEnumerable<JsonElement> GetDnsRecordSetsAsync(string zoneId, bool isPrivate, CancellationToken ct = default) =>
        GetPagedAsync(isPrivate
            ? $"{Endpoint}{zoneId}/ALL?api-version=2024-06-01"
            : $"{Endpoint}{zoneId}/recordsets?api-version=2018-05-01", "nextLink", ct);

    /// <summary>A resource by id, straight from ARM (authoritative, unlike the Resource Graph index).</summary>
    public Task<JsonElement> GetResourceAsync(string resourceId, string apiVersion, CancellationToken ct = default) =>
        SendAsync(HttpMethod.Get, $"{Endpoint}{resourceId}?api-version={apiVersion}", body: null, ct);

    /// <summary>NICs of the instances of a uniform scale set (Resource Graph doesn't index them).</summary>
    public IAsyncEnumerable<JsonElement> GetVmssNetworkInterfacesAsync(string vmssId, CancellationToken ct = default) =>
        GetPagedAsync($"{Endpoint}{vmssId}/networkInterfaces?api-version=2018-10-01", "nextLink", ct);

    public async Task<bool> ResourceGroupHasResourcesAsync(string subscriptionId, string resourceGroup, CancellationToken ct = default)
    {
        var url = $"{Endpoint}/subscriptions/{subscriptionId}/resourceGroups/{Uri.EscapeDataString(resourceGroup)}/resources?$top=1&api-version=2021-04-01";
        var page = await SendAsync(HttpMethod.Get, url, body: null, ct);
        return page.TryGetProperty("value", out var value) && value.GetArrayLength() > 0;
    }

    /// <summary>
    /// Creation time per resource group (name → time). Uses <c>$expand=createdTime</c>: ARM returns it,
    /// but it isn't part of the documented resource group schema, so treat a missing value as "unknown".
    /// </summary>
    public async Task<Dictionary<string, DateTimeOffset>> GetResourceGroupCreatedTimesAsync(string subscriptionId, CancellationToken ct = default)
    {
        var times = new Dictionary<string, DateTimeOffset>(StringComparer.OrdinalIgnoreCase);
        var url = $"{Endpoint}/subscriptions/{subscriptionId}/resourcegroups?api-version=2021-04-01&$expand=createdTime";
        await foreach (var item in GetPagedAsync(url, "nextLink", ct))
        {
            if (item.Str("name") is { } name && DateTimeOffset.TryParse(item.Str("createdTime"), out var created))
            {
                times[name] = created;
            }
        }
        return times;
    }

    /// <summary>
    /// Deletes a role assignment by its full resource id. Needs Microsoft.Authorization/roleAssignments/delete
    /// on the scope (Owner, User Access Administrator or RBAC Administrator). Already gone (404) counts as success.
    /// </summary>
    public async Task DeleteRoleAssignmentAsync(string roleAssignmentId, CancellationToken ct = default)
    {
        if (!roleAssignmentId.StartsWith('/') || !roleAssignmentId.Contains("/providers/Microsoft.Authorization/roleAssignments/", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException($"Geen geldige role assignment id: {roleAssignmentId}", nameof(roleAssignmentId));
        }

        try
        {
            await SendAsync(HttpMethod.Delete, $"{Endpoint}{roleAssignmentId}?api-version=2022-04-01", body: null, ct);
        }
        catch (AzureApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            // Already removed.
        }
    }

    /// <summary>
    /// Deletes a resource group and waits until ARM reports it done (or <paramref name="maxWait"/> passes).
    /// Returns true when finished, false when still running after <paramref name="maxWait"/>. Already gone (404) = true.
    /// Callers must check that it is empty first: ARM deletes everything inside it.
    /// </summary>
    public async Task<bool> DeleteResourceGroupAsync(string subscriptionId, string resourceGroup, TimeSpan maxWait, CancellationToken ct = default)
    {
        var url = $"{Endpoint}/subscriptions/{subscriptionId}/resourcegroups/{Uri.EscapeDataString(resourceGroup)}?api-version=2021-04-01";
        (HttpStatusCode Status, string? PollUrl, TimeSpan? RetryAfter) result;
        try
        {
            result = await SendOperationAsync(HttpMethod.Delete, url, ct);
        }
        catch (AzureApiException ex) when (ex.Status == HttpStatusCode.NotFound)
        {
            return true;
        }

        var deadline = DateTimeOffset.UtcNow + maxWait;
        while (result.Status == HttpStatusCode.Accepted && result.PollUrl is { } poll)
        {
            if (DateTimeOffset.UtcNow >= deadline) return false;
            await Task.Delay(result.RetryAfter is { } wait && wait < TimeSpan.FromSeconds(30) ? wait : TimeSpan.FromSeconds(10), ct);
            var next = await SendOperationAsync(HttpMethod.Get, poll, ct);
            result = (next.Status, next.PollUrl ?? poll, next.RetryAfter);
        }
        return true;
    }

    /// <summary>
    /// Azure Monitor platform metrics of a resource (needs only Reader). <paramref name="timespan"/> is ISO 8601 "start/end".
    /// </summary>
    /// <param name="filter">Optional dimension filter; <c>Authentication eq '*'</c> gives one time series per value.</param>
    public Task<JsonElement> GetMetricsAsync(string resourceId, string metricNames, string timespan, string interval, string aggregation, CancellationToken ct = default, string? filter = null) =>
        SendAsync(HttpMethod.Get,
            $"{Endpoint}{resourceId}/providers/Microsoft.Insights/metrics?api-version=2023-10-01" +
            $"&metricnames={Uri.EscapeDataString(metricNames)}&timespan={Uri.EscapeDataString(timespan)}" +
            $"&interval={interval}&aggregation={Uri.EscapeDataString(aggregation)}" +
            (filter is null ? "" : $"&$filter={Uri.EscapeDataString(filter)}"),
            body: null, ct);

    /// <summary>Built-in role definitions (tenant-wide): role GUID → role name.</summary>
    public async Task<Dictionary<string, string>> GetBuiltInRoleNamesAsync(CancellationToken ct = default)
    {
        var roles = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var url = $"{Endpoint}/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01&$filter=type%20eq%20'BuiltInRole'";
        await foreach (var item in GetPagedAsync(url, "nextLink", ct))
        {
            var name = item.Str("name");
            var roleName = item.TryGetProperty("properties", out var props) ? props.Str("roleName") : null;
            if (name is not null && roleName is not null) roles[name] = roleName;
        }
        return roles;
    }
}
