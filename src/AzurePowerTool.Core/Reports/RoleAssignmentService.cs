using System.Text.Json;
using AzurePowerTool.Core.Clients;
using AzurePowerTool.Core.Http;
using AzurePowerTool.Core.Models;

namespace AzurePowerTool.Core.Reports;

/// <summary>Reads Azure RBAC role assignments (incl. inherited from management groups) via Resource Graph.</summary>
public sealed class RoleAssignmentService(ResourceGraphClient resourceGraph, ArmClient arm)
{
    private const int PrincipalFilterBatchSize = 200;

    /// <param name="principalIds">Only assignments for these principals; null = all assignments.</param>
    public async Task<IReadOnlyList<RoleAssignmentInfo>> GetAsync(
        IReadOnlyCollection<string>? principalIds,
        IReadOnlyList<SubscriptionInfo> subscriptions,
        CancellationToken ct = default)
    {
        var rows = new List<JsonElement>();
        if (principalIds is null)
        {
            rows.AddRange(await resourceGraph.QueryAsync(Query(filter: null), "AtScopeAboveAndBelow", ct));
        }
        else
        {
            foreach (var batch in principalIds.Chunk(PrincipalFilterBatchSize))
            {
                var filter = $"| where tolower(tostring(properties.principalId)) in {ResourceGraphClient.GuidList(batch)}";
                rows.AddRange(await resourceGraph.QueryAsync(Query(filter), "AtScopeAboveAndBelow", ct));
            }
        }

        var subscriptionNames = subscriptions.ToDictionary(s => s.SubscriptionId, s => s.DisplayName, StringComparer.OrdinalIgnoreCase);

        // An assignment on a management group shows up once per subscription below it: dedupe on id.
        var assignments = rows
            .GroupBy(r => r.Str("id") ?? "", StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .Select(r =>
            {
                var scope = r.Str("scope") ?? "";
                var subscriptionId = ScopeParser.SubscriptionId(scope);
                return new RoleAssignmentInfo(
                    Id: r.Str("id") ?? "",
                    PrincipalId: (r.Str("principalId") ?? "").ToLowerInvariant(),
                    PrincipalType: r.Str("principalType") ?? "",
                    Scope: scope,
                    RoleDefinitionId: r.Str("roleDefinitionId") ?? "",
                    RoleName: "",
                    SubscriptionId: subscriptionId,
                    SubscriptionName: subscriptionId is not null && subscriptionNames.TryGetValue(subscriptionId, out var name) ? name : null,
                    CreatedOn: DateTimeOffset.TryParse(r.Str("createdOn"), out var created) ? created : null,
                    CreatedBy: r.Str("createdBy"));
            })
            .ToList();

        var roleNames = await ResolveRoleNamesAsync(assignments.Select(a => RoleGuid(a.RoleDefinitionId)), ct);

        return assignments
            .Select(a => a with { RoleName = roleNames.TryGetValue(RoleGuid(a.RoleDefinitionId), out var n) ? n : RoleGuid(a.RoleDefinitionId) })
            .OrderBy(a => a.SubscriptionName ?? "")
            .ThenBy(a => a.Scope, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string Query(string? filter) => $"""
        authorizationresources
        | where type =~ 'microsoft.authorization/roleassignments'
        {filter}
        | project id,
            principalId = tostring(properties.principalId),
            principalType = tostring(properties.principalType),
            scope = tostring(properties.scope),
            roleDefinitionId = tostring(properties.roleDefinitionId),
            createdOn = tostring(properties.createdOn),
            createdBy = tostring(properties.createdBy)
        """;

    private async Task<Dictionary<string, string>> ResolveRoleNamesAsync(IEnumerable<string> roleGuids, CancellationToken ct)
    {
        var needed = roleGuids.Where(g => g.Length > 0).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            foreach (var (guid, name) in await arm.GetBuiltInRoleNamesAsync(ct))
            {
                if (needed.Contains(guid)) names[guid] = name;
            }
        }
        catch (AzureApiException)
        {
            // Not fatal: fall through to the Resource Graph lookup.
        }

        // Custom roles (and anything not resolved above).
        var missing = needed.Where(g => !names.ContainsKey(g)).ToList();
        foreach (var batch in missing.Chunk(PrincipalFilterBatchSize))
        {
            var query = $"""
                authorizationresources
                | where type =~ 'microsoft.authorization/roledefinitions'
                | where tolower(name) in {ResourceGraphClient.GuidList(batch)}
                | project name = tolower(name), roleName = tostring(properties.roleName)
                """;
            foreach (var row in await resourceGraph.QueryAsync(query, ct: ct))
            {
                if (row.Str("name") is { } guid && row.Str("roleName") is { } roleName) names[guid] = roleName;
            }
        }

        return names;
    }

    private static string RoleGuid(string roleDefinitionId) => ScopeParser.Name(roleDefinitionId).ToLowerInvariant();
}
