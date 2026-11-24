namespace AzurePowerTool.Core.Models;

public sealed record TenantInfo(string TenantId, string? DisplayName, string? DefaultDomain)
{
    public string Label => DisplayName is { Length: > 0 } name ? $"{name} ({DefaultDomain ?? TenantId})" : TenantId;
}

public sealed record SubscriptionInfo(string SubscriptionId, string DisplayName, string State, string? TenantId);

public sealed record GraphUser(string Id, string? DisplayName, string? UserPrincipalName, string? Mail, string? UserType);

/// <summary>A user, group, service principal, directory role, ... as returned by Microsoft Graph.</summary>
public sealed record DirectoryObjectRef(string Id, string Type, string? DisplayName)
{
    /// <summary>"#microsoft.graph.servicePrincipal" → "servicePrincipal".</summary>
    public string ShortType => Type.StartsWith("#microsoft.graph.", StringComparison.Ordinal) ? Type["#microsoft.graph.".Length..] : Type;
}

public sealed record ReportResult<T>(IReadOnlyList<T> Items, IReadOnlyList<string> Warnings, DateTimeOffset GeneratedAt);

public enum ScopeLevel { Root, ManagementGroup, Subscription, ResourceGroup, Resource, Unknown }

public sealed record RoleAssignmentInfo(
    string Id,
    string PrincipalId,
    string PrincipalType,
    string Scope,
    string RoleDefinitionId,
    string RoleName,
    string? SubscriptionId,
    string? SubscriptionName,
    DateTimeOffset? CreatedOn,
    string? CreatedBy)
{
    public ScopeLevel ScopeLevel => ScopeParser.Level(Scope);

    /// <summary>Last meaningful segment of the scope: the resource / RG / MG name.</summary>
    public string ScopeName => ScopeParser.Name(Scope);
}

public sealed record EmptyResourceGroup(
    string Id,
    string Name,
    string SubscriptionId,
    string SubscriptionName,
    string Location,
    string? ManagedBy,
    IReadOnlyDictionary<string, string> Tags,
    VerificationStatus Verification,
    DateTimeOffset? CreatedTime = null)
{
    public int? AgeInDays => CreatedTime is { } created ? (int)(DateTimeOffset.UtcNow - created).TotalDays : null;
}

public enum VerificationStatus { NotVerified, ConfirmedEmpty, Failed }

/// <param name="DeleteBlockedReason">Set when deleting from the tool is not safe (e.g. the directory could not be read). Null = deletable.</param>
public sealed record OrphanedRoleAssignment(RoleAssignmentInfo Assignment, string? Note, string? DeleteBlockedReason = null);

public sealed record MyRoleAssignment(RoleAssignmentInfo Assignment, string Via);

public enum CheckStatus { Ok, Warning, Failed }

public sealed record CapabilityCheck(string Name, CheckStatus Status, string Detail, string? NeededFor = null);

public sealed record AccessOverview(
    string Username,
    string TenantId,
    GraphUser? User,
    IReadOnlyList<TenantInfo> Tenants,
    IReadOnlyList<SubscriptionInfo> Subscriptions,
    IReadOnlyList<string> EntraRoles,
    int GroupCount,
    IReadOnlyList<MyRoleAssignment> RoleAssignments,
    IReadOnlyList<string> GraphScopes,
    IReadOnlyList<CapabilityCheck> Checks,
    DateTimeOffset GeneratedAt);

public static class ScopeParser
{
    public static ScopeLevel Level(string scope)
    {
        var s = scope.TrimEnd('/');
        if (s.Length == 0 || s == "/") return ScopeLevel.Root;
        if (s.StartsWith("/providers/Microsoft.Management/managementGroups/", StringComparison.OrdinalIgnoreCase)) return ScopeLevel.ManagementGroup;
        if (!s.StartsWith("/subscriptions/", StringComparison.OrdinalIgnoreCase)) return ScopeLevel.Unknown;

        var segments = s.Split('/', StringSplitOptions.RemoveEmptyEntries);
        return segments.Length switch
        {
            2 => ScopeLevel.Subscription,
            4 when segments[2].Equals("resourceGroups", StringComparison.OrdinalIgnoreCase) => ScopeLevel.ResourceGroup,
            > 4 => ScopeLevel.Resource,
            _ => ScopeLevel.Unknown,
        };
    }

    public static string Name(string scope)
    {
        var segments = scope.Split('/', StringSplitOptions.RemoveEmptyEntries);
        return segments.Length == 0 ? "/" : segments[^1];
    }

    public static string? SubscriptionId(string scope)
    {
        var segments = scope.Split('/', StringSplitOptions.RemoveEmptyEntries);
        return segments.Length >= 2 && segments[0].Equals("subscriptions", StringComparison.OrdinalIgnoreCase) ? segments[1] : null;
    }
}
