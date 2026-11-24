using AzurePowerTool.Core.Auth;

namespace AzurePowerTool.Core.Storage;

public static class AuditActions
{
    public const string RoleAssignmentDelete = "RoleAssignment.Delete";
    public const string ResourceGroupDelete = "ResourceGroup.Delete";
    public const string Acknowledge = "Acknowledgement.Add";
    public const string AcknowledgeRevoke = "Acknowledgement.Revoke";
}

public sealed record AuditEntry(
    DateTimeOffset Time,
    string User,
    string TenantId,
    string Action,
    string TargetId,
    string? TargetName,
    bool Success,
    string? Details,
    string? Error);

/// <summary>Log of every change made from the tool (deletes, acknowledgements). Reading data is not logged.</summary>
public sealed class AuditLog(IAppDataStore store, IAzureSession session)
{
    public bool IsEnabled => store.IsAvailable;

    public Task WriteAsync(string action, string targetId, string? targetName, bool success, string? details = null, string? error = null, CancellationToken ct = default) =>
        store.UpdateAsync(data => data.Audit.Add(Create(action, targetId, targetName, success, details, error)), ct);

    public AuditEntry Create(string action, string targetId, string? targetName, bool success, string? details = null, string? error = null)
    {
        var account = session.Account;
        return new AuditEntry(
            DateTimeOffset.UtcNow,
            account?.Username ?? "(onbekend)",
            account?.TenantId ?? "",
            action,
            targetId,
            targetName,
            success,
            details,
            error is { Length: > 2000 } ? error[..2000] : error);
    }

    /// <summary>Newest first, over the last <paramref name="months"/> months.</summary>
    public async Task<IReadOnlyList<AuditEntry>> ListAsync(int months = 3, int max = 2000, CancellationToken ct = default)
    {
        var data = await store.ReadAsync(ct);
        var since = DateTimeOffset.UtcNow.AddMonths(-months);
        return data.Audit
            .Where(e => e.Time >= since)
            .OrderByDescending(e => e.Time)
            .Take(max)
            .ToList();
    }
}
