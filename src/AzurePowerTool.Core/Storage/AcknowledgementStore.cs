using AzurePowerTool.Core.Auth;

namespace AzurePowerTool.Core.Storage;

public static class AcknowledgementReports
{
    public const string UnusedResources = "unused-resources";
    public const string StorageSas = "storage-sas";
}

public sealed record Acknowledgement(string ResourceId, string? ResourceName, string? Kind, string AcknowledgedBy, DateTimeOffset AcknowledgedAt, string? Reason);

/// <summary>
/// Findings a user accepted ("this is intentional"), per report, so they don't keep coming back.
/// Every change is written to the <see cref="AuditLog"/> in the same write.
/// </summary>
public sealed class AcknowledgementStore(IAppDataStore store, AuditLog audit, IAzureSession session)
{
    public bool IsEnabled => store.IsAvailable;

    /// <summary>Resource id (case-insensitive) → acknowledgement.</summary>
    public async Task<Dictionary<string, Acknowledgement>> GetAsync(string report, CancellationToken ct = default)
    {
        var data = await store.ReadAsync(ct);
        var result = new Dictionary<string, Acknowledgement>(StringComparer.OrdinalIgnoreCase);
        if (data.Acknowledgements.TryGetValue(report, out var items))
        {
            foreach (var ack in items.Values) result[ack.ResourceId] = ack;
        }
        return result;
    }

    public async Task<Acknowledgement> AcknowledgeAsync(string report, string resourceId, string? name, string? kind, string? reason, CancellationToken ct = default)
    {
        var ack = new Acknowledgement(resourceId, name, kind, session.Account?.Username ?? "(onbekend)", DateTimeOffset.UtcNow,
            string.IsNullOrWhiteSpace(reason) ? null : reason.Trim());
        try
        {
            await store.UpdateAsync(data =>
            {
                if (!data.Acknowledgements.TryGetValue(report, out var items))
                {
                    data.Acknowledgements[report] = items = [];
                }
                items[Key(resourceId)] = ack;
                data.Audit.Add(audit.Create(AuditActions.Acknowledge, resourceId, name, true, Details(report, ack.Reason)));
            }, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await TryAuditAsync(AuditActions.Acknowledge, report, resourceId, name, reason, ex.Message);
            throw;
        }
        return ack;
    }

    public async Task RevokeAsync(string report, string resourceId, string? name, CancellationToken ct = default)
    {
        try
        {
            await store.UpdateAsync(data =>
            {
                if (data.Acknowledgements.TryGetValue(report, out var items))
                {
                    items.Remove(Key(resourceId));
                }
                data.Audit.Add(audit.Create(AuditActions.AcknowledgeRevoke, resourceId, name, true, Details(report, null)));
            }, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await TryAuditAsync(AuditActions.AcknowledgeRevoke, report, resourceId, name, null, ex.Message);
            throw;
        }
    }

    private static string Key(string resourceId) => resourceId.ToLowerInvariant();

    private static string Details(string report, string? reason) => reason is null ? $"Rapport: {report}" : $"Rapport: {report} · Reden: {reason}";

    private async Task TryAuditAsync(string action, string report, string id, string? name, string? reason, string error)
    {
        try { await audit.WriteAsync(action, id, name, false, Details(report, reason), error); }
        catch (Exception) { /* The original error is more important. */ }
    }
}
