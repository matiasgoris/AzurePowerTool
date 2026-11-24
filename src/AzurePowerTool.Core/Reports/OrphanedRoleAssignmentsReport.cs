using AzurePowerTool.Core.Clients;
using AzurePowerTool.Core.Http;
using AzurePowerTool.Core.Models;

namespace AzurePowerTool.Core.Reports;

/// <summary>
/// Report 2: role assignments whose principal (user, group, service principal / managed identity)
/// no longer exists in Entra ID. The portal shows these as "Identity not found" / type Unknown.
/// Note: ARM keeps the original principalType, so the only reliable check is asking Graph.
/// </summary>
public sealed class OrphanedRoleAssignmentsReport(RoleAssignmentService roleAssignments, ArmClient arm, GraphClient graph)
{
    public async Task<ReportResult<OrphanedRoleAssignment>> RunAsync(IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var warnings = new List<string>();

        progress?.Report("Subscriptions ophalen…");
        var subscriptions = await arm.GetSubscriptionsAsync(ct);

        progress?.Report("Role assignments ophalen via Resource Graph…");
        var assignments = await roleAssignments.GetAsync(principalIds: null, subscriptions, ct);

        var principalIds = assignments
            .Select(a => a.PrincipalId)
            .Where(id => Guid.TryParse(id, out _))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        progress?.Report($"{principalIds.Count} unieke principals opzoeken in Entra ID…");
        Dictionary<string, DirectoryObjectRef> existing;
        try
        {
            existing = await graph.GetByIdsAsync(principalIds, ct);
        }
        catch (AzureApiException ex) when (ex.IsForbidden)
        {
            throw new InvalidOperationException(
                "Je account mag de Entra ID directory niet lezen (Microsoft Graph gaf 'Forbidden'). " +
                "Zonder die leesrechten kan niet bepaald worden welke principals nog bestaan.", ex);
        }

        // Nothing found at all: almost certainly limited read rights, not real orphans. Don't allow deleting.
        var directoryUnreadable = principalIds.Count > 0 && existing.Count == 0;
        if (directoryUnreadable)
        {
            warnings.Add(
                "Geen enkele principal werd teruggevonden in Entra ID. Dat wijst meestal op beperkte directory-leesrechten " +
                "(bv. gastaccount) en niet op echte wezen. Controleer dit voor je iets opruimt.");
        }

        var orphans = assignments
            .Where(a => !existing.ContainsKey(a.PrincipalId))
            .Select(a => new OrphanedRoleAssignment(a, NoteFor(a),
                directoryUnreadable ? "Uitgeschakeld: geen enkele principal teruggevonden in Entra ID, dus dit is waarschijnlijk geen echte wees." : null))
            .ToList();

        warnings.Add($"{assignments.Count} role assignments gecontroleerd, {principalIds.Count} unieke principals, {orphans.Count} zonder bestaande principal.");

        return new ReportResult<OrphanedRoleAssignment>(orphans, warnings, DateTimeOffset.Now);
    }

    private static string? NoteFor(RoleAssignmentInfo assignment) => assignment.PrincipalType switch
    {
        "ForeignGroup" => "Groep uit een andere tenant: kan niet geverifieerd worden in deze directory.",
        _ when !Guid.TryParse(assignment.PrincipalId, out _) => "Ongeldige principal id.",
        _ => null,
    };
}
