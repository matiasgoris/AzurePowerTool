using AzurePowerTool.Core.Auth;
using AzurePowerTool.Core.Clients;
using AzurePowerTool.Core.Http;
using AzurePowerTool.Core.Models;

namespace AzurePowerTool.Core.Reports;

/// <summary>
/// "What can I see with my credentials?": account, tenants, subscriptions, Entra roles,
/// Azure RBAC assignments (direct and via groups) and whether each report will work.
/// Every part is fetched independently so one failing permission doesn't break the overview.
/// </summary>
public sealed class AccessOverviewReport(IAzureSession session, ArmClient arm, GraphClient graph, RoleAssignmentService roleAssignments)
{
    public async Task<AccessOverview> RunAsync(CancellationToken ct = default)
    {
        var account = session.Account ?? throw new NotSignedInException();
        var checks = new List<CapabilityCheck>();

        var tenantsTask = Try(() => arm.GetTenantsAsync(ct));
        var subscriptionsTask = Try(() => arm.GetSubscriptionsAsync(ct));
        var meTask = Try(() => graph.GetMeAsync(ct));
        var membershipsTask = Try(() => graph.GetMyTransitiveMembershipsAsync(ct));
        var scopesTask = Try(() => graph.GetGrantedScopesAsync(ct));
        var canReadUsersTask = Try(() => graph.CanReadUsersAsync(ct));
        await Task.WhenAll(tenantsTask, subscriptionsTask, meTask, membershipsTask, scopesTask, canReadUsersTask);

        var (tenants, tenantsError) = tenantsTask.Result;
        var (subscriptions, subscriptionsError) = subscriptionsTask.Result;
        var (me, meError) = meTask.Result;
        var (memberships, membershipsError) = membershipsTask.Result;
        var (scopes, _) = scopesTask.Result;
        var (canReadUsers, canReadUsersError) = canReadUsersTask.Result;

        subscriptions ??= [];
        memberships ??= [];

        checks.Add(subscriptionsError is null
            ? new CapabilityCheck("Azure Resource Manager", subscriptions.Count > 0 ? CheckStatus.Ok : CheckStatus.Warning,
                subscriptions.Count > 0
                    ? $"{subscriptions.Count} subscription(s) zichtbaar in deze tenant."
                    : "Aangemeld, maar je ziet geen enkele subscription in deze tenant.",
                "Alle rapporten")
            : new CapabilityCheck("Azure Resource Manager", CheckStatus.Failed, subscriptionsError, "Alle rapporten"));

        checks.Add(meError is null
            ? new CapabilityCheck("Microsoft Graph", CheckStatus.Ok, "Je profiel kan gelezen worden.")
            : new CapabilityCheck("Microsoft Graph", CheckStatus.Failed, meError));

        checks.Add(canReadUsersError is not null
            ? new CapabilityCheck("Directory lezen", CheckStatus.Failed, canReadUsersError, "Role assignments van verwijderde identiteiten, App secrets & certificaten")
            : canReadUsers
                ? new CapabilityCheck("Directory lezen", CheckStatus.Ok, "Je kan users, groepen en service principals opzoeken.", "Role assignments van verwijderde identiteiten, App secrets & certificaten")
                : new CapabilityCheck("Directory lezen", CheckStatus.Warning,
                    "Je mag de directory niet doorzoeken (typisch voor gastaccounts). Het rapport 'role assignments van verwijderde identiteiten' is dan onbetrouwbaar.",
                    "Role assignments van verwijderde identiteiten, App secrets & certificaten"));

        // RBAC for me + every group I'm (transitively) a member of.
        var groups = memberships.Where(m => m.ShortType == "group").ToList();
        var entraRoles = memberships.Where(m => m.ShortType == "directoryRole").Select(m => m.DisplayName ?? m.Id).Order().ToList();

        var myAssignments = new List<MyRoleAssignment>();
        if (me is not null)
        {
            try
            {
                var via = groups.ToDictionary(g => g.Id.ToLowerInvariant(), g => $"Groep: {g.DisplayName ?? g.Id}");
                via[me.Id.ToLowerInvariant()] = "Direct";

                var assignments = await roleAssignments.GetAsync(via.Keys.ToList(), subscriptions, ct);
                myAssignments = assignments
                    .Select(a => new MyRoleAssignment(a, via.GetValueOrDefault(a.PrincipalId, a.PrincipalId)))
                    .ToList();

                checks.Add(new CapabilityCheck("Azure Resource Graph", CheckStatus.Ok,
                    $"{myAssignments.Count} role assignment(s) voor jou gevonden (direct of via groepen).", "Alle rapporten"));
            }
            catch (Exception ex) when (ex is AzureApiException or HttpRequestException)
            {
                checks.Add(new CapabilityCheck("Azure Resource Graph", CheckStatus.Failed, ex.Message, "Alle rapporten"));
            }
        }

        if (membershipsError is not null)
        {
            checks.Add(new CapabilityCheck("Groepslidmaatschappen", CheckStatus.Warning,
                $"Kon je groepen niet ophalen: rollen via groepen ontbreken in het overzicht. ({membershipsError})"));
        }

        if (myAssignments.Count > 0 && !myAssignments.Any(a => a.Assignment.ScopeLevel is ScopeLevel.Root or ScopeLevel.ManagementGroup or ScopeLevel.Subscription))
        {
            checks.Add(new CapabilityCheck("Bereik", CheckStatus.Warning,
                "Je hebt enkel rechten op resourcegroep- of resource-niveau: rapporten tonen alleen wat binnen die scopes valt."));
        }

        return new AccessOverview(
            Username: me?.UserPrincipalName ?? account.Username,
            TenantId: account.TenantId,
            User: me,
            Tenants: tenants ?? [],
            Subscriptions: subscriptions,
            EntraRoles: entraRoles,
            GroupCount: groups.Count,
            RoleAssignments: myAssignments,
            GraphScopes: scopes ?? [],
            Checks: checks,
            GeneratedAt: DateTimeOffset.Now);
    }

    private static async Task<(T? Value, string? Error)> Try<T>(Func<Task<T>> action)
    {
        try
        {
            return (await action(), null);
        }
        catch (AzureApiException ex)
        {
            return (default, ex.IsForbidden ? $"Geen toegang ({(int)ex.Status} {ex.Code})." : ex.Message);
        }
        catch (HttpRequestException ex)
        {
            return (default, ex.Message);
        }
    }
}
