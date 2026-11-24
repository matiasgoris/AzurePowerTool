using System.Text.Json;
using AzurePowerTool.Core.Auth;
using AzurePowerTool.Core.Http;
using AzurePowerTool.Core.Models;

namespace AzurePowerTool.Core.Clients;

/// <summary>Microsoft Graph (Entra ID directory).</summary>
public sealed class GraphClient(HttpClient http, IAzureSession session)
    : AzureRestClient(http, session, Scope)
{
    public const string Scope = "https://graph.microsoft.com/.default";
    private const string Endpoint = "https://graph.microsoft.com/v1.0";
    private const string NextLink = "@odata.nextLink";
    private const int GetByIdsBatchSize = 1000;

    private readonly IAzureSession _session = session;

    public async Task<GraphUser> GetMeAsync(CancellationToken ct = default)
    {
        var me = await SendAsync(HttpMethod.Get, $"{Endpoint}/me?$select=id,displayName,userPrincipalName,mail,userType", body: null, ct);
        return new GraphUser(me.Str("id") ?? "", me.Str("displayName"), me.Str("userPrincipalName"), me.Str("mail"), me.Str("userType"));
    }

    /// <summary>All groups and directory roles the user is a (nested) member of.</summary>
    public async Task<IReadOnlyList<DirectoryObjectRef>> GetMyTransitiveMembershipsAsync(CancellationToken ct = default)
    {
        var result = new List<DirectoryObjectRef>();
        await foreach (var item in GetPagedAsync($"{Endpoint}/me/transitiveMemberOf?$select=id,displayName&$top=999", NextLink, ct))
        {
            result.Add(ToRef(item));
        }
        return result;
    }

    /// <summary>Looks up directory objects by id. Ids that don't come back no longer exist (or aren't visible).</summary>
    public async Task<Dictionary<string, DirectoryObjectRef>> GetByIdsAsync(IEnumerable<string> ids, CancellationToken ct = default)
    {
        var found = new Dictionary<string, DirectoryObjectRef>(StringComparer.OrdinalIgnoreCase);
        foreach (var batch in ids.Distinct(StringComparer.OrdinalIgnoreCase).Chunk(GetByIdsBatchSize))
        {
            var response = await SendAsync(HttpMethod.Post, $"{Endpoint}/directoryObjects/getByIds", new { ids = batch }, ct);
            if (!response.TryGetProperty("value", out var items)) continue;

            foreach (var item in items.EnumerateArray())
            {
                var obj = ToRef(item);
                found[obj.Id] = obj;
            }
        }
        return found;
    }

    /// <summary>All app registrations in the tenant with their secrets, certificates and owners.</summary>
    public IAsyncEnumerable<JsonElement> GetApplicationsWithCredentialsAsync(CancellationToken ct = default) =>
        GetPagedAsync(
            $"{Endpoint}/applications?$select=id,appId,displayName,passwordCredentials,keyCredentials" +
            "&$expand=owners($select=id,displayName,userPrincipalName)&$top=100",
            NextLink, ct);

    /// <summary>True if the user may enumerate users in the directory (guests often can't).</summary>
    public async Task<bool> CanReadUsersAsync(CancellationToken ct = default)
    {
        try
        {
            await SendAsync(HttpMethod.Get, $"{Endpoint}/users?$top=1&$select=id", body: null, ct);
            return true;
        }
        catch (AzureApiException ex) when (ex.IsForbidden)
        {
            return false;
        }
    }

    /// <summary>The delegated Graph permissions (scp claim) in the current token.</summary>
    public async Task<IReadOnlyList<string>> GetGrantedScopesAsync(CancellationToken ct = default)
    {
        var token = await _session.GetTokenAsync(Scope, ct);
        var payload = JwtClaims.ReadPayload(token);
        return payload.TryGetProperty("scp", out var scp) && scp.ValueKind == JsonValueKind.String
            ? (scp.GetString() ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries).Order().ToList()
            : [];
    }

    private static DirectoryObjectRef ToRef(JsonElement item) =>
        new(item.Str("id") ?? "", item.Str("@odata.type") ?? "", item.Str("displayName"));
}
