using System.Text.Json;
using AzurePowerTool.Core.Auth;
using AzurePowerTool.Core.Http;

namespace AzurePowerTool.Core.Clients;

/// <summary>
/// Azure Resource Graph: one KQL query over all subscriptions the user can see in the current tenant.
/// </summary>
public sealed class ResourceGraphClient(HttpClient http, IAzureSession session)
    : AzureRestClient(http, session, AzureScopes.Arm)
{
    private const string Url = $"{ArmClient.Endpoint}/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01";
    private const int PageSize = 1000;

    /// <param name="authorizationScopeFilter">
    /// For authorizationresources: "AtScopeAboveAndBelow" also returns assignments inherited from
    /// management groups / root. Null = API default (AtScopeAndBelow).
    /// </param>
    public async Task<IReadOnlyList<JsonElement>> QueryAsync(string query, string? authorizationScopeFilter = null, CancellationToken ct = default)
    {
        var rows = new List<JsonElement>();
        string? skipToken = null;

        do
        {
            var options = new Dictionary<string, object?>
            {
                ["resultFormat"] = "objectArray",
                ["$top"] = PageSize,
            };
            if (skipToken is not null) options["$skipToken"] = skipToken;
            if (authorizationScopeFilter is not null) options["authorizationScopeFilter"] = authorizationScopeFilter;

            var body = new Dictionary<string, object?> { ["query"] = query, ["options"] = options };
            var page = await SendAsync(HttpMethod.Post, Url, body, ct);

            if (page.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Array)
            {
                rows.AddRange(data.EnumerateArray());
            }
            skipToken = page.Str("$skipToken");
        }
        while (skipToken is not null);

        return rows;
    }

    /// <summary>Builds a safe KQL list literal from GUIDs (anything that isn't a GUID is dropped).</summary>
    public static string GuidList(IEnumerable<string> ids) =>
        "(" + string.Join(",", ids.Where(id => Guid.TryParse(id, out _)).Select(id => $"'{id.ToLowerInvariant()}'")) + ")";
}
