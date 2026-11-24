using System.Text.Json;
using AzurePowerTool.Core.Auth;
using AzurePowerTool.Core.Http;

namespace AzurePowerTool.Core.Clients;

/// <summary>
/// Key Vault data plane. Only lists metadata (names, expiry, tags, thumbprints): secret values are never read.
/// Needs list rights on the vault (RBAC: Key Vault Reader; access policies: List) and network access to the vault.
/// </summary>
public sealed class KeyVaultClient(HttpClient http, IAzureSession session)
    : AzureRestClient(http, session, Scope)
{
    private readonly IAzureSession _session = session;

    public const string Scope = "https://vault.azure.net/.default";
    private const string ApiVersion = "7.4";

    /// <summary>
    /// Null when a Key Vault token can be obtained, otherwise the reason. Fails when the
    /// app registration lacks the Azure Key Vault (user_impersonation) permission or consent.
    /// </summary>
    public async Task<string?> CheckAccessAsync(CancellationToken ct = default)
    {
        try
        {
            await _session.GetTokenAsync(Scope, ct);
            return null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return ex.InnerException?.Message ?? ex.Message;
        }
    }

    public IAsyncEnumerable<JsonElement> ListSecretsAsync(string vaultUri, CancellationToken ct = default) =>
        GetPagedAsync($"{vaultUri.TrimEnd('/')}/secrets?api-version={ApiVersion}&maxresults=25", "nextLink", ct);

    public IAsyncEnumerable<JsonElement> ListCertificatesAsync(string vaultUri, CancellationToken ct = default) =>
        GetPagedAsync($"{vaultUri.TrimEnd('/')}/certificates?api-version={ApiVersion}&maxresults=25", "nextLink", ct);
}
