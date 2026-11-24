using AzurePowerTool.Core.Auth;
using Microsoft.AspNetCore.Components;
using Microsoft.JSInterop;

namespace AzurePowerTool.Web.Auth;

/// <summary>
/// Session via MSAL.js (wwwroot/js/auth.js): sign-in with a redirect to Microsoft, tokens cached in this
/// browser, every Azure call made directly from the browser with the user's own token.
/// </summary>
public sealed class BrowserSession(IJSRuntime js, NavigationManager navigation) : IAzureSession
{
    private sealed record JsAccount(string Username, string TenantId, string HomeTenantId);
    private sealed record JsState(string? Error, JsAccount? Account);
    private sealed record JsToken(string? Token, string? TenantId, bool InteractionRequired, string? Error);

    public event Action? Changed;

    public bool IsSignedIn => Account is not null;

    public SignedInAccount? Account { get; private set; }

    /// <summary>Set when sign-in can't work at all (no app registration configured, MSAL failed to start).</summary>
    public string? ConfigurationError { get; private set; }

    public async Task<bool> TryResumeAsync(CancellationToken ct = default)
    {
        var state = await js.InvokeAsync<JsState>("powerToolAuth.state", ct);
        ConfigurationError = state.Error;
        if (state.Account is not { } account)
        {
            if (ConfigurationError is not null) Changed?.Invoke(); // let the sign-in page show why
            return false;
        }

        Account = new SignedInAccount(account.Username, account.TenantId, account.HomeTenantId);
        Changed?.Invoke();
        return true;
    }

    /// <summary>Leaves the page for the Microsoft sign-in; the app reloads afterwards.</summary>
    public async Task SignInAsync(string? tenant = null, CancellationToken ct = default) =>
        await js.InvokeVoidAsync("powerToolAuth.signIn", ct, string.IsNullOrWhiteSpace(tenant) ? null : tenant.Trim(), navigation.Uri);

    /// <summary>After <see cref="ReauthenticationRequiredException"/>: sign in again, then come back to this page.</summary>
    public async Task ReauthenticateAsync() =>
        await js.InvokeVoidAsync("powerToolAuth.reauthenticate", null, Account?.TenantId, navigation.Uri);

    public async Task SwitchTenantAsync(string tenantId, CancellationToken ct = default)
    {
        if (Account is null) throw new NotSignedInException();

        // Redirects to Microsoft when the tenant needs an interactive sign-in (MFA, consent).
        var result = await js.InvokeAsync<JsToken>("powerToolAuth.switchTenant", ct, tenantId, navigation.Uri);
        if (result.Token is null)
        {
            if (result.InteractionRequired) return; // the page is leaving
            throw new InvalidOperationException($"Wisselen naar tenant {tenantId} mislukt: {result.Error}");
        }

        Account = Account with { TenantId = result.TenantId ?? tenantId };
        Changed?.Invoke();
    }

    public async Task SignOutAsync()
    {
        await js.InvokeVoidAsync("powerToolAuth.signOut");
        Account = null;
        Changed?.Invoke();
    }

    public async Task<string> GetTokenAsync(string scope, CancellationToken ct = default)
    {
        if (Account is null) throw new NotSignedInException();

        var result = await js.InvokeAsync<JsToken>("powerToolAuth.getToken", ct, scope, Account.TenantId);
        if (result.Token is { } token) return token;
        if (result.InteractionRequired) throw new ReauthenticationRequiredException(result.Error);
        throw new InvalidOperationException($"Token ophalen mislukt: {result.Error}");
    }
}
