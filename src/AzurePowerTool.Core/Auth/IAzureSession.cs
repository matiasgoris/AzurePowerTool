namespace AzurePowerTool.Core.Auth;

/// <summary>
/// The signed-in user's session. All Azure calls get their tokens from here, so the tool only ever
/// sees what the user may see. The web app implements it with MSAL.js in the browser.
/// </summary>
public interface IAzureSession
{
    bool IsSignedIn { get; }

    SignedInAccount? Account { get; }

    /// <summary>Raised after sign-in, sign-out or a tenant switch.</summary>
    event Action? Changed;

    /// <summary>Silently restores the previous session (no sign-in screen). Returns false if not possible.</summary>
    Task<bool> TryResumeAsync(CancellationToken ct = default);

    /// <summary>Interactive sign-in. <paramref name="tenant"/> is optional (tenant id or domain).</summary>
    Task SignInAsync(string? tenant = null, CancellationToken ct = default);

    Task SwitchTenantAsync(string tenantId, CancellationToken ct = default);

    Task SignOutAsync();

    Task<string> GetTokenAsync(string scope, CancellationToken ct = default);
}

public static class AzureScopes
{
    public const string Arm = "https://management.azure.com/.default";
    public const string Graph = "https://graph.microsoft.com/.default";
    public const string KeyVault = "https://vault.azure.net/.default";
}

public sealed record SignedInAccount(string Username, string TenantId, string HomeTenantId);

public sealed class NotSignedInException() : InvalidOperationException("Je bent niet aangemeld.");

/// <summary>No valid token without user interaction (expired session, new consent needed). The user must sign in again.</summary>
public sealed class ReauthenticationRequiredException(string? detail = null)
    : InvalidOperationException("Je sessie is verlopen of vraagt een nieuwe aanmelding." + (detail is null ? "" : $" ({detail})"));
