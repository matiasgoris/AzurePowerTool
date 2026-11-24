using System.Collections.Concurrent;
using System.Text.Json;
using AzurePowerTool.Core.Clients;
using AzurePowerTool.Core.Http;
using AzurePowerTool.Core.Models;

namespace AzurePowerTool.Core.Reports;

/// <summary>
/// App registration secrets and certificates that are expired, expire soon, or live too long.
/// Expiring credentials cause outages; expired ones are clutter; long-lived secrets are a leak risk.
/// Optionally scans all Key Vaults (metadata only) to find where each credential is stored.
/// </summary>
public sealed class AppCredentialsReport(GraphClient graph, ResourceGraphClient resourceGraph, ArmClient arm, KeyVaultClient keyVault)
{
    public const int ExpiringSoonDays = 60;
    public const int UrgentDays = 30;
    public const int MaxSecretLifetimeDays = 366;
    public const int SuggestedLifetimeDays = 180;
    private const int MaxLocationsPerCredential = 5;

    private const string VaultQuery = """
        resources
        | where type =~ 'microsoft.keyvault/vaults'
        | project id, name, type, subscriptionId, resourceGroup, location, vaultUri = tostring(properties.vaultUri)
        """;

    public async Task<ReportResult<AppCredential>> RunAsync(bool scanKeyVaults = true, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;
        var warnings = new List<string>();

        var (items, appCount, credentialCount) = await ReadCredentialsAsync(now, progress, ct);
        warnings.Add($"{appCount} app registrations en {credentialCount} credentials gecontroleerd, {items.Count} vragen actie.");

        IReadOnlyList<VaultItem> vaultItems = [];
        if (scanKeyVaults && items.Count > 0)
        {
            (vaultItems, var vaultWarnings) = await ScanKeyVaultsAsync(progress, ct);
            warnings.AddRange(vaultWarnings);
        }

        progress?.Report("Credentials koppelen aan Key Vault…");
        var result = items
            .Select(c => Finish(c, Match(c, vaultItems), now))
            .OrderByDescending(i => i.Severity)
            .ThenBy(i => i.End ?? DateTimeOffset.MaxValue)
            .ThenBy(i => i.AppName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (scanKeyVaults && vaultItems.Count > 0)
        {
            var located = result.Count(r => r.Locations.Any(l => l.Confidence >= MatchConfidence.Likely));
            warnings.Add($"Voor {located} van de {result.Count} credentials is de Key Vault-locatie zeker of waarschijnlijk gevonden.");
        }
        if (result.Any(i => i.Owners.Count == 0))
        {
            warnings.Add("Een aantal apps heeft geen eigenaar. Zoek eerst uit wie de app gebruikt voor je een secret roteert of verwijdert.");
        }

        return new ReportResult<AppCredential>(result, warnings, DateTimeOffset.Now);
    }

    // ---- Step 1: app registrations from Graph

    private sealed record Credential(CredentialKind Kind, string KeyId, string? Description, string? Thumbprint, DateTimeOffset? Start, DateTimeOffset? End);

    private async Task<(List<AppCredential> Items, int Apps, int Credentials)> ReadCredentialsAsync(DateTimeOffset now, IProgress<string>? progress, CancellationToken ct)
    {
        var items = new List<AppCredential>();
        var appCount = 0;
        var credentialCount = 0;

        progress?.Report("App registrations ophalen uit Entra ID…");
        try
        {
            await foreach (var app in graph.GetApplicationsWithCredentialsAsync(ct))
            {
                appCount++;
                if (appCount % 100 == 0) progress?.Report($"App registrations ophalen… {appCount}");

                var credentials = Read(app, "passwordCredentials", CredentialKind.Secret)
                    .Concat(Read(app, "keyCredentials", CredentialKind.Certificate))
                    .ToList();
                credentialCount += credentials.Count;

                var hasValid = credentials.Any(c => c.End is null || c.End > now);
                var owners = Owners(app);
                var appId = app.Str("appId") ?? "";

                foreach (var c in credentials)
                {
                    if (Evaluate(c, now) is not { } verdict) continue;

                    items.Add(new AppCredential(
                        AppObjectId: app.Str("id") ?? "",
                        AppId: appId,
                        AppName: app.Str("displayName") ?? appId,
                        Owners: owners,
                        Kind: c.Kind,
                        KeyId: c.KeyId,
                        Description: c.Description,
                        Thumbprint: c.Thumbprint,
                        Start: c.Start,
                        End: c.End,
                        State: verdict.State,
                        Severity: verdict.Severity,
                        AppHasValidCredential: hasValid));
                }
            }
        }
        catch (AzureApiException ex) when (ex.IsForbidden)
        {
            throw new InvalidOperationException(
                "Je account mag de app registrations niet lezen (Microsoft Graph gaf 'Forbidden'). " +
                "Daarvoor is Application.Read.All of Directory.Read.All nodig, of een gewoon member-account.", ex);
        }

        return (items, appCount, credentialCount);
    }

    private static IEnumerable<Credential> Read(JsonElement app, string property, CredentialKind kind)
    {
        if (!app.TryGetProperty(property, out var list) || list.ValueKind != JsonValueKind.Array) yield break;
        foreach (var c in list.EnumerateArray())
        {
            // For certificates, customKeyIdentifier is the (base64) SHA-1 thumbprint.
            var thumbprint = kind == CredentialKind.Certificate ? HexFromBase64(c.Str("customKeyIdentifier")) : null;
            yield return new Credential(kind, c.Str("keyId") ?? "", c.Str("displayName"), thumbprint, c.Date("startDateTime"), c.Date("endDateTime"));
        }
    }

    private static IReadOnlyList<string> Owners(JsonElement app) =>
        app.TryGetProperty("owners", out var owners) && owners.ValueKind == JsonValueKind.Array
            ? owners.EnumerateArray()
                .Select(o => o.Str("userPrincipalName") ?? o.Str("displayName") ?? o.Str("id") ?? "")
                .Where(s => s.Length > 0)
                .ToList()
            : [];

    private static (CredentialState State, Severity Severity)? Evaluate(Credential c, DateTimeOffset now)
    {
        if (c.End is not { } end)
            return (CredentialState.LongLived, Severity.Medium);

        var daysLeft = (end - now).TotalDays;
        if (daysLeft < 0) return (CredentialState.Expired, Severity.Low);
        if (daysLeft <= UrgentDays) return (CredentialState.ExpiringSoon, Severity.High);
        if (daysLeft <= ExpiringSoonDays) return (CredentialState.ExpiringSoon, Severity.Medium);

        // Certificates commonly live 1-2 years; only flag secrets for lifetime.
        if (c.Kind == CredentialKind.Secret && c.Start is { } start && (end - start).TotalDays > MaxSecretLifetimeDays)
            return (CredentialState.LongLived, Severity.Medium);

        return null;
    }

    // ---- Step 2: Key Vault metadata (never values)

    private sealed record VaultItem(
        ResourceRef Vault,
        bool IsCertificate,
        string Name,
        DateTimeOffset? Expires,
        IReadOnlyDictionary<string, string> Tags,
        string? ContentType,
        string? Thumbprint);

    private async Task<(IReadOnlyList<VaultItem> Items, List<string> Warnings)> ScanKeyVaultsAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress?.Report("Key Vaults zoeken…");
        if (await keyVault.CheckAccessAsync(ct) is { } tokenError)
        {
            return ([], [$"Key Vaults niet doorzocht: er kon geen Key Vault-token opgehaald worden ({tokenError}). " +
                         "In de gehoste versie heeft de app registration daarvoor de permissie Azure Key Vault 'user_impersonation' (met consent) nodig."]);
        }

        var subscriptionNames = await ResourceRows.SubscriptionNamesAsync(arm, ct);
        var vaults = (await resourceGraph.QueryAsync(VaultQuery, ct: ct))
            .Select(r => (Ref: ResourceRows.ToRef(r, subscriptionNames), Uri: r.Str("vaultUri")))
            .Where(v => !string.IsNullOrEmpty(v.Uri))
            .ToList();

        var items = new ConcurrentBag<VaultItem>();
        var noAccess = new ConcurrentBag<string>();
        var unreachable = new ConcurrentBag<string>();
        var done = 0;

        await Parallel.ForEachAsync(vaults, new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = ct }, async (vault, token) =>
        {
            try
            {
                await foreach (var s in keyVault.ListSecretsAsync(vault.Uri!, token))
                {
                    // Secrets backing a Key Vault certificate are matched via the certificate instead.
                    if (s.Bool("managed") == true) continue;
                    items.Add(new VaultItem(vault.Ref, false, ItemName(s), Expiry(s), s.StringMap("tags"), s.Str("contentType"), null));
                }
                await foreach (var c in keyVault.ListCertificatesAsync(vault.Uri!, token))
                {
                    items.Add(new VaultItem(vault.Ref, true, ItemName(c), Expiry(c), c.StringMap("tags"), null, HexFromBase64(c.Str("x5t"))));
                }
            }
            catch (AzureApiException ex) when (ex.IsForbidden && IsFirewall(ex))
            {
                unreachable.Add(vault.Ref.Name);
            }
            catch (AzureApiException ex) when (ex.IsForbidden)
            {
                noAccess.Add(vault.Ref.Name);
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !token.IsCancellationRequested)
            {
                // Private endpoint only (DNS → private IP) or timeout.
                unreachable.Add(vault.Ref.Name);
            }

            var count = Interlocked.Increment(ref done);
            if (count % 5 == 0 || count == vaults.Count) progress?.Report($"Key Vaults doorzoeken… {count}/{vaults.Count}");
        });

        var warnings = new List<string>();
        var failed = noAccess.Count + unreachable.Count;
        warnings.Add($"{vaults.Count - failed} van de {vaults.Count} Key Vaults doorzocht (alleen namen, vervaldatums, tags en thumbprints, geen waarden).");
        if (noAccess.Count > 0)
            warnings.Add($"Geen leesrechten op {noAccess.Count} Key Vault(s) (nodig: Key Vault Reader of een access policy met 'List'): {Names(noAccess)}.");
        if (unreachable.Count > 0)
            warnings.Add($"{unreachable.Count} Key Vault(s) niet bereikbaar vanaf deze machine (firewall of alleen private endpoint): {Names(unreachable)}.");

        return (items.ToList(), warnings);
    }

    private static string ItemName(JsonElement item) =>
        (item.Str("id") ?? "").TrimEnd('/').Split('/').LastOrDefault() ?? "";

    private static DateTimeOffset? Expiry(JsonElement item) =>
        item.TryGetProperty("attributes", out var attributes) && attributes.TryGetProperty("exp", out var exp) && exp.TryGetInt64(out var seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : null;

    private static bool IsFirewall(AzureApiException ex) =>
        ex.ApiMessage.Contains("firewall", StringComparison.OrdinalIgnoreCase)
        || ex.ApiMessage.Contains("Client address is not authorized", StringComparison.OrdinalIgnoreCase)
        || ex.ApiMessage.Contains("Public network access is disabled", StringComparison.OrdinalIgnoreCase);

    private static string Names(IEnumerable<string> names)
    {
        var list = names.Order(StringComparer.OrdinalIgnoreCase).ToList();
        return list.Count <= 10 ? string.Join(", ", list) : string.Join(", ", list.Take(10)) + $" en {list.Count - 10} andere";
    }

    // ---- Step 3: match credentials to Key Vault items

    private static IReadOnlyList<KeyVaultMatch> Match(AppCredential c, IReadOnlyList<VaultItem> vaultItems)
    {
        if (vaultItems.Count == 0) return [];

        var matches = new List<KeyVaultMatch>();
        foreach (var item in vaultItems)
        {
            if (Score(c, item) is not { } score) continue;
            matches.Add(new KeyVaultMatch(item.Vault, item.IsCertificate ? "Certificaat" : "Secret", item.Name, item.Expires, score.Confidence, score.Reason));
        }

        return matches
            .OrderByDescending(m => m.Confidence)
            .ThenBy(m => m.Label, StringComparer.OrdinalIgnoreCase)
            .Take(MaxLocationsPerCredential)
            .ToList();
    }

    private static (MatchConfidence Confidence, string Reason)? Score(AppCredential c, VaultItem item)
    {
        if (c.Kind == CredentialKind.Certificate)
        {
            return item.IsCertificate && c.Thumbprint is not null && c.Thumbprint == item.Thumbprint
                ? (MatchConfidence.Certain, "zelfde thumbprint")
                : null;
        }
        if (item.IsCertificate) return null;

        var metadata = new[] { item.Name, item.ContentType }.Concat(item.Tags.Keys).Concat(item.Tags.Values);
        if (metadata.Any(m => Contains(m, c.AppId)))
            return (MatchConfidence.Certain, "app id in naam, tag of content type");
        if (metadata.Any(m => Contains(m, c.KeyId)))
            return (MatchConfidence.Certain, "key id van het secret in een tag");

        var sameExpiry = c.End is { } end && item.Expires is { } exp ? Math.Abs((end - exp).TotalHours) : double.MaxValue;
        var similarName = NameLooksLike(item.Name, c.AppName) || NameLooksLike(item.Name, c.Description);

        if (sameExpiry <= 0.05) // within 3 minutes: set by the same script
            return (MatchConfidence.Likely, similarName ? "zelfde vervaldatum en naam lijkt op de app" : "exact dezelfde vervaldatum");
        if (sameExpiry <= 24 && similarName)
            return (MatchConfidence.Likely, "vervaldatum (zelfde dag) en naam lijkt op de app");
        if (similarName)
            return (MatchConfidence.Possible, "naam lijkt op de app of de omschrijving van het secret");

        return null;
    }

    private static bool Contains(string? haystack, string needle) =>
        haystack is not null && needle.Length > 0 && haystack.Contains(needle, StringComparison.OrdinalIgnoreCase);

    /// <summary>"kv secret 'sp-myapp-secret'" vs app "My App": compares letters and digits only, at least 5 characters.</summary>
    private static bool NameLooksLike(string secretName, string? other)
    {
        var a = Normalize(secretName);
        var b = Normalize(other);
        return a.Length >= 5 && b.Length >= 5 && (a.Contains(b, StringComparison.Ordinal) || b.Contains(a, StringComparison.Ordinal));
    }

    private static string Normalize(string? value) =>
        new((value ?? "").ToLowerInvariant().Where(char.IsLetterOrDigit).ToArray());

    private static string? HexFromBase64(string? value)
    {
        if (string.IsNullOrEmpty(value)) return null;
        var base64 = value.Replace('-', '+').Replace('_', '/');
        base64 = base64.PadRight(base64.Length + (4 - base64.Length % 4) % 4, '=');
        try { return Convert.ToHexString(Convert.FromBase64String(base64)); }
        catch (FormatException) { return null; }
    }

    // ---- Step 4: fix text and commands, now that the location is known

    private static AppCredential Finish(AppCredential c, IReadOnlyList<KeyVaultMatch> locations, DateTimeOffset now)
    {
        var target = locations.FirstOrDefault(l => l.Confidence >= MatchConfidence.Likely && l.ItemKind == "Secret");
        var certFlag = c.Kind == CredentialKind.Certificate ? " --cert" : "";
        var delete = $"az ad app credential delete --id {c.AppId} --key-id {c.KeyId}{certFlag}";
        var newEnd = now.AddDays(SuggestedLifetimeDays);

        string fix, command;
        string? cleanup = null;

        if (c.State == CredentialState.Expired)
        {
            fix = c.AppHasValidCredential
                ? "Verlopen credential verwijderen (de app heeft nog een geldige)."
                : "Geen enkele geldige credential meer: wordt de app nog gebruikt? Zo niet, de app opruimen; anders roteren.";
            command = delete;
            if (target is not null)
            {
                fix += $" Het verlopen secret staat waarschijnlijk nog in Key Vault {target.Vault.Name}.";
                cleanup = $"az keyvault secret delete --vault-name {target.Vault.Name} --name {target.ItemName}";
            }
        }
        else if (c.Kind == CredentialKind.Certificate)
        {
            fix = "Nieuw certificaat toevoegen, de applicatie laten overschakelen en daarna het oude verwijderen.";
            command = $"az ad app credential reset --id {c.AppId} --append --cert @<nieuw-certificaat.pem>";
            cleanup = delete;
        }
        else
        {
            var label = (c.Description ?? "rotated").Replace("\"", "");
            var reset = $"az ad app credential reset --id {c.AppId} --append --display-name \"{label}\" --end-date {newEnd:yyyy-MM-dd}";
            fix = c.State == CredentialState.ExpiringSoon
                ? $"Nieuw secret aanmaken (max. {SuggestedLifetimeDays} dagen), in de applicatie / Key Vault zetten en daarna het oude verwijderen."
                : $"Vervangen door een secret van max. {SuggestedLifetimeDays} dagen, of beter: overstappen op managed identity of federated credentials.";

            // Known vault: write the new secret straight into it, without the value ever being printed.
            command = target is null
                ? reset
                : $"NEW=$({reset} --query password -o tsv) && az keyvault secret set --vault-name {target.Vault.Name} --name {target.ItemName} --value \"$NEW\" --expires {newEnd:yyyy-MM-dd}T00:00:00Z --output none && unset NEW";
            cleanup = delete;
        }

        return c with { Locations = locations, Fix = fix, AzCli = command, AzCliCleanup = cleanup };
    }
}
