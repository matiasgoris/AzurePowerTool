using System.Text.Json;
using AzurePowerTool.Core.Clients;
using AzurePowerTool.Core.Http;
using AzurePowerTool.Core.Models;

namespace AzurePowerTool.Core.Reports;

/// <summary>
/// Security settings on storage accounts, Key Vaults, App Services / Function Apps and SQL servers.
/// One Resource Graph query; each check is a small rule below with its fix command.
/// Resources in a network security perimeter (NSP) in Enforced mode count as network-secured: the
/// "open network" checks are not reported for them. NSP associations come from ARM (Resource Graph doesn't index them).
/// </summary>
public sealed class InsecureConfigReport(ResourceGraphClient resourceGraph, ArmClient arm)
{
    private const string Query = """
        resources
        | where type in~ ('microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults', 'microsoft.web/sites', 'microsoft.sql/servers')
        | project id, name, type, kind, subscriptionId, resourceGroup, location,
            allowBlobPublicAccess = properties.allowBlobPublicAccess,
            minimumTlsVersion = tostring(properties.minimumTlsVersion),
            supportsHttpsTrafficOnly = properties.supportsHttpsTrafficOnly,
            allowSharedKeyAccess = properties.allowSharedKeyAccess,
            networkDefaultAction = tostring(properties.networkAcls.defaultAction),
            publicNetworkAccess = tostring(properties.publicNetworkAccess),
            enablePurgeProtection = properties.enablePurgeProtection,
            enableRbacAuthorization = properties.enableRbacAuthorization,
            httpsOnly = properties.httpsOnly,
            minimalTlsVersion = tostring(properties.minimalTlsVersion)
        """;

    private const string OpenNetworkCheck = "Bereikbaar vanuit alle netwerken";
    private const string PublicNetworkCheck = "Publieke netwerktoegang aan";
    private static readonly HashSet<string> NetworkChecks = [OpenNetworkCheck, PublicNetworkCheck];

    public async Task<ReportResult<ConfigFinding>> RunAsync(IProgress<string>? progress = null, CancellationToken ct = default)
    {
        progress?.Report("Subscriptions ophalen…");
        var subscriptionNames = await ResourceRows.SubscriptionNamesAsync(arm, ct);

        progress?.Report($"Configuratie ophalen via Resource Graph ({subscriptionNames.Count} subscriptions)…");
        var rows = await resourceGraph.QueryAsync(Query, ct: ct);

        var (perimeters, perimeterWarnings) = await NspLookup.GetAssociationsAsync(resourceGraph, arm, progress, ct);

        var findings = new List<ConfigFinding>();
        var securedByNsp = 0;
        foreach (var row in rows)
        {
            var resource = ResourceRows.ToRef(row, subscriptionNames);
            var found = resource.Type.ToLowerInvariant() switch
            {
                "microsoft.storage/storageaccounts" => Storage(resource, row),
                "microsoft.keyvault/vaults" => KeyVault(resource, row),
                "microsoft.web/sites" => WebApp(resource, row),
                "microsoft.sql/servers" => Sql(resource, row),
                _ => [],
            };
            var nsp = perimeters.GetValueOrDefault(resource.Id);

            foreach (var finding in found)
            {
                if (nsp is null || !NetworkChecks.Contains(finding.Check))
                {
                    findings.Add(finding with { Nsp = nsp });
                }
                else if (nsp.IsEnforced)
                {
                    securedByNsp++;
                }
                else
                {
                    // In a perimeter, but only Learning/Audit: the fix is enforcing the perimeter, not touching the resource.
                    findings.Add(finding with
                    {
                        Nsp = nsp,
                        Current = $"{finding.Current} · NSP {nsp.Label}",
                        Expected = "NSP-koppeling op Enforced",
                        Impact = $"In {nsp.AccessMode}-modus wordt verkeer buiten de perimeter alleen gelogd. Na Enforced wordt het geblokkeerd " +
                                 "als er geen access rule voor is: controleer eerst de NSP-logs.",
                        AzCli = $"az resource update --ids \"{nsp.Id}\" --set properties.accessMode=Enforced --api-version 2024-07-01",
                    });
                }
            }
        }

        var ordered = findings
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Category)
            .ThenBy(f => f.Check)
            .ThenBy(f => f.Resource.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var warnings = new List<string>
        {
            $"{rows.Count} resources gecontroleerd, {ordered.Count} bevinding(en) op {ordered.Select(f => f.Resource.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count()} resource(s).",
            "Kijk naar de kolom 'Impact' voor je een fix uitvoert: sommige wijzigingen kunnen applicaties breken of zijn onomkeerbaar.",
        };
        if (securedByNsp > 0)
        {
            warnings.Add($"{securedByNsp} netwerkbevinding(en) niet gemeld: die resources zitten in een network security perimeter in Enforced-modus.");
        }
        warnings.AddRange(perimeterWarnings);

        return new ReportResult<ConfigFinding>(ordered, warnings, DateTimeOffset.Now);
    }

    private static string NameArgs(ResourceRef r) => $"--name {r.Name} --resource-group {r.ResourceGroup}";

    private static bool IsModernTls(string? version, params string[] ok) =>
        version is { Length: > 0 } v && ok.Contains(v, StringComparer.OrdinalIgnoreCase);

    /// <summary>"Disabled", or "SecuredByPerimeter" (the NSP decides).</summary>
    private static bool PublicAccessOff(JsonElement row) =>
        row.Str("publicNetworkAccess") is { } pna
        && (pna.Equals("Disabled", StringComparison.OrdinalIgnoreCase) || pna.Equals("SecuredByPerimeter", StringComparison.OrdinalIgnoreCase));

    private static bool NetworkOpen(JsonElement row) =>
        !PublicAccessOff(row)
        && !"Deny".Equals(row.Str("networkDefaultAction"), StringComparison.OrdinalIgnoreCase);

    private static IEnumerable<ConfigFinding> Storage(ResourceRef r, JsonElement row)
    {
        const string category = "Storage";
        var cli = $"az storage account update --ids \"{r.Id}\"";

        // Null on older accounts means "allowed".
        if (row.Bool("allowBlobPublicAccess") != false)
            yield return new ConfigFinding(r, category, "Anonieme blob-toegang toegestaan", Severity.High,
                row.Bool("allowBlobPublicAccess") is null ? "niet ingesteld (= toegestaan)" : "true", "false",
                "Containers die nu publiek gelezen worden, zijn daarna niet meer bereikbaar zonder authenticatie.",
                $"{cli} --allow-blob-public-access false");

        if (row.Bool("supportsHttpsTrafficOnly") == false)
            yield return new ConfigFinding(r, category, "HTTP (onversleuteld) toegestaan", Severity.High,
                "false", "true", "Clients die nog via http:// verbinden, falen.",
                $"{cli} --https-only true");

        if (!IsModernTls(row.Str("minimumTlsVersion"), "TLS1_2", "TLS1_3"))
            yield return new ConfigFinding(r, category, "Minimale TLS-versie te laag", Severity.Medium,
                row.Str("minimumTlsVersion") is { Length: > 0 } tls ? tls : "niet ingesteld (= TLS1_0)", "TLS1_2",
                "Zeer oude clients (TLS 1.0/1.1) kunnen niet meer verbinden.",
                $"{cli} --min-tls-version TLS1_2");

        if (NetworkOpen(row))
            yield return new ConfigFinding(r, category, OpenNetworkCheck, Severity.Medium,
                "default action Allow", "Deny + firewall/private endpoint",
                "Voeg eerst de nodige netwerkregels of een private endpoint toe, anders verliezen applicaties de toegang.",
                $"{cli} --default-action Deny");

        if (row.Bool("allowSharedKeyAccess") != false)
            yield return new ConfigFinding(r, category, "Toegang met account keys / SAS toegestaan", Severity.Low,
                row.Bool("allowSharedKeyAccess") is null ? "niet ingesteld (= toegestaan)" : "true", "false (alleen Entra ID)",
                "Alles wat met een connection string, account key of SAS-token werkt, breekt. Eerst overstappen op managed identity.",
                $"{cli} --allow-shared-key-access false");
    }

    private static IEnumerable<ConfigFinding> KeyVault(ResourceRef r, JsonElement row)
    {
        const string category = "Key Vault";
        var cli = $"az keyvault update {NameArgs(r)}";

        // Soft delete is enforced on every vault nowadays, so it is not checked.
        if (row.Bool("enablePurgeProtection") != true)
            yield return new ConfigFinding(r, category, "Purge protection uitgeschakeld", Severity.Medium,
                "niet ingesteld", "true",
                "Onomkeerbaar: purge protection kan daarna niet meer uitgezet worden, en verwijderde vaults blijven de retentieperiode bestaan.",
                $"{cli} --enable-purge-protection true");

        if (NetworkOpen(row))
            yield return new ConfigFinding(r, category, OpenNetworkCheck, Severity.Medium,
                "default action Allow", "Deny + firewall/private endpoint",
                "Voeg eerst de nodige netwerkregels of een private endpoint toe, anders verliezen applicaties de toegang.",
                $"{cli} --default-action Deny");

        if (row.Bool("enableRbacAuthorization") != true)
            yield return new ConfigFinding(r, category, "Access policies in plaats van Azure RBAC", Severity.Low,
                "access policies", "Azure RBAC",
                "Bestaande access policies werken daarna niet meer: ken eerst de juiste RBAC-rollen toe (bv. Key Vault Secrets User).",
                $"{cli} --enable-rbac-authorization true");
    }

    private static IEnumerable<ConfigFinding> WebApp(ResourceRef r, JsonElement row)
    {
        var kind = row.Str("kind") ?? "";
        var category = kind.Contains("functionapp", StringComparison.OrdinalIgnoreCase) ? "Function App" : "App Service";

        if (row.Bool("httpsOnly") != true)
            yield return new ConfigFinding(r, category, "HTTP (onversleuteld) toegestaan", Severity.High,
                "httpsOnly false", "httpsOnly true", "Verkeer via http:// wordt daarna doorgestuurd naar https://.",
                $"az resource update --ids \"{r.Id}\" --set properties.httpsOnly=true");
    }

    private static IEnumerable<ConfigFinding> Sql(ResourceRef r, JsonElement row)
    {
        const string category = "SQL";
        var cli = $"az sql server update {NameArgs(r)}";

        if (!PublicAccessOff(row))
            yield return new ConfigFinding(r, category, PublicNetworkCheck, Severity.Medium,
                row.Str("publicNetworkAccess") is { Length: > 0 } pna ? pna : "niet ingesteld", "Disabled + private endpoint",
                "Alleen nog bereikbaar via private endpoint: zet dat eerst op, anders verliezen applicaties de verbinding.",
                $"{cli} --enable-public-network false");

        if (!IsModernTls(row.Str("minimalTlsVersion"), "1.2", "1.3"))
            yield return new ConfigFinding(r, category, "Minimale TLS-versie te laag", Severity.Medium,
                row.Str("minimalTlsVersion") is { Length: > 0 } tls ? tls : "niet ingesteld", "1.2",
                "Zeer oude clients (TLS 1.0/1.1) kunnen niet meer verbinden.",
                $"{cli} --minimal-tls-version 1.2");
    }
}
