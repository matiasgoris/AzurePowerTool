namespace AzurePowerTool.Core.Models;

/// <summary>How urgent a finding is. Higher value = more urgent (filters use "at least").</summary>
public enum Severity { Low = 1, Medium = 2, High = 3 }

public static class SeverityExtensions
{
    public static string Label(this Severity severity) => severity switch
    {
        Severity.High => "Hoog",
        Severity.Medium => "Middel",
        _ => "Laag",
    };
}

/// <summary>An Azure resource as found in Resource Graph.</summary>
public sealed record ResourceRef(
    string Id,
    string Name,
    string Type,
    string SubscriptionId,
    string SubscriptionName,
    string ResourceGroup,
    string Location);

// ---- Report: app registration secrets and certificates

public enum CredentialKind { Secret, Certificate }

public enum CredentialState { Expired, ExpiringSoon, LongLived }

public sealed record AppCredential(
    string AppObjectId,
    string AppId,
    string AppName,
    IReadOnlyList<string> Owners,
    CredentialKind Kind,
    string KeyId,
    string? Description,
    string? Thumbprint,
    DateTimeOffset? Start,
    DateTimeOffset? End,
    CredentialState State,
    Severity Severity,
    bool AppHasValidCredential)
{
    /// <summary>Key Vault secrets/certificates that (probably) hold this credential, best match first.</summary>
    public IReadOnlyList<KeyVaultMatch> Locations { get; init; } = [];

    public string Fix { get; init; } = "";

    /// <summary>Main remediation command (rotate, or delete when expired).</summary>
    public string AzCli { get; init; } = "";

    /// <summary>Follow-up command, run once the application uses the new credential. Null = none.</summary>
    public string? AzCliCleanup { get; init; }

    public int? DaysLeft => End is { } end ? (int)Math.Floor((end - DateTimeOffset.UtcNow).TotalDays) : null;

    public string StateLabel => State switch
    {
        CredentialState.Expired => "Verlopen",
        CredentialState.ExpiringSoon => "Verloopt binnenkort",
        _ => End is null ? "Geen einddatum" : "Te lang geldig",
    };
}

public enum MatchConfidence { Possible = 1, Likely = 2, Certain = 3 }

/// <summary>
/// A Key Vault item that matches an app credential. Entra ID doesn't record where a secret is stored,
/// so secrets are matched on app id / key id in name or tags, expiry date and name; certificates on thumbprint.
/// </summary>
public sealed record KeyVaultMatch(
    ResourceRef Vault,
    string ItemKind,
    string ItemName,
    DateTimeOffset? Expires,
    MatchConfidence Confidence,
    string Reason)
{
    public string ConfidenceLabel => Confidence switch
    {
        MatchConfidence.Certain => "Zeker",
        MatchConfidence.Likely => "Waarschijnlijk",
        _ => "Mogelijk",
    };

    public string Label => $"{Vault.Name}/{ItemName}";
}

// ---- Report: unused (orphaned) resources

public sealed record UnusedResource(
    ResourceRef Resource,
    string Kind,
    string? Detail,
    string? ManagedBy,
    DateTimeOffset? CreatedTime,
    IReadOnlyDictionary<string, string> Tags)
{
    public int? AgeInDays => CreatedTime is { } created ? (int)(DateTimeOffset.UtcNow - created).TotalDays : null;

    public string AzCli => $"az resource delete --ids \"{Resource.Id}\"";
}

// ---- Report: NSG rules open to the internet

public sealed record OpenPortRule(
    ResourceRef Nsg,
    string RuleId,
    string RuleName,
    int Priority,
    string Protocol,
    IReadOnlyList<string> Sources,
    IReadOnlyList<string> Ports,
    IReadOnlyList<string> ExposedServices,
    Severity Severity,
    int AttachedSubnets,
    int AttachedNics)
{
    public bool IsAttached => AttachedSubnets + AttachedNics > 0;

    public string AttachedLabel => IsAttached
        ? string.Join(", ", new[] { AttachedSubnets > 0 ? $"{AttachedSubnets} subnet(s)" : null, AttachedNics > 0 ? $"{AttachedNics} NIC(s)" : null }.Where(s => s is not null))
        : "niet gekoppeld";

    public string AzCliRestrict => $"az network nsg rule update --ids \"{RuleId}\" --source-address-prefixes <TOEGELATEN_IP_OF_RANGE>";

    public string AzCliDelete => $"az network nsg rule delete --ids \"{RuleId}\"";
}

// ---- Report: insecure resource configuration

public sealed record ConfigFinding(
    ResourceRef Resource,
    string Category,
    string Check,
    Severity Severity,
    string Current,
    string Expected,
    string? Impact,
    string AzCli)
{
    /// <summary>The network security perimeter the resource is associated with, if any.</summary>
    public NspAssociation? Nsp { get; init; }
}

/// <summary>A resource's association with a network security perimeter. Enforced = public traffic is governed by the perimeter.</summary>
public sealed record NspAssociation(string Id, string PerimeterName, string AccessMode)
{
    public bool IsEnforced => AccessMode.Equals("Enforced", StringComparison.OrdinalIgnoreCase);

    public string Label => $"{PerimeterName} ({AccessMode})";
}

// ---- Report: orphaned DNS records

public enum DnsZoneKind { Private, Public }

/// <summary>How a DNS record was judged. Everything except <see cref="None"/> means: verified orphaned.</summary>
public enum DnsCheckBasis
{
    /// <summary>The IP lies in a subnet we can fully see, and no resource in it holds that IP.</summary>
    Subnet,
    /// <summary>The IP lies in the address space of a VNet, but in none of its subnets.</summary>
    Vnet,
    /// <summary>The alias target resource no longer exists.</summary>
    AliasTarget,
    /// <summary>The CNAME target does not exist (missing in our own zone, or NXDOMAIN under a public Azure domain).</summary>
    CnameTarget,
    /// <summary>Could not be verified either way.</summary>
    None,
}

/// <summary>
/// One target (IP or host name) of a DNS record that looks orphaned. A record set with several IPs
/// gives one row per dead IP; the remaining IPs are in <see cref="OtherTargets"/>.
/// </summary>
public sealed record OrphanedDnsRecord(
    ResourceRef Zone,
    DnsZoneKind ZoneKind,
    string RecordName,
    string RecordType,
    string Fqdn,
    string Target,
    DnsCheckBasis Basis,
    string Reason,
    Severity Severity,
    int? Ttl,
    IReadOnlyList<string> OtherTargets,
    /// <summary>VNet(s) and subnet(s) the IP was checked against, e.g. "vnet-hub / snet-app (10.0.1.0/24)". Empty = none.</summary>
    IReadOnlyList<string> CheckedNetworks,
    string AzCliDelete)
{
    public bool Verified => Basis != DnsCheckBasis.None;

    public string VerificationLabel => Basis switch
    {
        DnsCheckBasis.Subnet => "Geverifieerd op subnet",
        DnsCheckBasis.Vnet => "Geverifieerd op VNet",
        DnsCheckBasis.AliasTarget => "Geverifieerd: aliasdoel weg",
        DnsCheckBasis.CnameTarget => "Geverifieerd: CNAME-doel weg",
        _ => "Niet verifieerbaar",
    };
}

// ---- Report: publicly reachable storage accounts without NSP, exclusion tag or private endpoint

public enum StorageExposure
{
    /// <summary>Public access on, firewall denies by default and has no IP or VNet rules (only trusted services / resource instances).</summary>
    NoRules,
    /// <summary>Public access on, firewall allows selected IP ranges or VNets.</summary>
    SelectedNetworks,
    /// <summary>Default action Allow: reachable from the whole internet.</summary>
    AllNetworks,
}

public sealed record PublicStorageAccount(
    ResourceRef Resource,
    StorageExposure Exposure,
    Severity Severity,
    int IpRules,
    int VnetRules,
    /// <summary>Private endpoint connections that are not approved (pending / rejected): they don't protect anything yet.</summary>
    int UnapprovedPrivateEndpoints,
    bool AnonymousBlobAccess,
    string? Kind,
    string? Sku,
    IReadOnlyDictionary<string, string> Tags)
{
    /// <summary>Set when the account sits in a perimeter that is not Enforced (Learning / Audit): traffic is only logged, not blocked.</summary>
    public NspAssociation? Nsp { get; init; }

    public string? AzCliEnforceNsp => Nsp is { } nsp
        ? $"az resource update --ids \"{nsp.Id}\" --set properties.accessMode=Enforced --api-version 2024-07-01"
        : null;

    public string ExposureLabel => Exposure switch
    {
        StorageExposure.AllNetworks => "Alle netwerken",
        StorageExposure.SelectedNetworks => "Geselecteerde netwerken",
        _ => "Firewall zonder regels",
    };

    public string RulesLabel => Exposure == StorageExposure.AllNetworks
        ? "default action Allow"
        : $"{IpRules} IP-regel(s), {VnetRules} VNet-regel(s)";

    public string AzCliDisablePublic => $"az storage account update --ids \"{Resource.Id}\" --public-network-access Disabled";

    public string AzCliExclude => $"az tag update --resource-id \"{Resource.Id}\" --operation Merge --tags nsp=excluded";
}

// ---- Report: SAS / account key usage on storage accounts

public enum SasUsageState
{
    /// <summary>Requests signed with a SAS token were seen.</summary>
    SasUsed,
    /// <summary>No SAS, but requests signed with the account key.</summary>
    KeyOnly,
    /// <summary>Neither SAS nor account key: shared key access can be switched off.</summary>
    NotUsed,
    /// <summary>The metrics could not be read.</summary>
    Unknown,
}

/// <summary>Request counts per authentication type over the measured period (Azure Monitor "Transactions" metric).</summary>
public sealed record StorageSasUsage(
    ResourceRef Resource,
    SasUsageState State,
    /// <summary>False = account keys and account/service SAS are blocked; only user delegation SAS still works.</summary>
    bool SharedKeyAllowed,
    string? SasExpirationPeriod,
    long SasRequests,
    long DelegationSasRequests,
    long AccountKeyRequests,
    long OAuthRequests,
    long AnonymousRequests,
    DateTimeOffset? LastSasUse,
    string? Kind,
    string? Sku,
    IReadOnlyDictionary<string, string> Tags)
{
    public long TotalSasRequests => SasRequests + DelegationSasRequests;

    /// <summary>Value of the <c>sourcecode</c> tag (tag names are case-insensitive in Azure), usually a repo URL.</summary>
    public string? SourceCode => Tags.FirstOrDefault(t => t.Key.Equals("sourcecode", StringComparison.OrdinalIgnoreCase)).Value is { Length: > 0 } v
        ? v.Trim()
        : null;

    public string StateLabel => State switch
    {
        SasUsageState.SasUsed => "SAS in gebruik",
        SasUsageState.KeyOnly => "Alleen account key",
        SasUsageState.NotUsed => "Geen key- of SAS-gebruik",
        _ => "Onbekend (geen metrics)",
    };

    /// <summary>Only when nothing uses keys or SAS: otherwise this breaks clients.</summary>
    public string? AzCliDisableSharedKey => State == SasUsageState.NotUsed && SharedKeyAllowed
        ? $"az storage account update --ids \"{Resource.Id}\" --allow-shared-key-access false"
        : null;
}
