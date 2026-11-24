using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using AzurePowerTool.Core.Clients;
using AzurePowerTool.Core.Http;
using AzurePowerTool.Core.Models;

namespace AzurePowerTool.Core.Reports;

/// <summary>
/// DNS records (private and public Azure DNS zones) that point to something that no longer exists.
/// <list type="bullet">
/// <item>A records: the IP is held by no resource we can see. It is <em>verified</em> orphaned only when it lies in a
/// VNet we can read, and the subnet it lies in is fully visible (every IP configuration in it belongs to a NIC or load
/// balancer we can read, no delegation, no service links). Otherwise: not verifiable, with the reason.</item>
/// <item>CNAME records: the target is missing in one of our own zones, or doesn't resolve (NXDOMAIN).</item>
/// <item>Alias records: the target resource no longer exists.</item>
/// </list>
/// Record sets are read from ARM (Resource Graph doesn't index them); everything else comes from Resource Graph.
/// </summary>
public sealed class OrphanedDnsRecordsReport(ResourceGraphClient resourceGraph, ArmClient arm, DnsOverHttpsResolver dns)
{
    private const string ZonesQuery = """
        resources
        | where type in~ ('microsoft.network/privatednszones', 'microsoft.network/dnszones')
        | project id, name, type, subscriptionId, resourceGroup, location
        """;

    private const string VnetsQuery = """
        resources
        | where type =~ 'microsoft.network/virtualnetworks'
        | project id, name, type, subscriptionId, resourceGroup, location, addressPrefixes = properties.addressSpace.addressPrefixes
        """;

    /// <summary>Every place a resource holds an IP. Separate queries: Resource Graph limits the number of unions.</summary>
    private static readonly string[] UsedIpQueries =
    [
        """
        resources | where type =~ 'microsoft.network/networkinterfaces'
        | mv-expand c = properties.ipConfigurations | project id, ip = tostring(c.properties.privateIPAddress)
        """,
        """
        resources | where type =~ 'microsoft.network/loadbalancers'
        | mv-expand c = properties.frontendIPConfigurations | project id, ip = tostring(c.properties.privateIPAddress)
        """,
        """
        resources | where type =~ 'microsoft.network/applicationgateways'
        | mv-expand c = properties.frontendIPConfigurations | project id, ip = tostring(c.properties.privateIPAddress)
        """,
        """
        resources | where type =~ 'microsoft.network/azurefirewalls'
        | mv-expand c = properties.ipConfigurations | project id, ip = tostring(c.properties.privateIPAddress)
        """,
        """
        resources | where type =~ 'microsoft.network/azurefirewalls'
        | project id, ip = tostring(properties.hubIPAddresses.privateIPAddress)
        """,
        """
        resources | where type =~ 'microsoft.network/privateendpoints'
        | mv-expand c = properties.customDnsConfigs | mv-expand a = c.ipAddresses | project id, ip = tostring(a)
        """,
        """
        resources | where type =~ 'microsoft.network/dnsresolvers/inboundendpoints'
        | mv-expand c = properties.ipConfigurations | project id, ip = tostring(c.privateIpAddress)
        """,
        """
        resources | where type =~ 'microsoft.containerinstance/containergroups'
        | project id, ip = tostring(properties.ipAddress.ip)
        """,
        """
        resources | where type =~ 'microsoft.apimanagement/service'
        | mv-expand a = properties.privateIPAddresses | project id, ip = tostring(a)
        """,
        """
        resources | where type =~ 'microsoft.network/publicipaddresses'
        | project id, ip = tostring(properties.ipAddress)
        """,
    ];

    /// <summary>Subnets whose service instances take IPs that are listed nowhere.</summary>
    private static readonly HashSet<string> ServiceSubnets = new(StringComparer.OrdinalIgnoreCase)
    {
        "GatewaySubnet", "AzureFirewallSubnet", "AzureFirewallManagementSubnet", "AzureBastionSubnet", "RouteServerSubnet",
    };

    /// <summary>A CNAME target under one of these public domains that gives NXDOMAIN is gone, also from a private zone.</summary>
    private static readonly string[] AzurePublicSuffixes =
    [
        "windows.net", "azure.com", "azure.net", "azurewebsites.net", "cloudapp.net", "trafficmanager.net", "azureedge.net",
        "azurefd.net", "azure-api.net", "azurecontainer.io", "azurecr.io", "azurestaticapps.net", "azure-devices.net",
        "azuredatabricks.net", "azuresynapse.net", "azurehdinsight.net", "azurecontainerapps.io",
    ];

    private static readonly TimeSpan DnsTimeout = TimeSpan.FromSeconds(5);

    private sealed record Zone(ResourceRef Ref, DnsZoneKind Kind);

    private sealed record RecordSet(Zone Zone, string Name, string Type, string Fqdn, int? Ttl, IReadOnlyList<string> Ips, string? Cname, string? AliasTarget);

    private sealed record Vnet(ResourceRef Ref, IReadOnlyList<IPNetwork> AddressSpace);

    private sealed record Subnet(string Name, IReadOnlyList<IPNetwork> Prefixes, string? NotVerifiableReason, IReadOnlyList<string> VmssIds);

    /// <summary>Outcome of checking one IP against one VNet.</summary>
    private sealed record NetworkCheck(string Label, DnsCheckBasis Basis, string? NotVerifiableReason);

    public async Task<ReportResult<OrphanedDnsRecord>> RunAsync(IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var warnings = new List<string>();

        progress?.Report("Subscriptions ophalen…");
        var subscriptionNames = await ResourceRows.SubscriptionNamesAsync(arm, ct);

        progress?.Report("DNS-zones zoeken…");
        var zones = (await resourceGraph.QueryAsync(ZonesQuery, ct: ct))
            .Select(r => ResourceRows.ToRef(r, subscriptionNames))
            .Select(z => new Zone(z, z.Type.Equals("microsoft.network/privatednszones", StringComparison.OrdinalIgnoreCase) ? DnsZoneKind.Private : DnsZoneKind.Public))
            .ToList();

        if (zones.Count == 0)
        {
            return new ReportResult<OrphanedDnsRecord>([], ["Geen DNS-zones gevonden in de subscriptions die je kan zien."], DateTimeOffset.Now);
        }

        var (records, zoneNames) = await LoadRecordSetsAsync(zones, warnings, progress, ct);

        progress?.Report("IP-adressen in gebruik ophalen…");
        var (usedIps, visibleIds) = await LoadUsedIpsAsync(ct);

        var findings = new ConcurrentBag<OrphanedDnsRecord>();

        await CheckIpRecordsAsync(records, usedIps, visibleIds, subscriptionNames, findings, warnings, progress, ct);
        await CheckCnameRecordsAsync(records, zoneNames, findings, progress, ct);
        await CheckAliasRecordsAsync(records, subscriptionNames, findings, progress, ct);

        var items = findings
            .OrderByDescending(f => f.Verified)
            .ThenByDescending(f => f.Severity)
            .ThenBy(f => f.Zone.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(f => f.RecordName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var verified = items.Count(i => i.Verified);
        warnings.Insert(0, items.Count == 0
            ? $"Geen verweesde records gevonden in {zones.Count} zone(s)."
            : $"{verified} record(s) geverifieerd verweesd, {items.Count - verified} niet verifieerbaar ({zones.Count} zone(s) doorzocht).");
        if (items.Any(i => !i.Verified))
        {
            warnings.Add("'Niet verifieerbaar' betekent: niets gevonden dat het IP of de naam gebruikt, maar we kunnen niet uitsluiten dat iets buiten je zicht het wel doet. Controleer die records zelf voor je iets verwijdert.");
        }

        return new ReportResult<OrphanedDnsRecord>(items, warnings, DateTimeOffset.Now);
    }

    // ---- Loading

    /// <summary>
    /// The A/CNAME/alias record sets, plus per zone name (lowercase) every record name of any type.
    /// The name set is null when a zone with that name couldn't be read (several private zones can share a name).
    /// </summary>
    private async Task<(List<RecordSet> Records, Dictionary<string, HashSet<string>?> ZoneNames)> LoadRecordSetsAsync(
        List<Zone> zones, List<string> warnings, IProgress<string>? progress, CancellationToken ct)
    {
        var records = new ConcurrentBag<RecordSet>();
        var names = new ConcurrentBag<(string Zone, string? Name)>();
        var forbidden = 0;
        var failed = 0;
        var done = 0;

        await Parallel.ForEachAsync(zones, new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = ct }, async (zone, token) =>
        {
            var zoneName = zone.Ref.Name.ToLowerInvariant();
            try
            {
                var local = new List<(string, string?)>();
                await foreach (var item in arm.GetDnsRecordSetsAsync(zone.Ref.Id, zone.Kind == DnsZoneKind.Private, token))
                {
                    local.Add((zoneName, (item.Str("name") ?? "@").ToLowerInvariant()));
                    if (ParseRecordSet(zone, item) is { } record) records.Add(record);
                }
                foreach (var n in local) names.Add(n);
            }
            catch (AzureApiException ex) when (ex.IsForbidden)
            {
                Interlocked.Increment(ref forbidden);
                names.Add((zoneName, null));
            }
            catch (AzureApiException)
            {
                Interlocked.Increment(ref failed);
                names.Add((zoneName, null));
            }

            var count = Interlocked.Increment(ref done);
            progress?.Report($"Records ophalen… {count}/{zones.Count} zones");
        });

        if (forbidden > 0) warnings.Add($"Voor {forbidden} zone(s) mocht je de records niet lezen (nodig: Reader of DNS Zone / Private DNS Zone Reader).");
        if (failed > 0) warnings.Add($"Voor {failed} zone(s) konden de records niet opgehaald worden.");

        var zoneNames = names.GroupBy(n => n.Zone).ToDictionary(
            g => g.Key,
            g => g.Any(n => n.Name is null) ? null : g.Select(n => n.Name!).ToHashSet());
        return (records.ToList(), zoneNames);
    }

    /// <summary>Only A, CNAME and alias records are checked. Auto-registered VM records are managed by Azure itself.</summary>
    private static RecordSet? ParseRecordSet(Zone zone, JsonElement item)
    {
        var type = (item.Str("type") ?? "").Split('/')[^1].ToUpperInvariant();
        if (!item.TryGetProperty("properties", out var props)) return null;
        if (props.Bool("isAutoRegistered") == true) return null;

        var alias = Prop(props, "targetResource") is { } target ? target.Str("id") : null;
        var ips = type == "A" && Prop(props, "aRecords") is { ValueKind: JsonValueKind.Array } a
            ? a.EnumerateArray().Select(r => r.Str("ipv4Address")).OfType<string>().ToList()
            : [];
        var cname = type == "CNAME" && Prop(props, "cnameRecord") is { } c ? c.Str("cname") : null;

        if (alias is not { Length: > 0 } && ips.Count == 0 && cname is not { Length: > 0 }) return null;

        var name = item.Str("name") ?? "@";
        var fqdn = (props.Str("fqdn") ?? (name == "@" ? zone.Ref.Name : $"{name}.{zone.Ref.Name}")).TrimEnd('.');
        return new RecordSet(zone, name, type, fqdn, props.Int("ttl") ?? props.Int("TTL"), ips, cname, alias is { Length: > 0 } ? alias : null);
    }

    /// <summary>Private DNS uses camelCase ("aRecords"), public DNS PascalCase ("ARecords").</summary>
    private static JsonElement? Prop(JsonElement element, string name)
    {
        foreach (var p in element.EnumerateObject())
        {
            if (p.Name.Equals(name, StringComparison.OrdinalIgnoreCase) && p.Value.ValueKind != JsonValueKind.Null) return p.Value;
        }
        return null;
    }

    /// <summary>IP → owning resource id, plus the (lowercase) ids of every resource that holds an IP.</summary>
    private async Task<(ConcurrentDictionary<string, string> UsedIps, HashSet<string> VisibleIds)> LoadUsedIpsAsync(CancellationToken ct)
    {
        var results = await Task.WhenAll(UsedIpQueries.Select(q => resourceGraph.QueryAsync(q, ct: ct)));
        var used = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var visible = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var row in results.SelectMany(r => r))
        {
            if (row.Str("id") is not { } id) continue;
            visible.Add(id);
            if (row.Str("ip") is { Length: > 0 } ip && IPAddress.TryParse(ip, out var parsed)) used.TryAdd(parsed.ToString(), id);
        }
        return (used, visible);
    }

    // ---- A records: IP held by nothing?

    private async Task CheckIpRecordsAsync(
        List<RecordSet> records, ConcurrentDictionary<string, string> usedIps, HashSet<string> visibleIds,
        IReadOnlyDictionary<string, string> subscriptionNames, ConcurrentBag<OrphanedDnsRecord> findings,
        List<string> warnings, IProgress<string>? progress, CancellationToken ct)
    {
        var ipRecords = records.Where(r => r.Ips.Count > 0 && r.AliasTarget is null).ToList();
        var candidateIps = ipRecords.SelectMany(r => r.Ips)
            .Select(ip => IPAddress.TryParse(ip, out var a) ? a : null).OfType<IPAddress>()
            .Where(ip => !usedIps.ContainsKey(ip.ToString()))
            .Distinct()
            .ToList();
        if (candidateIps.Count == 0) return;

        progress?.Report("VNets ophalen…");
        var vnets = (await resourceGraph.QueryAsync(VnetsQuery, ct: ct))
            .Select(r => new Vnet(ResourceRows.ToRef(r, subscriptionNames), Networks(r.StrList("addressPrefixes"))))
            .ToList();

        // Per candidate IP: the VNets whose address space holds it. Only those VNets are read in detail.
        var containing = candidateIps.ToDictionary(ip => ip, ip => vnets.Where(v => v.AddressSpace.Any(n => n.Contains(ip))).ToList());
        var neededVnets = containing.Values.SelectMany(v => v).DistinctBy(v => v.Ref.Id, StringComparer.OrdinalIgnoreCase).ToList();

        progress?.Report($"Subnets controleren ({neededVnets.Count} VNet(s))…");
        var subnets = new ConcurrentDictionary<string, IReadOnlyList<Subnet>?>(StringComparer.OrdinalIgnoreCase);
        await Parallel.ForEachAsync(neededVnets, new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = ct }, async (vnet, token) =>
        {
            try
            {
                subnets[vnet.Ref.Id] = ParseSubnets(await arm.GetResourceAsync(vnet.Ref.Id, "2024-05-01", token), visibleIds);
            }
            catch (AzureApiException)
            {
                subnets[vnet.Ref.Id] = null;
            }
        });

        // Uniform VMSS instances (AKS nodes, ...) aren't in Resource Graph: read their NICs directly.
        var vmssIds = subnets.Values.OfType<IReadOnlyList<Subnet>>().SelectMany(s => s).SelectMany(s => s.VmssIds)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var vmssFailed = new ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        if (vmssIds.Count > 0)
        {
            progress?.Report($"IP's van {vmssIds.Count} scale set(s) ophalen…");
            await Parallel.ForEachAsync(vmssIds, new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = ct }, async (vmssId, token) =>
            {
                try
                {
                    await foreach (var nic in arm.GetVmssNetworkInterfacesAsync(vmssId, token))
                    {
                        if (!nic.TryGetProperty("properties", out var props) || Prop(props, "ipConfigurations") is not { ValueKind: JsonValueKind.Array } configs) continue;
                        foreach (var config in configs.EnumerateArray())
                        {
                            if (config.TryGetProperty("properties", out var cp) && cp.Str("privateIPAddress") is { } ip && IPAddress.TryParse(ip, out var parsed))
                                usedIps.TryAdd(parsed.ToString(), vmssId);
                        }
                    }
                }
                catch (AzureApiException)
                {
                    vmssFailed[vmssId] = true;
                }
            });
        }

        var unreadableVnets = subnets.Count(s => s.Value is null);
        if (unreadableVnets > 0)
            warnings.Add($"{unreadableVnets} VNet(s) konden niet gelezen worden bij ARM: IP's daarin zijn niet verifieerbaar.");

        foreach (var record in ipRecords)
        {
            var dead = record.Ips.Where(ip => IPAddress.TryParse(ip, out var a) && !usedIps.ContainsKey(a.ToString())).ToList();
            var alive = record.Ips.Except(dead).ToList();

            foreach (var ipText in dead)
            {
                var ip = IPAddress.Parse(ipText);
                var checks = containing.GetValueOrDefault(ip, [])
                    .Select(v => CheckInVnet(ip, v, subnets.GetValueOrDefault(v.Ref.Id), vmssFailed))
                    .ToList();

                DnsCheckBasis basis;
                string reason;
                if (checks.Count == 0)
                {
                    basis = DnsCheckBasis.None;
                    reason = IsPrivate(ip)
                        ? "Privé-IP buiten alle VNets die je kan zien (on-premises, andere tenant, of subscription zonder leesrechten)."
                        : "Publiek IP dat niet bij een public IP-resource in jouw subscriptions hoort (externe hosting, of een vrijgegeven Azure-IP).";
                }
                else if (checks.FirstOrDefault(c => c.Basis == DnsCheckBasis.None) is { } blocked)
                {
                    basis = DnsCheckBasis.None;
                    reason = blocked.NotVerifiableReason!;
                }
                else
                {
                    basis = checks.Any(c => c.Basis == DnsCheckBasis.Subnet) ? DnsCheckBasis.Subnet : DnsCheckBasis.Vnet;
                    reason = basis == DnsCheckBasis.Subnet
                        ? "Geen enkele resource in het subnet gebruikt dit IP."
                        : "Het IP ligt in de adresruimte van het VNet, maar in geen enkel subnet: niets kan het gebruiken.";
                    if (checks.Count > 1) reason += $" Gecontroleerd in {checks.Count} overlappende VNets.";
                }

                findings.Add(Finding(record, ipText, basis, reason, alive, checks.Select(c => c.Label).ToList(),
                    record.Zone.Kind == DnsZoneKind.Private
                        ? $"az network private-dns record-set a remove-record {Args(record)} -a {ipText}"
                        : $"az network dns record-set a remove-record {Args(record)} -a {ipText}"));
            }
        }
    }

    private static NetworkCheck CheckInVnet(IPAddress ip, Vnet vnet, IReadOnlyList<Subnet>? subnets, ConcurrentDictionary<string, bool> vmssFailed)
    {
        if (subnets is null)
            return new NetworkCheck(vnet.Ref.Name, DnsCheckBasis.None, $"VNet {vnet.Ref.Name} kon niet gelezen worden bij ARM.");

        var subnet = subnets.FirstOrDefault(s => s.Prefixes.Any(p => p.Contains(ip)));
        if (subnet is null)
            return new NetworkCheck($"{vnet.Ref.Name} (buiten subnets)", DnsCheckBasis.Vnet, null);

        var label = $"{vnet.Ref.Name} / {subnet.Name} ({string.Join(", ", subnet.Prefixes)})";
        if (subnet.NotVerifiableReason is { } why)
            return new NetworkCheck(label, DnsCheckBasis.None, $"Subnet {subnet.Name} in {vnet.Ref.Name}: {why}");
        if (subnet.VmssIds.FirstOrDefault(vmssFailed.ContainsKey) is { } vmss)
            return new NetworkCheck(label, DnsCheckBasis.None, $"Subnet {subnet.Name} in {vnet.Ref.Name}: de IP's van scale set {ResourceName(vmss)} konden niet gelezen worden.");

        return new NetworkCheck(label, DnsCheckBasis.Subnet, null);
    }

    /// <summary>
    /// A subnet is fully visible when every IP configuration in it belongs to a NIC, load balancer or scale set we can read,
    /// and no service claims the subnet (delegation, service links, special subnet names).
    /// </summary>
    private static IReadOnlyList<Subnet> ParseSubnets(JsonElement vnet, HashSet<string> visibleIds)
    {
        var list = new List<Subnet>();
        if (!vnet.TryGetProperty("properties", out var vp) || Prop(vp, "subnets") is not { ValueKind: JsonValueKind.Array } subnets) return list;

        foreach (var subnet in subnets.EnumerateArray())
        {
            var name = subnet.Str("name") ?? "";
            if (!subnet.TryGetProperty("properties", out var sp)) continue;

            var prefixes = Networks([.. sp.StrList("addressPrefix"), .. sp.StrList("addressPrefixes")]);
            var vmss = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string? reason = null;

            if (ServiceSubnets.Contains(name))
            {
                reason = "instanties van deze dienst gebruiken IP's die nergens zichtbaar zijn.";
            }
            else if (Ids(sp, "delegations", "serviceName") is { Count: > 0 } delegations)
            {
                reason = $"gedelegeerd aan {string.Join(", ", delegations)}; zulke diensten hebben geen zichtbare NIC.";
            }
            else if (Ids(sp, "serviceAssociationLinks", "linkedResourceType").Concat(Ids(sp, "resourceNavigationLinks", "linkedResourceType")).ToList() is { Count: > 0 } links)
            {
                reason = $"in gebruik door {string.Join(", ", links.Distinct(StringComparer.OrdinalIgnoreCase))}; die dienst heeft geen zichtbare NIC.";
            }
            else if (Prop(sp, "ipConfigurationProfiles") is { ValueKind: JsonValueKind.Array } profiles && profiles.GetArrayLength() > 0)
            {
                reason = "bevat container-netwerkprofielen; die IP's zijn niet zichtbaar.";
            }
            else
            {
                var hidden = 0;
                var services = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var configId in Ids(sp, "ipConfigurations", "id"))
                {
                    var owner = OwnerOf(configId);
                    var vmssAt = owner.IndexOf("/virtualMachines/", StringComparison.OrdinalIgnoreCase);
                    if (owner.Contains("/virtualMachineScaleSets/", StringComparison.OrdinalIgnoreCase) && vmssAt > 0)
                        vmss.Add(owner[..vmssAt]);
                    else if (owner.Contains("/networkInterfaces/", StringComparison.OrdinalIgnoreCase) || owner.Contains("/loadBalancers/", StringComparison.OrdinalIgnoreCase))
                    {
                        if (!visibleIds.Contains(owner)) hidden++;
                    }
                    else
                        services.Add(ResourceType(owner));
                }

                if (services.Count > 0)
                    reason = $"in gebruik door {string.Join(", ", services)}; die dienst gebruikt meer IP's dan zichtbaar zijn.";
                else if (hidden > 0)
                    reason = $"{hidden} IP-configuratie(s) horen bij resources die je niet kan lezen (bv. private endpoints in een andere subscription).";
            }

            list.Add(new Subnet(name, prefixes, reason, vmss.ToList()));
        }
        return list;
    }

    // ---- CNAME records: target exists?

    private async Task CheckCnameRecordsAsync(List<RecordSet> records, Dictionary<string, HashSet<string>?> zoneNames,
        ConcurrentBag<OrphanedDnsRecord> findings, IProgress<string>? progress, CancellationToken ct)
    {
        var cnames = records.Where(r => r.Cname is not null && r.AliasTarget is null).ToList();
        if (cnames.Count == 0) return;

        var resolved = new ConcurrentDictionary<string, (bool? Exists, string? Error)>(StringComparer.OrdinalIgnoreCase);
        var done = 0;

        await Parallel.ForEachAsync(cnames, new ParallelOptions { MaxDegreeOfParallelism = 16, CancellationToken = ct }, async (record, token) =>
        {
            var target = record.Cname!.TrimEnd('.').ToLowerInvariant();
            var command = $"az network {(record.Zone.Kind == DnsZoneKind.Private ? "private-dns" : "dns")} record-set cname delete {Args(record)} --yes";

            // 1. Target in one of our own zones: the record must be there.
            var ownZone = zoneNames.Keys.Where(z => target == z || target.EndsWith("." + z, StringComparison.Ordinal)).MaxBy(z => z.Length);
            if (ownZone is not null)
            {
                var relative = target == ownZone ? "@" : target[..^(ownZone.Length + 1)];
                if (zoneNames[ownZone] is not { } names)
                {
                    findings.Add(Finding(record, record.Cname!, DnsCheckBasis.None,
                        $"Het doel ligt in je zone {ownZone}, maar (een van) die zone(s) kon niet gelezen worden.", [], [], command));
                }
                else if (!HasName(names, relative))
                {
                    findings.Add(Finding(record, record.Cname!, DnsCheckBasis.CnameTarget,
                        $"Het doel bestaat niet in je eigen zone {ownZone}.", [], [], command));
                }
                return;
            }

            // 2. Otherwise ask public DNS (DNS-over-HTTPS: a browser has no access to the OS resolver).
            if (!resolved.TryGetValue(target, out var result))
            {
                result = await dns.ResolveAsync(target, DnsTimeout, token);
                resolved[target] = result;
            }

            if (result.Exists == false)
            {
                var publicName = record.Zone.Kind == DnsZoneKind.Public || AzurePublicSuffixes.Any(s => target.EndsWith("." + s, StringComparison.Ordinal));
                findings.Add(publicName
                    ? Finding(record, record.Cname!, DnsCheckBasis.CnameTarget, "Het doel bestaat niet (DNS geeft NXDOMAIN).", [], [], command)
                    : Finding(record, record.Cname!, DnsCheckBasis.None, "Het doel is niet publiek resolvebaar, maar kan een interne naam zijn (on-premises DNS, andere private zone).", [], [], command));
            }
            else if (result.Exists is null)
            {
                findings.Add(Finding(record, record.Cname!, DnsCheckBasis.None, $"DNS-opzoeking van het doel mislukte: {result.Error}", [], [], command));
            }

            var count = Interlocked.Increment(ref done);
            if (count % 20 == 0) progress?.Report($"CNAME-doelen opzoeken… {count}/{cnames.Count}");
        });
    }

    private static bool HasName(HashSet<string> names, string relative)
    {
        if (names.Contains(relative)) return true;
        // Wildcards: "*" covers everything, "*.sub" covers "x.sub".
        if (names.Contains("*")) return true;
        var dot = relative.IndexOf('.');
        while (dot > 0)
        {
            if (names.Contains("*" + relative[dot..])) return true;
            dot = relative.IndexOf('.', dot + 1);
        }
        return false;
    }

    // ---- Alias records: target resource exists?

    private async Task CheckAliasRecordsAsync(
        List<RecordSet> records, IReadOnlyDictionary<string, string> subscriptionNames, ConcurrentBag<OrphanedDnsRecord> findings,
        IProgress<string>? progress, CancellationToken ct)
    {
        var aliases = records.Where(r => r.AliasTarget is not null).ToList();
        if (aliases.Count == 0) return;

        progress?.Report($"Aliasdoelen controleren ({aliases.Count})…");
        var lookup = aliases.SelectMany(a => new[] { a.AliasTarget!, TopLevel(a.AliasTarget!) })
            .Where(id => !id.Contains('\''))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var existing = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var chunk in lookup.Chunk(200))
        {
            var list = string.Join(",", chunk.Select(id => $"'{id.ToLowerInvariant()}'"));
            foreach (var row in await resourceGraph.QueryAsync($"resources | where tolower(id) in ({list}) | project id", ct: ct))
            {
                if (row.Str("id") is { } id) existing.Add(id);
            }
        }

        foreach (var record in aliases)
        {
            var target = record.AliasTarget!;
            if (existing.Contains(target)) continue;

            var command = $"az network dns record-set {record.Type.ToLowerInvariant()} delete {Args(record)} --yes";
            var top = TopLevel(target);
            var (basis, reason) = ScopeParser.SubscriptionId(target) is not { } sub || !subscriptionNames.ContainsKey(sub)
                ? (DnsCheckBasis.None, "Het aliasdoel staat in een subscription die je niet kan zien.")
                : !top.Equals(target, StringComparison.OrdinalIgnoreCase) && existing.Contains(top)
                    ? (DnsCheckBasis.None, $"Het aliasdoel is een subresource van {ResourceName(top)}, die nog bestaat; Resource Graph indexeert zulke subresources niet altijd.")
                    : (DnsCheckBasis.AliasTarget, "De resource waar de alias naar verwijst bestaat niet meer.");

            findings.Add(Finding(record, target, basis, reason, [], [], command));
        }
    }

    // ---- Helpers

    private static OrphanedDnsRecord Finding(RecordSet r, string target, DnsCheckBasis basis, string reason,
        IReadOnlyList<string> others, IReadOnlyList<string> networks, string command) =>
        new(r.Zone.Ref, r.Zone.Kind, r.Name, r.AliasTarget is null ? r.Type : $"{r.Type} (alias)", r.Fqdn, target, basis, reason,
            basis == DnsCheckBasis.None ? Severity.Low : r.Zone.Kind == DnsZoneKind.Public ? Severity.High : Severity.Medium,
            r.Ttl, others, networks, command);

    private static string Args(RecordSet r) =>
        $"--subscription {r.Zone.Ref.SubscriptionId} -g {r.Zone.Ref.ResourceGroup} -z {r.Zone.Ref.Name} -n \"{r.Name}\"";

    private static List<IPNetwork> Networks(IEnumerable<string> prefixes) =>
        prefixes.Select(p => IPNetwork.TryParse(p, out var n) ? n : (IPNetwork?)null).OfType<IPNetwork>().ToList();

    /// <summary>Values of one property of the objects in an array property (e.g. delegations[].properties.serviceName).</summary>
    private static List<string> Ids(JsonElement props, string array, string field)
    {
        var values = new List<string>();
        if (Prop(props, array) is not { ValueKind: JsonValueKind.Array } items) return values;
        foreach (var item in items.EnumerateArray())
        {
            var value = item.Str(field) ?? (item.TryGetProperty("properties", out var p) ? p.Str(field) : null);
            if (value is { Length: > 0 }) values.Add(value);
        }
        return values;
    }

    /// <summary>".../networkInterfaces/nic/ipConfigurations/ipconfig1" → ".../networkInterfaces/nic".</summary>
    private static string OwnerOf(string configId)
    {
        var last = configId.TrimEnd('/').LastIndexOf('/');
        var secondLast = last > 0 ? configId.LastIndexOf('/', last - 1) : -1;
        return secondLast > 0 ? configId[..secondLast] : configId;
    }

    /// <summary>"/subscriptions/s/resourceGroups/rg/providers/Ns/type/name/child/x" → the part up to "name".</summary>
    private static string TopLevel(string id)
    {
        var segments = id.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var providers = Array.FindIndex(segments, s => s.Equals("providers", StringComparison.OrdinalIgnoreCase));
        return providers >= 0 && segments.Length > providers + 3
            ? "/" + string.Join('/', segments[..(providers + 4)])
            : id;
    }

    private static string ResourceType(string id)
    {
        var segments = id.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var providers = Array.FindLastIndex(segments, s => s.Equals("providers", StringComparison.OrdinalIgnoreCase));
        return providers >= 0 && segments.Length > providers + 2 ? $"{segments[providers + 1]}/{segments[providers + 2]}" : id;
    }

    private static string ResourceName(string id) => id.Split('/', StringSplitOptions.RemoveEmptyEntries).LastOrDefault() ?? id;

    private static readonly IPNetwork[] PrivateRanges =
        [IPNetwork.Parse("10.0.0.0/8"), IPNetwork.Parse("172.16.0.0/12"), IPNetwork.Parse("192.168.0.0/16"), IPNetwork.Parse("100.64.0.0/10")];

    private static bool IsPrivate(IPAddress ip) => PrivateRanges.Any(r => r.Contains(ip));
}
