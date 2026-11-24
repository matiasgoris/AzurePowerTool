using AzurePowerTool.Core.Clients;
using AzurePowerTool.Core.Http;
using AzurePowerTool.Core.Models;

namespace AzurePowerTool.Core.Reports;

/// <summary>
/// Inbound NSG "Allow" rules that open management or database ports (or all ports) to the whole internet.
/// Web ports (80/443) are deliberately not reported.
/// </summary>
public sealed class OpenNsgPortsReport(ResourceGraphClient resourceGraph, ArmClient arm)
{
    private const string Query = """
        resources
        | where type =~ 'microsoft.network/networksecuritygroups'
        | extend attachedSubnets = coalesce(array_length(properties.subnets), 0),
                 attachedNics = coalesce(array_length(properties.networkInterfaces), 0)
        | mv-expand rule = properties.securityRules
        | where rule.properties.direction =~ 'Inbound' and rule.properties.access =~ 'Allow'
        | project id, name, type, subscriptionId, resourceGroup, location, attachedSubnets, attachedNics,
            ruleId = tostring(rule.id),
            ruleName = tostring(rule.name),
            priority = toint(rule.properties.priority),
            protocol = tostring(rule.properties.protocol),
            sourceAddressPrefix = rule.properties.sourceAddressPrefix,
            sourceAddressPrefixes = rule.properties.sourceAddressPrefixes,
            destinationPortRange = rule.properties.destinationPortRange,
            destinationPortRanges = rule.properties.destinationPortRanges
        """;

    /// <summary>Sources that mean "anyone on the internet".</summary>
    private static readonly HashSet<string> OpenSources = new(StringComparer.OrdinalIgnoreCase) { "*", "Internet", "Any", "0.0.0.0/0", "0.0.0.0", "::/0" };

    private static readonly (int Port, string Service, Severity Severity)[] SensitivePorts =
    [
        (22, "SSH", Severity.High),
        (3389, "RDP", Severity.High),
        (23, "Telnet", Severity.High),
        (445, "SMB", Severity.High),
        (135, "RPC", Severity.High),
        (5985, "WinRM", Severity.High),
        (5986, "WinRM (HTTPS)", Severity.High),
        (21, "FTP", Severity.Medium),
        (1433, "SQL Server", Severity.Medium),
        (3306, "MySQL", Severity.Medium),
        (5432, "PostgreSQL", Severity.Medium),
        (6379, "Redis", Severity.Medium),
        (27017, "MongoDB", Severity.Medium),
        (9200, "Elasticsearch", Severity.Medium),
    ];

    public async Task<ReportResult<OpenPortRule>> RunAsync(IProgress<string>? progress = null, CancellationToken ct = default)
    {
        progress?.Report("Subscriptions ophalen…");
        var subscriptionNames = await ResourceRows.SubscriptionNamesAsync(arm, ct);

        progress?.Report($"NSG-regels ophalen via Resource Graph ({subscriptionNames.Count} subscriptions)…");
        var rows = await resourceGraph.QueryAsync(Query, ct: ct);

        var items = new List<OpenPortRule>();
        foreach (var r in rows)
        {
            var protocol = r.Str("protocol") ?? "*";
            if (protocol.Equals("Icmp", StringComparison.OrdinalIgnoreCase)) continue;

            var sources = r.StrList("sourceAddressPrefix").Concat(r.StrList("sourceAddressPrefixes")).ToList();
            if (!sources.Any(OpenSources.Contains)) continue;

            var ports = r.StrList("destinationPortRange").Concat(r.StrList("destinationPortRanges")).ToList();
            if (Expose(ports) is not { } exposure) continue;

            items.Add(new OpenPortRule(
                Nsg: ResourceRows.ToRef(r, subscriptionNames),
                RuleId: r.Str("ruleId") ?? "",
                RuleName: r.Str("ruleName") ?? "",
                Priority: r.Int("priority") ?? 0,
                Protocol: protocol,
                Sources: sources,
                Ports: ports,
                ExposedServices: exposure.Services,
                Severity: exposure.Severity,
                AttachedSubnets: r.Int("attachedSubnets") ?? 0,
                AttachedNics: r.Int("attachedNics") ?? 0));
        }

        var ordered = items
            .OrderByDescending(i => i.Severity)
            .ThenByDescending(i => i.IsAttached)
            .ThenBy(i => i.Nsg.SubscriptionName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(i => i.Nsg.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var warnings = new List<string>
        {
            $"{rows.Count} inbound allow-regels gecontroleerd, {ordered.Count} stellen gevoelige poorten open voor het internet.",
        };
        if (ordered.Any(i => !i.IsAttached))
        {
            warnings.Add("Sommige NSG's zijn aan geen subnet of NIC gekoppeld: daar is het risico nu klein, maar de regel opruimen voorkomt verrassingen later.");
        }

        return new ReportResult<OpenPortRule>(ordered, warnings, DateTimeOffset.Now);
    }

    private static (IReadOnlyList<string> Services, Severity Severity)? Expose(IReadOnlyList<string> ranges)
    {
        if (ranges.Count == 0 || ranges.Any(r => r == "*" || r == "0-65535"))
            return (["Alle poorten"], Severity.High);

        var hits = SensitivePorts.Where(p => ranges.Any(r => Covers(r, p.Port))).ToList();
        if (hits.Count == 0) return null;

        return (hits.Select(h => $"{h.Service} ({h.Port})").ToList(), hits.Max(h => h.Severity));
    }

    private static bool Covers(string range, int port)
    {
        var parts = range.Split('-', 2, StringSplitOptions.TrimEntries);
        if (!int.TryParse(parts[0], out var from)) return false;
        var to = parts.Length == 2 && int.TryParse(parts[1], out var end) ? end : from;
        return port >= from && port <= to;
    }
}
