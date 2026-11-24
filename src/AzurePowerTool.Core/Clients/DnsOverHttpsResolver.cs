using System.Net.Http.Json;
using System.Text.Json;
using AzurePowerTool.Core.Http;

namespace AzurePowerTool.Core.Clients;

/// <summary>
/// Public DNS lookups over HTTPS (Cloudflare's JSON API), because a browser can't use the OS resolver.
/// Only public names resolve: internal names (on-premises DNS, private zones) give NXDOMAIN here.
/// </summary>
public sealed class DnsOverHttpsResolver(HttpClient http)
{
    public const string Endpoint = "https://cloudflare-dns.com/dns-query";

    private const int NoError = 0;
    private const int NxDomain = 3;

    /// <summary>True = resolves, false = NXDOMAIN, null = couldn't tell (timeout, other error).</summary>
    public async Task<(bool? Exists, string? Error)> ResolveAsync(string host, TimeSpan timeout, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try
        {
            // A first, then AAAA: like the OS resolver, a name "exists" when it has any address.
            foreach (var type in new[] { "A", "AAAA" })
            {
                var (status, hasAnswer) = await QueryAsync(host, type, cts.Token);
                if (status == NxDomain) return (false, null);
                if (status != NoError) return (null, $"DNS-status {status}");
                if (hasAnswer) return (true, null);
            }
            return (true, "bestaat, maar zonder adressen");
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return (null, "time-out");
        }
        catch (HttpRequestException ex)
        {
            return (null, ex.Message);
        }
    }

    private async Task<(int Status, bool HasAnswer)> QueryAsync(string host, string type, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"{Endpoint}?name={Uri.EscapeDataString(host)}&type={type}");
        request.Headers.Accept.ParseAdd("application/dns-json");
        using var response = await http.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
        var json = await response.Content.ReadFromJsonAsync<JsonElement>(ct);
        var status = json.Int("Status") ?? -1;
        var hasAnswer = json.TryGetProperty("Answer", out var answer) && answer.ValueKind == JsonValueKind.Array
            && answer.EnumerateArray().Any(a => a.Int("type") is 1 or 28); // A or AAAA
        return (status, hasAnswer);
    }
}
