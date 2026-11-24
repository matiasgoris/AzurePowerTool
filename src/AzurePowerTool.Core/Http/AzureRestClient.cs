using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Runtime.CompilerServices;
using System.Text.Json;
using AzurePowerTool.Core.Auth;

namespace AzurePowerTool.Core.Http;

/// <summary>
/// Minimal REST base for ARM and Microsoft Graph: bearer token, retries on throttling, paging.
/// Plain REST keeps the dependencies small and gives full control over the queries.
/// </summary>
public abstract class AzureRestClient(HttpClient http, IAzureSession session, string scope)
{
    private const int MaxAttempts = 4;

    protected async Task<JsonElement> SendAsync(HttpMethod method, string url, object? body, CancellationToken ct)
    {
        for (var attempt = 1; ; attempt++)
        {
            using var request = new HttpRequestMessage(method, url);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await session.GetTokenAsync(scope, ct));
            if (body is not null)
            {
                request.Content = JsonContent.Create(body);
            }

            using var response = await http.SendAsync(request, ct);

            if (IsTransient(response.StatusCode) && attempt < MaxAttempts)
            {
                var delay = response.Headers.RetryAfter?.Delta ?? TimeSpan.FromSeconds(Math.Pow(2, attempt));
                await Task.Delay(delay, ct);
                continue;
            }

            var text = await response.Content.ReadAsStringAsync(ct);
            if (!response.IsSuccessStatusCode)
            {
                throw AzureApiException.FromResponse(response.StatusCode, text, url);
            }

            if (string.IsNullOrWhiteSpace(text)) return default;

            using var doc = JsonDocument.Parse(text);
            return doc.RootElement.Clone();
        }
    }

    /// <summary>
    /// For long-running ARM operations: returns the status and the URL to poll (Location / Azure-AsyncOperation).
    /// Errors throw <see cref="AzureApiException"/>, like <see cref="SendAsync"/>.
    /// </summary>
    protected async Task<(HttpStatusCode Status, string? PollUrl, TimeSpan? RetryAfter)> SendOperationAsync(HttpMethod method, string url, CancellationToken ct)
    {
        for (var attempt = 1; ; attempt++)
        {
            using var request = new HttpRequestMessage(method, url);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await session.GetTokenAsync(scope, ct));
            using var response = await http.SendAsync(request, ct);

            if (IsTransient(response.StatusCode) && attempt < MaxAttempts)
            {
                await Task.Delay(response.Headers.RetryAfter?.Delta ?? TimeSpan.FromSeconds(Math.Pow(2, attempt)), ct);
                continue;
            }
            if (!response.IsSuccessStatusCode)
            {
                throw AzureApiException.FromResponse(response.StatusCode, await response.Content.ReadAsStringAsync(ct), url);
            }
            return (response.StatusCode, response.Headers.Location?.ToString(), response.Headers.RetryAfter?.Delta);
        }
    }

    /// <summary>Follows ARM's "nextLink" or Graph's "@odata.nextLink" and yields the "value" items.</summary>
    protected async IAsyncEnumerable<JsonElement> GetPagedAsync(string url, string nextLinkProperty, [EnumeratorCancellation] CancellationToken ct)
    {
        string? next = url;
        while (next is not null)
        {
            var page = await SendAsync(HttpMethod.Get, next, body: null, ct);
            if (page.TryGetProperty("value", out var items))
            {
                foreach (var item in items.EnumerateArray()) yield return item;
            }
            // Some APIs (e.g. network security perimeters) return "nextLink": "" on the last page.
            next = page.Str(nextLinkProperty) is { Length: > 0 } link ? link : null;
        }
    }

    private static bool IsTransient(HttpStatusCode status) =>
        status is HttpStatusCode.TooManyRequests or HttpStatusCode.BadGateway or HttpStatusCode.ServiceUnavailable or HttpStatusCode.GatewayTimeout;
}

public sealed class AzureApiException(HttpStatusCode status, string? code, string message, string url)
    : Exception($"{(int)status} {code}: {message}")
{
    public HttpStatusCode Status { get; } = status;
    public string? Code { get; } = code;
    public string ApiMessage { get; } = message;
    public string Url { get; } = url;

    public bool IsForbidden => Status is HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized;

    internal static AzureApiException FromResponse(HttpStatusCode status, string body, string url)
    {
        string? code = null;
        var message = body;
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("error", out var error))
            {
                code = error.Str("code");
                message = error.Str("message") ?? body;
            }
        }
        catch (JsonException)
        {
            // Not JSON: keep the raw body as message.
        }

        return new AzureApiException(status, code, message, url);
    }
}

public static class JsonElementExtensions
{
    public static string? Str(this JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object
        && element.TryGetProperty(name, out var value)
        && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    /// <summary>A JSON boolean, "true"/"false" string or 1/0 number. Null when missing or anything else.</summary>
    public static bool? Bool(this JsonElement element, string name)
    {
        if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty(name, out var value)) return null;
        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.String when bool.TryParse(value.GetString(), out var parsed) => parsed,
            // Resource Graph returns computed booleans (isnotnull, tobool) as 1 / 0.
            JsonValueKind.Number when value.TryGetInt32(out var number) => number != 0,
            _ => null,
        };
    }

    public static int? Int(this JsonElement element, string name)
    {
        if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty(name, out var value)) return null;
        return value.ValueKind switch
        {
            JsonValueKind.Number when value.TryGetInt32(out var number) => number,
            JsonValueKind.String when int.TryParse(value.GetString(), out var parsed) => parsed,
            _ => null,
        };
    }

    /// <summary>A string, or an array of strings, as a list. Empty when missing.</summary>
    public static IReadOnlyList<string> StrList(this JsonElement element, string name)
    {
        if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty(name, out var value)) return [];
        return value.ValueKind switch
        {
            JsonValueKind.String when value.GetString() is { Length: > 0 } single => [single],
            JsonValueKind.Array => value.EnumerateArray()
                .Where(v => v.ValueKind == JsonValueKind.String)
                .Select(v => v.GetString()!)
                .Where(s => s.Length > 0)
                .ToList(),
            _ => [],
        };
    }

    public static DateTimeOffset? Date(this JsonElement element, string name) =>
        DateTimeOffset.TryParse(element.Str(name), System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal, out var date) ? date : null;

    public static IReadOnlyDictionary<string, string> StringMap(this JsonElement element, string name)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (element.ValueKind == JsonValueKind.Object
            && element.TryGetProperty(name, out var value)
            && value.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in value.EnumerateObject())
            {
                map[property.Name] = property.Value.ValueKind == JsonValueKind.String
                    ? property.Value.GetString() ?? ""
                    : property.Value.GetRawText();
            }
        }
        return map;
    }
}
