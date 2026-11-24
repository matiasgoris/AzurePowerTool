using System.Text.Json;

namespace AzurePowerTool.Core.Auth;

/// <summary>Reads (without validating) the claims of an access token. Only used for display purposes.</summary>
public static class JwtClaims
{
    public static JsonElement ReadPayload(string jwt)
    {
        var parts = jwt.Split('.');
        if (parts.Length < 2) throw new FormatException("Geen geldig JWT-token.");

        var payload = parts[1].Replace('-', '+').Replace('_', '/');
        payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');

        using var doc = JsonDocument.Parse(Convert.FromBase64String(payload));
        return doc.RootElement.Clone();
    }

    public static string? GetString(string jwt, string claim)
    {
        var payload = ReadPayload(jwt);
        return payload.TryGetProperty(claim, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
    }
}
