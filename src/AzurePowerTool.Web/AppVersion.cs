using System.Reflection;

namespace AzurePowerTool.Web;

public static class AppVersion
{
    /// <summary>E.g. "1.0.12 (3f2a9c1)": the build version plus the short commit it was built from.</summary>
    public static string Display { get; } = Create();

    private static string Create()
    {
        var informational = typeof(AppVersion).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.0.0-dev";

        // The SDK appends "+<commit sha>" when building from a git repository.
        var parts = informational.Split('+', 2);
        return parts.Length == 2 && parts[1].Length >= 7
            ? $"{parts[0]} ({parts[1][..7]})"
            : parts[0];
    }
}
