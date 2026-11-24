namespace AzurePowerTool.Web.Components.Shared;

public static class Portal
{
    public static string ResourceUrl(string tenantId, string resourceId) =>
        $"https://portal.azure.com/#@{tenantId}/resource{resourceId}";

    /// <summary>The "Access control (IAM)" blade of a scope.</summary>
    public static string AccessControlUrl(string tenantId, string scope) =>
        $"https://portal.azure.com/#@{tenantId}/resource{scope}/users";
}
