namespace AzurePowerTool.Web.Components.Shared;

public sealed record FilterOption(string Value, string Label, int Count)
{
    /// <summary>Selects the items that have no value (e.g. role assignments on a management group).</summary>
    public const string NoValue = "__none__";
}
