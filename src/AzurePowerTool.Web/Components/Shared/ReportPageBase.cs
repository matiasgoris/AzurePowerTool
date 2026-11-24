using AzurePowerTool.Core.Models;
using Microsoft.AspNetCore.Components;
using Microsoft.JSInterop;

namespace AzurePowerTool.Web.Components.Shared;

/// <summary>Shared plumbing for report pages: run/cancel, progress, errors, filtering, CSV export.</summary>
public abstract class ReportPageBase<T> : SessionAwareComponent
{
    private CancellationTokenSource? _cts;

    [Inject] protected IJSRuntime JS { get; set; } = default!;

    protected ReportResult<T>? Result { get; private set; }
    protected bool Running { get; private set; }
    protected string? Status { get; private set; }
    protected Exception? Error { get; private set; }
    protected string Filter { get; set; } = "";

    /// <summary>Selected option values (see <see cref="FilterOption.Value"/>). Empty = all.</summary>
    protected HashSet<string> SelectedSubscriptions { get; } = new(StringComparer.OrdinalIgnoreCase);
    protected HashSet<string> SelectedRegions { get; } = new(StringComparer.OrdinalIgnoreCase);

    protected abstract Task<ReportResult<T>> ExecuteAsync(IProgress<string> progress, CancellationToken ct);

    protected abstract IEnumerable<string?> SearchFields(T item);

    /// <summary>Subscription of an item as (id, display name); id null = not tied to a subscription. Null selector = no filter.</summary>
    protected virtual Func<T, (string? Key, string? Label)>? SubscriptionSelector => null;

    /// <summary>Region of an item. Null selector = no region filter.</summary>
    protected virtual Func<T, string?>? RegionSelector => null;

    /// <summary>Type of an item (e.g. principal type). Null selector = no type filter.</summary>
    protected virtual Func<T, string?>? TypeSelector => null;

    /// <summary>Severity of an item. Null selector = no severity filter.</summary>
    protected virtual Func<T, Severity>? SeveritySelector => null;

    /// <summary>Show only items with at least this severity.</summary>
    protected Severity MinSeverity { get; set; } = Severity.Low;

    /// <summary>Type option values (see <see cref="FilterOption.Value"/>) the user unchecked.</summary>
    protected HashSet<string> ExcludedTypes { get; } = new(StringComparer.OrdinalIgnoreCase);

    protected IReadOnlyList<FilterOption> TypeOptions =>
        TypeSelector is { } select ? BuildOptions(i => { var t = select(i); return (t, t); }, "(onbekend)") : [];

    /// <summary>Label for items without subscription / region in the dropdown.</summary>
    protected virtual string NoSubscriptionLabel => "(geen subscription)";

    protected IReadOnlyList<FilterOption> SubscriptionOptions =>
        SubscriptionSelector is { } select ? BuildOptions(i => select(i), NoSubscriptionLabel) : [];

    protected IReadOnlyList<FilterOption> RegionOptions =>
        RegionSelector is { } select ? BuildOptions(i => { var r = select(i); return (r, r); }, "(geen regio)") : [];

    /// <summary>Page-specific filter (e.g. minimum age). Default: everything passes.</summary>
    protected virtual bool ExtraFilter(T item) => true;
    protected virtual bool HasExtraFilters => false;
    protected virtual void ClearExtraFilters() { }

    // ---- Sorting: click a column header. Asc → desc → original order. Empty values always last.
    protected string? SortKey { get; private set; }
    protected bool SortDescending { get; private set; }

    /// <summary>Value to sort on for a column key; null = no value (sorted last).</summary>
    protected virtual IComparable? SortValue(T item, string key) => null;

    protected void SortBy(string key)
    {
        if (SortKey != key) { SortKey = key; SortDescending = false; }
        else if (!SortDescending) { SortDescending = true; }
        else { SortKey = null; SortDescending = false; }
    }

    protected string SortIndicator(string key) => SortKey == key ? (SortDescending ? " ▼" : " ▲") : "";

    protected bool HasActiveFilters => HasExtraFilters || Filter.Trim().Length > 0 || SelectedSubscriptions.Count > 0 || SelectedRegions.Count > 0 || ExcludedTypes.Count > 0 || MinSeverity != Severity.Low;

    protected IReadOnlyList<T> Filtered
    {
        get
        {
            if (Result is null) return [];
            IEnumerable<T> items = Result.Items;

            if (SelectedSubscriptions.Count > 0 && SubscriptionSelector is { } sub)
                items = items.Where(i => SelectedSubscriptions.Contains(OptionKey(sub(i).Key)));

            if (SelectedRegions.Count > 0 && RegionSelector is { } region)
                items = items.Where(i => SelectedRegions.Contains(OptionKey(region(i))));

            if (ExcludedTypes.Count > 0 && TypeSelector is { } type)
                items = items.Where(i => !ExcludedTypes.Contains(OptionKey(type(i))));

            if (MinSeverity != Severity.Low && SeveritySelector is { } severity)
                items = items.Where(i => severity(i) >= MinSeverity);

            items = items.Where(ExtraFilter);

            var text = Filter.Trim();
            if (text.Length > 0)
                items = items.Where(i => SearchFields(i).Any(f => f?.Contains(text, StringComparison.OrdinalIgnoreCase) == true));

            if (SortKey is { } key)
            {
                var keyed = items.Select(i => (Item: i, Value: SortValue(i, key))).ToList();
                var withValue = keyed.Where(x => x.Value is not null);
                var sorted = SortDescending
                    ? withValue.OrderByDescending(x => x.Value, Comparer<IComparable?>.Default)
                    : withValue.OrderBy(x => x.Value, Comparer<IComparable?>.Default);
                items = sorted.Concat(keyed.Where(x => x.Value is null)).Select(x => x.Item);
            }

            return items.ToList();
        }
    }

    protected void ClearFilters()
    {
        Filter = "";
        SelectedSubscriptions.Clear();
        SelectedRegions.Clear();
        ExcludedTypes.Clear();
        MinSeverity = Severity.Low;
        ClearExtraFilters();
    }

    private static string OptionKey(string? value) =>
        string.IsNullOrEmpty(value) ? FilterOption.NoValue : value.ToLowerInvariant();

    private IReadOnlyList<FilterOption> BuildOptions(Func<T, (string? Key, string? Label)> select, string emptyLabel)
    {
        if (Result is null) return [];
        return Result.Items
            .Select(select)
            .GroupBy(x => OptionKey(x.Key))
            .Select(g => new FilterOption(
                g.Key,
                g.Key == FilterOption.NoValue ? emptyLabel : g.First().Label ?? g.Key,
                g.Count()))
            .OrderBy(o => o.Value == FilterOption.NoValue)
            .ThenBy(o => o.Label, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    protected async Task RunAsync()
    {
        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        Running = true;
        Error = null;
        Status = "Starten…";

        var progress = new Progress<string>(message =>
        {
            Status = message;
            _ = InvokeAsync(StateHasChanged);
        });

        try
        {
            Result = await ExecuteAsync(progress, _cts.Token);
            Status = null;
            DropStaleFilters();
        }
        catch (OperationCanceledException)
        {
            Status = "Geannuleerd.";
        }
        catch (Exception ex)
        {
            Error = ex;
            Status = null;
        }
        finally
        {
            Running = false;
        }
    }

    /// <summary>Drops an item from the current result (e.g. after deleting it in Azure).</summary>
    protected void RemoveFromResult(T item)
    {
        if (Result is null) return;
        Result = Result with { Items = Result.Items.Where(i => !EqualityComparer<T>.Default.Equals(i, item)).ToList() };
    }

    protected void Cancel() => _cts?.Cancel();

    /// <summary>After a re-run, keep a selection only if it still exists in the new results.</summary>
    private void DropStaleFilters()
    {
        SelectedSubscriptions.IntersectWith(SubscriptionOptions.Select(o => o.Value));
        SelectedRegions.IntersectWith(RegionOptions.Select(o => o.Value));
    }

    protected ValueTask DownloadCsvAsync(string fileName, string content) =>
        JS.InvokeVoidAsync("powerTool.downloadFile", fileName, content, "text/csv;charset=utf-8");

    protected override Task OnSessionChangedAsync()
    {
        Cancel();
        Result = null;
        Error = null;
        Status = null;
        ClearFilters();
        return Task.CompletedTask;
    }

    public override void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        base.Dispose();
    }
}
