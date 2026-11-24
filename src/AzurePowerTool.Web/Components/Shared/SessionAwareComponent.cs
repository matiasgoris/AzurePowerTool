using AzurePowerTool.Core.Auth;
using AzurePowerTool.Core.Storage;
using Microsoft.AspNetCore.Components;

namespace AzurePowerTool.Web.Components.Shared;

/// <summary>Re-renders when the user signs in/out, switches tenant, or (dis)connects the log file.</summary>
public abstract class SessionAwareComponent : ComponentBase, IDisposable
{
    [Inject] protected IAzureSession Session { get; set; } = default!;
    [Inject] private IAppDataStore Store { get; set; } = default!;

    protected override void OnInitialized()
    {
        Session.Changed += HandleSessionChanged;
        Store.Changed += HandleStoreChanged;
    }

    protected virtual Task OnSessionChangedAsync() => Task.CompletedTask;

    private void HandleSessionChanged() => _ = InvokeAsync(async () =>
    {
        await OnSessionChangedAsync();
        StateHasChanged();
    });

    private void HandleStoreChanged() => _ = InvokeAsync(StateHasChanged);

    public virtual void Dispose()
    {
        Session.Changed -= HandleSessionChanged;
        Store.Changed -= HandleStoreChanged;
        GC.SuppressFinalize(this);
    }
}
