using AzurePowerTool.Core.Storage;
using Microsoft.JSInterop;

namespace AzurePowerTool.Web.Storage;

public enum LogFileState
{
    /// <summary>The browser can't write files (Firefox, Safari): use Edge or Chrome.</summary>
    Unsupported,
    /// <summary>No file chosen yet.</summary>
    None,
    /// <summary>A file was chosen before; the browser wants a click to grant access again.</summary>
    NeedsPermission,
    Connected,
}

/// <summary>
/// <see cref="AppData"/> in a JSON file the user picks (wwwroot/js/logfile.js, File System Access API).
/// Every write first reads the file again, so changes from another tab or device (OneDrive) are kept.
/// </summary>
public sealed class LogFileStore(IJSRuntime js) : IAppDataStore
{
    private sealed record JsResult(string State, string? Name);

    private readonly SemaphoreSlim _gate = new(1, 1);

    public event Action? Changed;

    public LogFileState State { get; private set; } = LogFileState.None;

    public string? FileName { get; private set; }

    public bool IsAvailable => State == LogFileState.Connected;

    /// <summary>At startup: reconnects to the remembered file when the browser still allows it.</summary>
    public async Task InitializeAsync()
    {
        Apply(await js.InvokeAsync<JsResult>("powerToolLogFile.restore"));
    }

    /// <summary>Needs a click: the browser asks to allow access to the remembered file.</summary>
    public async Task ReconnectAsync() => Apply(await js.InvokeAsync<JsResult>("powerToolLogFile.reconnect"));

    /// <summary>Lets the user pick a new file. An existing valid log in that place is kept, not overwritten.</summary>
    public async Task CreateAsync()
    {
        var result = await js.InvokeAsync<JsResult?>("powerToolLogFile.create");
        if (result is null) return; // cancelled
        Apply(result);
        if (IsAvailable)
        {
            // Writes a valid (possibly empty) document; refuses a file that isn't ours.
            var data = await ReadAsync();
            await WriteAsync(data);
        }
    }

    public async Task OpenAsync()
    {
        var result = await js.InvokeAsync<JsResult?>("powerToolLogFile.open");
        if (result is null) return;
        Apply(result);
        if (IsAvailable)
        {
            try
            {
                await ReadAsync(); // validate now rather than on the first acknowledgement
            }
            catch
            {
                await DisconnectAsync();
                throw;
            }
        }
    }

    public async Task DisconnectAsync()
    {
        await js.InvokeVoidAsync("powerToolLogFile.forget");
        State = LogFileState.None;
        FileName = null;
        Changed?.Invoke();
    }

    public async Task<AppData> ReadAsync(CancellationToken ct = default)
    {
        EnsureAvailable();
        return AppData.Parse(await js.InvokeAsync<string>("powerToolLogFile.read", ct));
    }

    public async Task UpdateAsync(Action<AppData> change, CancellationToken ct = default)
    {
        EnsureAvailable();
        await _gate.WaitAsync(ct);
        try
        {
            var data = await ReadAsync(ct);
            change(data);
            await WriteAsync(data, ct);
        }
        finally
        {
            _gate.Release();
        }
    }

    private Task WriteAsync(AppData data, CancellationToken ct = default) =>
        js.InvokeVoidAsync("powerToolLogFile.write", ct, data.Serialize()).AsTask();

    private void EnsureAvailable()
    {
        if (!IsAvailable) throw new InvalidOperationException("Er is geen logbestand gekoppeld. Kies er een links onderaan.");
    }

    private void Apply(JsResult result)
    {
        State = result.State switch
        {
            "unsupported" => LogFileState.Unsupported,
            "granted" => LogFileState.Connected,
            "prompt" or "denied" => LogFileState.NeedsPermission,
            _ => LogFileState.None,
        };
        FileName = result.Name;
        Changed?.Invoke();
    }
}
