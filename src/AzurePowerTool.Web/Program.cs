using AzurePowerTool.Core;
using AzurePowerTool.Core.Auth;
using AzurePowerTool.Core.Storage;
using AzurePowerTool.Web.Auth;
using AzurePowerTool.Web.Components;
using AzurePowerTool.Web.Storage;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;

// Runs entirely in the browser: static files (GitHub Pages), no server. Azure is called directly with the
// signed-in user's token; acknowledgements and the activity log go to a file the user picks.
var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<Routes>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

builder.Services.AddSingleton<BrowserSession>();
builder.Services.AddSingleton<IAzureSession>(sp => sp.GetRequiredService<BrowserSession>());
builder.Services.AddSingleton<LogFileStore>();
builder.Services.AddSingleton<IAppDataStore>(sp => sp.GetRequiredService<LogFileStore>());
builder.Services.AddAzurePowerToolCore();

await builder.Build().RunAsync();
