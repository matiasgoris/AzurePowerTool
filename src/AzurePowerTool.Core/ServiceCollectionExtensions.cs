using AzurePowerTool.Core.Clients;
using AzurePowerTool.Core.Reports;
using AzurePowerTool.Core.Storage;
using Microsoft.Extensions.DependencyInjection;

namespace AzurePowerTool.Core;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Clients, reports, audit log and acknowledgements. An <see cref="Auth.IAzureSession"/> and an
    /// <see cref="IAppDataStore"/> must be registered separately.
    /// </summary>
    public static IServiceCollection AddAzurePowerToolCore(this IServiceCollection services)
    {
        services.AddHttpClient<ArmClient>();
        services.AddHttpClient<ResourceGraphClient>();
        services.AddHttpClient<GraphClient>();
        // Short timeout: vaults behind a private endpoint don't answer from outside and would block the report.
        services.AddHttpClient<KeyVaultClient>(client => client.Timeout = TimeSpan.FromSeconds(20));
        services.AddHttpClient<DnsOverHttpsResolver>();

        services.AddTransient<RoleAssignmentService>();
        services.AddTransient<EmptyResourceGroupsReport>();
        services.AddTransient<OrphanedRoleAssignmentsReport>();
        services.AddTransient<AccessOverviewReport>();
        services.AddTransient<AppCredentialsReport>();
        services.AddTransient<UnusedResourcesReport>();
        services.AddTransient<OrphanedDnsRecordsReport>();
        services.AddTransient<OpenNsgPortsReport>();
        services.AddTransient<InsecureConfigReport>();
        services.AddTransient<PublicStorageReport>();
        services.AddTransient<StorageSasUsageReport>();

        services.AddTransient<AuditLog>();
        services.AddTransient<AcknowledgementStore>();

        return services;
    }
}
