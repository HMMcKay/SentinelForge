using Microsoft.Extensions.Options;
using SentinelForge.Agent.Configuration;
using SentinelForge.Agent.Events;
using SentinelForge.Agent.Identity;
using SentinelForge.Agent.Ingestion;
using SentinelForge.Agent.Runtime;
using SentinelForge.Agent.Spool;

var builder = Host.CreateApplicationBuilder(args);
builder.Configuration.AddEnvironmentVariables(prefix: "SENTINELFORGE_");

builder.Logging.ClearProviders();
builder.Logging.AddJsonConsole(options => options.IncludeScopes = true);

if (OperatingSystem.IsWindows())
{
    builder.Services.AddWindowsService(options => options.ServiceName = "SentinelForge Sensor");
}

builder.Services
    .AddOptions<AgentOptions>()
    .Bind(builder.Configuration.GetSection(AgentOptions.SectionName))
    .ValidateOnStart();
builder.Services.AddSingleton<IValidateOptions<AgentOptions>, AgentOptionsValidator>();

builder.Services.AddSingleton<SensorHealthState>();
builder.Services.AddSingleton<IIdentityProtector, PlatformIdentityProtector>();
builder.Services.AddSingleton<ISensorIdentityStore, FileSensorIdentityStore>();
builder.Services.AddSingleton<IDurableSpool, DiskBatchSpool>();
builder.Services.AddSingleton<ICursorStore, FileCursorStore>();
builder.Services.AddSingleton<ISysmonNormalizer, SysmonNormalizer>();
builder.Services.AddSingleton<IEventSource>(services =>
{
    var options = services.GetRequiredService<IOptions<AgentOptions>>().Value;
    return options.EventSource.Equals("sysmon", StringComparison.OrdinalIgnoreCase)
        ? ActivatorUtilities.CreateInstance<WindowsSysmonEventSource>(services)
        : ActivatorUtilities.CreateInstance<IdleEventSource>(services);
});
builder.Services.AddHttpClient<IIngestionClient, IngestionClient>();
builder.Services.AddHostedService<SensorWorker>();

await builder.Build().RunAsync();
