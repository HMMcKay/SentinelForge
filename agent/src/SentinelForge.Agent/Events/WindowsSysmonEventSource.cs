using System.Diagnostics.Eventing.Reader;
using Microsoft.Extensions.Options;
using SentinelForge.Agent.Configuration;

namespace SentinelForge.Agent.Events;

public sealed class WindowsSysmonEventSource : IEventSource
{
    private readonly AgentOptions _options;
    private readonly ILogger<WindowsSysmonEventSource> _logger;

    public WindowsSysmonEventSource(IOptions<AgentOptions> options, ILogger<WindowsSysmonEventSource> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public Task<IReadOnlyList<SysmonRecord>> ReadBatchAsync(long afterRecordId, int maxCount, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("The Sysmon event source is available only on Windows. Set Agent:EventSource=idle for cross-platform smoke tests.");
        }

        return Task.Run<IReadOnlyList<SysmonRecord>>(() => ReadBatch(afterRecordId, maxCount, cancellationToken), cancellationToken);
    }

#pragma warning disable CA1416 // Every call is dominated by the explicit OperatingSystem.IsWindows guard above.
    private IReadOnlyList<SysmonRecord> ReadBatch(long afterRecordId, int maxCount, CancellationToken cancellationToken)
    {
        var result = new List<SysmonRecord>(maxCount);
        var queryText = $"*[System[EventRecordID > {Math.Max(0, afterRecordId)}]]";
        var query = new EventLogQuery(_options.SysmonChannel, PathType.LogName, queryText)
        {
            ReverseDirection = false,
            TolerateQueryErrors = false
        };

        try
        {
            using var reader = new EventLogReader(query);
            while (result.Count < maxCount && !cancellationToken.IsCancellationRequested)
            {
                using var record = reader.ReadEvent();
                if (record is null) break;

                var xml = record.ToXml();
                result.Add(new SysmonRecord(
                    record.RecordId ?? 0,
                    record.Id,
                    record.TimeCreated is { } time ? new DateTimeOffset(DateTime.SpecifyKind(time, DateTimeKind.Local)) : DateTimeOffset.UtcNow,
                    record.MachineName ?? Environment.MachineName,
                    record.LogName ?? _options.SysmonChannel,
                    record.ProviderName ?? "Microsoft-Windows-Sysmon",
                    xml));
            }
        }
        catch (EventLogNotFoundException exception)
        {
            _logger.LogError(exception, "Sysmon channel {Channel} was not found. Install and configure Sysmon before starting the sensor", _options.SysmonChannel);
            throw;
        }

        return result;
    }
#pragma warning restore CA1416
}
