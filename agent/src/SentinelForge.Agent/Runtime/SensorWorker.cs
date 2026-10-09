using System.Text.Json;
using Microsoft.Extensions.Options;
using SentinelForge.Agent.Configuration;
using SentinelForge.Agent.Events;
using SentinelForge.Agent.Identity;
using SentinelForge.Agent.Ingestion;
using SentinelForge.Agent.Models;
using SentinelForge.Agent.Spool;

namespace SentinelForge.Agent.Runtime;

public sealed class SensorWorker : BackgroundService
{
    private readonly AgentOptions _options;
    private readonly IEventSource _eventSource;
    private readonly ISysmonNormalizer _normalizer;
    private readonly IDurableSpool _spool;
    private readonly ICursorStore _cursorStore;
    private readonly ISensorIdentityStore _identityStore;
    private readonly IIngestionClient _ingestionClient;
    private readonly SensorHealthState _health;
    private readonly ILogger<SensorWorker> _logger;

    public SensorWorker(
        IOptions<AgentOptions> options,
        IEventSource eventSource,
        ISysmonNormalizer normalizer,
        IDurableSpool spool,
        ICursorStore cursorStore,
        ISensorIdentityStore identityStore,
        IIngestionClient ingestionClient,
        SensorHealthState health,
        ILogger<SensorWorker> logger)
    {
        _options = options.Value;
        _eventSource = eventSource;
        _normalizer = normalizer;
        _spool = spool;
        _cursorStore = cursorStore;
        _identityStore = identityStore;
        _ingestionClient = ingestionClient;
        _health = health;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await _spool.InitializeAsync(stoppingToken);
        var identity = await ResolveIdentityAsync(stoppingToken);
        _health.SetSensorId(identity.SensorId);
        using var logScope = _logger.BeginScope(new Dictionary<string, object?> { ["sensor_id"] = identity.SensorId });
        _logger.LogInformation("SentinelForge sensor started with event source {EventSource}", _options.EventSource);

        var cursor = await _cursorStore.LoadAsync(stoppingToken);
        var nextHeartbeat = DateTimeOffset.MinValue;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await DrainSpoolAsync(identity, stoppingToken);
                var records = await _eventSource.ReadBatchAsync(cursor, _options.BatchSize, stoppingToken);
                if (records.Count > 0)
                {
                    var normalized = new List<NormalizedEvent>(records.Count);
                    foreach (var record in records.OrderBy(item => item.RecordId))
                    {
                        try
                        {
                            normalized.Add(_normalizer.Normalize(record, identity.SensorId));
                            _health.RecordEvent(record.EventTime);
                        }
                        catch (Exception exception) when (exception is InvalidDataException or System.Xml.XmlException or FormatException or UnsupportedSysmonEventException)
                        {
                            _health.RecordError($"normalization:{exception.GetType().Name}");
                            _logger.LogError(exception, "Skipped malformed Sysmon record {RecordId}; raw XML was not logged", record.RecordId);
                        }
                    }

                    if (normalized.Count > 0)
                    {
                        await _spool.AppendAsync(EventBatch.Create(identity.SensorId, normalized), stoppingToken);
                    }

                    cursor = records.Max(item => item.RecordId);
                    await _cursorStore.SaveAsync(cursor, stoppingToken);
                    await DrainSpoolAsync(identity, stoppingToken);
                }

                if (DateTimeOffset.UtcNow >= nextHeartbeat)
                {
                    await ReportHealthAsync(identity, stoppingToken);
                    nextHeartbeat = DateTimeOffset.UtcNow.AddSeconds(_options.HeartbeatIntervalSeconds);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                _health.RecordError(exception.GetType().Name);
                _logger.LogError(exception, "Sensor loop failed; collection will retry after the poll interval");
                await WriteLocalHealthAsync(stoppingToken);
            }

            await Task.Delay(TimeSpan.FromSeconds(_options.PollIntervalSeconds), stoppingToken);
        }
    }

    private async Task<SensorIdentity> ResolveIdentityAsync(CancellationToken cancellationToken)
    {
        var persisted = await _identityStore.LoadAsync(cancellationToken);
        if (persisted is not null) return persisted;

        SensorIdentity identity;
        if (!string.IsNullOrWhiteSpace(_options.SensorId) && !string.IsNullOrWhiteSpace(_options.IngestionToken))
        {
            identity = new SensorIdentity(_options.SensorId, _options.IngestionToken);
        }
        else
        {
            _logger.LogInformation("No sensor identity is present; requesting enrollment");
            identity = await _ingestionClient.EnrollAsync(cancellationToken);
        }

        await _identityStore.SaveAsync(identity, cancellationToken);
        return identity;
    }

    private async Task DrainSpoolAsync(SensorIdentity identity, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var item = await _spool.PeekAsync(cancellationToken);
            if (item is null) return;

            IngestionResult result;
            try
            {
                result = await _ingestionClient.SendBatchAsync(item.Batch, identity, cancellationToken);
            }
            catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
            {
                if (cancellationToken.IsCancellationRequested) throw;
                _health.RecordError($"upload:{exception.GetType().Name}");
                _logger.LogWarning(exception, "Batch {BatchId} remains in the spool after upload retries were exhausted", item.Batch.BatchId);
                return;
            }

            if (result.Accepted)
            {
                await _spool.CompleteAsync(item, cancellationToken);
                _health.RecordUpload();
                _logger.LogDebug("Uploaded batch {BatchId} containing {EventCount} events", item.Batch.BatchId, item.Batch.Events.Count);
                continue;
            }

            if (result.PermanentFailure)
            {
                await _spool.CompleteAsync(item, cancellationToken);
                _health.RecordRejectedBatch();
                _health.RecordError($"batch_rejected:{result.StatusCode}");
                _logger.LogError("Backend permanently rejected batch {BatchId} with HTTP {StatusCode}; batch was removed to prevent queue starvation",
                    item.Batch.BatchId, result.StatusCode);
                continue;
            }

            _health.RecordError($"upload:{result.Error}");
            return;
        }
    }

    private async Task ReportHealthAsync(SensorIdentity identity, CancellationToken cancellationToken)
    {
        var snapshot = await WriteLocalHealthAsync(cancellationToken);
        try
        {
            var result = await _ingestionClient.SendHeartbeatAsync(snapshot, identity, cancellationToken);
            if (!result.Accepted)
            {
                _logger.LogWarning("Health heartbeat was not accepted (HTTP {StatusCode})", result.StatusCode);
            }
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            if (cancellationToken.IsCancellationRequested) throw;
            _logger.LogWarning(exception, "Health heartbeat failed; local health telemetry remains available");
        }
    }

    private async Task<SensorHealthSnapshot> WriteLocalHealthAsync(CancellationToken cancellationToken)
    {
        var usage = await _spool.GetUsageAsync(cancellationToken);
        var snapshot = _health.Snapshot(usage.EventCount, usage.Bytes);
        var path = _options.ExpandedHealthPath;
        var directory = Path.GetDirectoryName(path) ?? throw new InvalidOperationException("Health path has no parent directory.");
        Directory.CreateDirectory(directory);
        var temporaryPath = path + ".tmp";
        try
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(snapshot, JsonDefaults.Options);
            await File.WriteAllBytesAsync(temporaryPath, bytes, cancellationToken);
            File.Move(temporaryPath, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
        return snapshot;
    }
}
