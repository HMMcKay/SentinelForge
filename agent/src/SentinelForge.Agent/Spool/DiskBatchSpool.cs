using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Options;
using SentinelForge.Agent.Configuration;
using SentinelForge.Agent.Models;
using SentinelForge.Agent.Runtime;

namespace SentinelForge.Agent.Spool;

public sealed class DiskBatchSpool : IDurableSpool
{
    private readonly string _directory;
    private readonly long _maxBytes;
    private readonly ILogger<DiskBatchSpool> _logger;
    private readonly SensorHealthState _health;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public DiskBatchSpool(IOptions<AgentOptions> options, ILogger<DiskBatchSpool> logger, SensorHealthState health)
    {
        _directory = options.Value.ExpandedSpoolDirectory;
        _maxBytes = options.Value.SpoolMaxBytes;
        _logger = logger;
        _health = health;
    }

    public Task InitializeAsync(CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(_directory);
        return Task.CompletedTask;
    }

    public async Task AppendAsync(EventBatch batch, CancellationToken cancellationToken)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(batch, JsonDefaults.Options);
        if (bytes.LongLength > _maxBytes)
        {
            throw new InvalidOperationException("A single event batch exceeds the configured spool capacity.");
        }

        await _gate.WaitAsync(cancellationToken);
        try
        {
            Directory.CreateDirectory(_directory);
            var files = EnumerateBatchFiles();
            var used = files.Sum(file => file.Length);
            foreach (var oldest in files)
            {
                if (used + bytes.LongLength <= _maxBytes) break;
                File.Delete(oldest.FullName);
                used -= oldest.Length;
                _health.RecordDroppedBatch();
                _logger.LogWarning("Spool capacity reached; dropped oldest batch file {BatchFile}", oldest.Name);
            }

            var timestamp = DateTimeOffset.UtcNow.ToString("yyyyMMddHHmmssfffffff", CultureInfo.InvariantCulture);
            var finalPath = Path.Combine(_directory, $"{timestamp}-{batch.BatchId}.batch.json");
            var temporaryPath = finalPath + ".tmp";
            try
            {
                await File.WriteAllBytesAsync(temporaryPath, bytes, cancellationToken);
                File.Move(temporaryPath, finalPath);
            }
            finally
            {
                if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<SpoolItem?> PeekAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            while (true)
            {
                var file = EnumerateBatchFiles().FirstOrDefault();
                if (file is null) return null;
                try
                {
                    await using var stream = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, useAsync: true);
                    var batch = await JsonSerializer.DeserializeAsync<EventBatch>(stream, JsonDefaults.Options, cancellationToken);
                    if (batch is null) throw new JsonException("Batch deserialized to null.");
                    return new SpoolItem(file.FullName, batch, file.Length);
                }
                catch (Exception exception) when (exception is JsonException or IOException)
                {
                    _logger.LogError(exception, "Discarding unreadable spool file {BatchFile}", file.Name);
                    File.Delete(file.FullName);
                    _health.RecordDroppedBatch();
                }
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task CompleteAsync(SpoolItem item, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var fullPath = Path.GetFullPath(item.Path);
            var root = Path.GetFullPath(_directory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (!fullPath.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Refusing to delete a spool item outside the spool directory.");
            }
            if (File.Exists(fullPath)) File.Delete(fullPath);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<SpoolUsage> GetUsageAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var files = EnumerateBatchFiles();
            var eventCount = 0;
            foreach (var file in files)
            {
                try
                {
                    await using var stream = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.Read, 16 * 1024, useAsync: true);
                    using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
                    if (document.RootElement.TryGetProperty("events", out var events) && events.ValueKind == JsonValueKind.Array)
                    {
                        eventCount += events.GetArrayLength();
                    }
                }
                catch (Exception exception) when (exception is IOException or JsonException)
                {
                    _logger.LogWarning(exception, "Could not count events in spool file {BatchFile}", file.Name);
                }
            }
            return new SpoolUsage(files.Count, eventCount, files.Sum(file => file.Length));
        }
        finally
        {
            _gate.Release();
        }
    }

    private List<FileInfo> EnumerateBatchFiles() => new DirectoryInfo(_directory)
        .EnumerateFiles("*.batch.json", SearchOption.TopDirectoryOnly)
        .OrderBy(file => file.Name, StringComparer.Ordinal)
        .ToList();
}
