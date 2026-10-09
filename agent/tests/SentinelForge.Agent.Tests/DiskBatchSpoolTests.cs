using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SentinelForge.Agent.Configuration;
using SentinelForge.Agent.Models;
using SentinelForge.Agent.Runtime;
using SentinelForge.Agent.Spool;

namespace SentinelForge.Agent.Tests;

public sealed class DiskBatchSpoolTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "sentinelforge-tests", Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task PersistsAndCompletesBatch()
    {
        var spool = CreateSpool(1_048_576);
        await spool.InitializeAsync(CancellationToken.None);
        var batch = Batch("one");

        await spool.AppendAsync(batch, CancellationToken.None);
        var item = await spool.PeekAsync(CancellationToken.None);

        Assert.NotNull(item);
        Assert.Equal("one", item.Batch.BatchId);
        await spool.CompleteAsync(item, CancellationToken.None);
        Assert.Null(await spool.PeekAsync(CancellationToken.None));
    }

    [Fact]
    public async Task DropsOldestWholeBatchWhenCapacityIsReached()
    {
        var templateBytes = JsonSerializer.SerializeToUtf8Bytes(Batch("template"), JsonDefaults.Options).Length;
        var health = new SensorHealthState();
        var spool = CreateSpool(templateBytes * 2L + 16, health);
        await spool.InitializeAsync(CancellationToken.None);

        await spool.AppendAsync(Batch("one"), CancellationToken.None);
        await Task.Delay(2);
        await spool.AppendAsync(Batch("two"), CancellationToken.None);
        await Task.Delay(2);
        await spool.AppendAsync(Batch("three"), CancellationToken.None);

        var usage = await spool.GetUsageAsync(CancellationToken.None);
        var first = await spool.PeekAsync(CancellationToken.None);
        Assert.True(usage.BatchCount <= 2);
        Assert.NotEqual("one", first?.Batch.BatchId);
        Assert.Contains("spool_batch_dropped", health.Snapshot(usage.EventCount, usage.Bytes).ErrorCodes);
    }

    [Fact]
    public async Task RefusesCompletionOutsideSpoolDirectory()
    {
        var spool = CreateSpool(1_048_576);
        await spool.InitializeAsync(CancellationToken.None);
        var outside = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".json");
        var item = new SpoolItem(outside, Batch("outside"), 1);

        await Assert.ThrowsAsync<InvalidOperationException>(() => spool.CompleteAsync(item, CancellationToken.None));
    }

    private DiskBatchSpool CreateSpool(long maxBytes, SensorHealthState? health = null)
    {
        var options = Options.Create(new AgentOptions { SpoolDirectory = _directory, SpoolMaxBytes = maxBytes });
        return new DiskBatchSpool(options, NullLogger<DiskBatchSpool>.Instance, health ?? new SensorHealthState());
    }

    private static EventBatch Batch(string id) => new()
    {
        SensorId = "sensor-test",
        BatchId = id,
        Events = Array.Empty<NormalizedEvent>()
    };

    public void Dispose()
    {
        if (Directory.Exists(_directory)) Directory.Delete(_directory, recursive: true);
    }
}
