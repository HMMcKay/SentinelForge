using SentinelForge.Agent.Models;

namespace SentinelForge.Agent.Spool;

public sealed record SpoolItem(string Path, EventBatch Batch, long SizeBytes);
public sealed record SpoolUsage(int BatchCount, int EventCount, long Bytes);

public interface IDurableSpool
{
    Task InitializeAsync(CancellationToken cancellationToken);
    Task AppendAsync(EventBatch batch, CancellationToken cancellationToken);
    Task<SpoolItem?> PeekAsync(CancellationToken cancellationToken);
    Task CompleteAsync(SpoolItem item, CancellationToken cancellationToken);
    Task<SpoolUsage> GetUsageAsync(CancellationToken cancellationToken);
}
