namespace SentinelForge.Agent.Events;

public interface IEventSource
{
    Task<IReadOnlyList<SysmonRecord>> ReadBatchAsync(long afterRecordId, int maxCount, CancellationToken cancellationToken);
}
