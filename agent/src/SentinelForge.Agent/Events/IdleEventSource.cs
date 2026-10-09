namespace SentinelForge.Agent.Events;

public sealed class IdleEventSource : IEventSource
{
    public Task<IReadOnlyList<SysmonRecord>> ReadBatchAsync(long afterRecordId, int maxCount, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<SysmonRecord>>(Array.Empty<SysmonRecord>());
}
