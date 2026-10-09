namespace SentinelForge.Agent.Spool;

public interface ICursorStore
{
    Task<long> LoadAsync(CancellationToken cancellationToken);
    Task SaveAsync(long recordId, CancellationToken cancellationToken);
}
