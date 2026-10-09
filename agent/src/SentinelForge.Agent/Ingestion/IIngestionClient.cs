using SentinelForge.Agent.Models;
using SentinelForge.Agent.Runtime;

namespace SentinelForge.Agent.Ingestion;

public sealed record IngestionResult(bool Accepted, bool PermanentFailure, int? StatusCode, string? Error);

public interface IIngestionClient
{
    Task<SensorIdentity> EnrollAsync(CancellationToken cancellationToken);
    Task<IngestionResult> SendBatchAsync(EventBatch batch, SensorIdentity identity, CancellationToken cancellationToken);
    Task<IngestionResult> SendHeartbeatAsync(SensorHealthSnapshot health, SensorIdentity identity, CancellationToken cancellationToken);
}
