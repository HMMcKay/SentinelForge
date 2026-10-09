using SentinelForge.Agent.Models;

namespace SentinelForge.Agent.Identity;

public interface ISensorIdentityStore
{
    Task<SensorIdentity?> LoadAsync(CancellationToken cancellationToken);
    Task SaveAsync(SensorIdentity identity, CancellationToken cancellationToken);
}
