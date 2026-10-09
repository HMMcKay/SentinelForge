using SentinelForge.Agent.Models;

namespace SentinelForge.Agent.Events;

public interface ISysmonNormalizer
{
    NormalizedEvent Normalize(SysmonRecord record, string sensorId, DateTimeOffset? ingestTime = null);
}
