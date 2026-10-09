using System.Text.Json.Serialization;

namespace SentinelForge.Agent.Models;

public sealed record SensorIdentity(
    [property: JsonPropertyName("sensor_id")] string SensorId,
    [property: JsonPropertyName("ingestion_token")] string IngestionToken);
