using System.Text.Json.Serialization;

namespace SentinelForge.Agent.Models;

public sealed record EventBatch
{
    [JsonPropertyName("schema_version")]
    public string SchemaVersion { get; init; } = "1.0";

    [JsonPropertyName("sensor_id")]
    public required string SensorId { get; init; }

    [JsonPropertyName("batch_id")]
    public required string BatchId { get; init; }

    [JsonPropertyName("events")]
    public required IReadOnlyList<NormalizedEvent> Events { get; init; }

    public static EventBatch Create(string sensorId, IReadOnlyList<NormalizedEvent> events) => new()
    {
        SensorId = sensorId,
        BatchId = Guid.NewGuid().ToString("D"),
        Events = events
    };
}
