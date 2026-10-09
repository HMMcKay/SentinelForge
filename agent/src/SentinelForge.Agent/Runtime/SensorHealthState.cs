using System.Text.Json.Serialization;
using Microsoft.Extensions.Hosting.WindowsServices;

namespace SentinelForge.Agent.Runtime;

public sealed record SensorHealthSnapshot
{
    [JsonPropertyName("status")]
    public required string Status { get; init; }

    [JsonPropertyName("agent_version")]
    public required string AgentVersion { get; init; }

    [JsonPropertyName("service_mode")]
    public required bool ServiceMode { get; init; }

    [JsonPropertyName("spool_event_count")]
    public required int SpoolEventCount { get; init; }

    [JsonPropertyName("spool_bytes")]
    public required long SpoolBytes { get; init; }

    [JsonPropertyName("last_event_time")]
    public DateTimeOffset? LastEventTime { get; init; }

    [JsonPropertyName("error_codes")]
    public IReadOnlyList<string> ErrorCodes { get; init; } = Array.Empty<string>();
}

public sealed class SensorHealthState
{
    private static readonly string AgentVersion =
        (typeof(SensorHealthState).Assembly.GetName().Version ?? new Version(0, 0)).ToString(3);
    private readonly object _gate = new();
    private DateTimeOffset? _lastEventTime;
    private string? _lastError;
    private bool _droppedBatch;
    private bool _rejectedBatch;

    public void SetSensorId(string sensorId) => ArgumentException.ThrowIfNullOrWhiteSpace(sensorId);
    public void RecordEvent(DateTimeOffset time) { lock (_gate) _lastEventTime = time; }
    public void RecordUpload() { lock (_gate) _lastError = null; }
    public void RecordError(string error) { lock (_gate) _lastError = SanitizeCode(error); }
    public void RecordDroppedBatch() { lock (_gate) _droppedBatch = true; }
    public void RecordRejectedBatch() { lock (_gate) _rejectedBatch = true; }

    public SensorHealthSnapshot Snapshot(int spoolEventCount, long spoolBytes)
    {
        lock (_gate)
        {
            var errors = new List<string>(3);
            if (_lastError is not null) errors.Add(_lastError);
            if (_droppedBatch) errors.Add("spool_batch_dropped");
            if (_rejectedBatch) errors.Add("batch_rejected");
            return new SensorHealthSnapshot
            {
                Status = errors.Count == 0 ? "healthy" : "degraded",
                AgentVersion = AgentVersion,
                ServiceMode = OperatingSystem.IsWindows() && WindowsServiceHelpers.IsWindowsService(),
                SpoolEventCount = Math.Max(0, spoolEventCount),
                SpoolBytes = Math.Max(0, spoolBytes),
                LastEventTime = _lastEventTime,
                ErrorCodes = errors
            };
        }
    }

    private static string SanitizeCode(string value)
    {
        var sanitized = new string(value
            .ToLowerInvariant()
            .Select(character => char.IsAsciiLetterOrDigit(character) || character is '_' or '-' or ':' ? character : '_')
            .Take(64)
            .ToArray());
        return string.IsNullOrWhiteSpace(sanitized) ? "unknown_error" : sanitized;
    }
}
