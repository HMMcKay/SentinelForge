namespace SentinelForge.Agent.Configuration;

public sealed record AgentOptions
{
    public const string SectionName = "Agent";

    public string BaseUrl { get; init; } = "http://127.0.0.1:8000";
    public string EnrollmentPath { get; init; } = "/api/v1/sensors/enroll";
    public string IngestionPath { get; init; } = "/api/v1/events/batch";
    public string HeartbeatPathTemplate { get; init; } = "/api/v1/sensors/{sensor_id}/heartbeat";
    public string EnrollmentToken { get; init; } = string.Empty;
    public string SensorId { get; init; } = string.Empty;
    public string IngestionToken { get; init; } = string.Empty;
    public string SensorName { get; init; } = string.Empty;
    public string EventSource { get; init; } = "sysmon";
    public string SysmonChannel { get; init; } = "Microsoft-Windows-Sysmon/Operational";
    public int BatchSize { get; init; } = 100;
    public int PollIntervalSeconds { get; init; } = 2;
    public int HeartbeatIntervalSeconds { get; init; } = 30;
    public int RequestTimeoutSeconds { get; init; } = 15;
    public int MaxRetryAttempts { get; init; } = 5;
    public int RetryBaseDelayMilliseconds { get; init; } = 500;
    public int RetryMaxDelaySeconds { get; init; } = 30;
    public string SpoolDirectory { get; init; } = "%ProgramData%\\SentinelForge\\spool";
    public long SpoolMaxBytes { get; init; } = 256L * 1024 * 1024;
    public string IdentityPath { get; init; } = "%ProgramData%\\SentinelForge\\identity.bin";
    public string CursorPath { get; init; } = "%ProgramData%\\SentinelForge\\cursor.txt";
    public string HealthPath { get; init; } = "%ProgramData%\\SentinelForge\\health.json";
    public bool AllowInsecureHttp { get; init; }
    public bool AllowPlaintextIdentityForTests { get; init; }

    public string ExpandedSpoolDirectory => ExpandPath(SpoolDirectory);
    public string ExpandedIdentityPath => ExpandPath(IdentityPath);
    public string ExpandedCursorPath => ExpandPath(CursorPath);
    public string ExpandedHealthPath => ExpandPath(HealthPath);

    private static string ExpandPath(string path) =>
        Path.GetFullPath(Environment.ExpandEnvironmentVariables(path));
}
