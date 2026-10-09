using System.Text.Json.Serialization;

namespace SentinelForge.Agent.Models;

public sealed record NormalizedEvent
{
    [JsonPropertyName("event_id")]
    public required string EventId { get; init; }

    [JsonPropertyName("event_time")]
    public required DateTimeOffset EventTime { get; init; }

    [JsonPropertyName("event_type")]
    public required string EventType { get; init; }

    [JsonPropertyName("host")]
    public required HostFields Host { get; init; }

    [JsonPropertyName("source")]
    public required SourceFields Source { get; init; }

    [JsonPropertyName("user")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public UserFields? User { get; init; }

    [JsonPropertyName("process")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ProcessFields? Process { get; init; }

    [JsonPropertyName("network")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public NetworkFields? Network { get; init; }

    [JsonPropertyName("file")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public FileFields? File { get; init; }

    [JsonPropertyName("registry")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public RegistryFields? Registry { get; init; }

    [JsonPropertyName("scenario_run_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ScenarioRunId { get; init; }

    [JsonPropertyName("raw_event_ref")]
    public required string RawEventRef { get; init; }

    [JsonPropertyName("attack_tags")]
    public IReadOnlyList<string> AttackTags { get; init; } = Array.Empty<string>();

    [JsonPropertyName("metadata")]
    public IReadOnlyDictionary<string, string> Metadata { get; init; } = new Dictionary<string, string>();
}

public sealed record HostFields
{
    [JsonPropertyName("hostname")]
    public required string Hostname { get; init; }

    [JsonPropertyName("host_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? HostId { get; init; }

    [JsonPropertyName("os_name")]
    public string? OsName { get; init; } = "Windows";

    [JsonPropertyName("os_version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? OsVersion { get; init; }
}

public sealed record SourceFields(
    [property: JsonPropertyName("provider")] string Provider,
    [property: JsonPropertyName("channel")] string? Channel,
    [property: JsonPropertyName("event_code")] string? EventCode,
    [property: JsonPropertyName("record_id")] string? RecordId);

public sealed record UserFields(
    [property: JsonPropertyName("name")] string? Name,
    [property: JsonPropertyName("domain")] string? Domain,
    [property: JsonPropertyName("sid")] string? Sid);

public sealed record ProcessFields
{
    [JsonPropertyName("pid")]
    public int? Pid { get; init; }

    [JsonPropertyName("guid")]
    public string? Guid { get; init; }

    [JsonPropertyName("name")]
    public string? Name { get; init; }

    [JsonPropertyName("executable")]
    public string? Executable { get; init; }

    [JsonPropertyName("command_line")]
    public string? CommandLine { get; init; }

    [JsonPropertyName("parent_pid")]
    public int? ParentPid { get; init; }

    [JsonPropertyName("parent_guid")]
    public string? ParentGuid { get; init; }

    [JsonPropertyName("parent_name")]
    public string? ParentName { get; init; }

    [JsonPropertyName("parent_executable")]
    public string? ParentExecutable { get; init; }

    [JsonPropertyName("integrity_level")]
    public string? IntegrityLevel { get; init; }

    [JsonPropertyName("sha256")]
    public string? Sha256 { get; init; }
}

public sealed record NetworkFields
{
    [JsonPropertyName("source_ip")]
    public string? SourceIp { get; init; }

    [JsonPropertyName("source_port")]
    public int? SourcePort { get; init; }

    [JsonPropertyName("destination_ip")]
    public string? DestinationIp { get; init; }

    [JsonPropertyName("destination_port")]
    public int? DestinationPort { get; init; }

    [JsonPropertyName("protocol")]
    public string? Protocol { get; init; }

    [JsonPropertyName("dns_question")]
    public string? DnsQuestion { get; init; }
}

public sealed record FileFields
{
    [JsonPropertyName("path")]
    public required string Path { get; init; }

    [JsonPropertyName("operation")]
    public required string Operation { get; init; }

    [JsonPropertyName("sha256")]
    public string? Sha256 { get; init; }

    [JsonPropertyName("size")]
    public long? Size { get; init; }
}

public sealed record RegistryFields
{
    [JsonPropertyName("key_path")]
    public required string KeyPath { get; init; }

    [JsonPropertyName("value_name")]
    public string? ValueName { get; init; }

    [JsonPropertyName("value_data")]
    public string? ValueData { get; init; }

    [JsonPropertyName("operation")]
    public required string Operation { get; init; }
}
