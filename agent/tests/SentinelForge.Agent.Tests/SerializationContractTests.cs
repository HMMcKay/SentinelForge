using System.Text.Json;
using SentinelForge.Agent.Events;
using SentinelForge.Agent.Models;
using SentinelForge.Agent.Runtime;

namespace SentinelForge.Agent.Tests;

public sealed class SerializationContractTests
{
    [Fact]
    public void BatchMatchesBackendSchemaVersionAndFlattenedEventShape()
    {
        const string xml = """
            <Event><EventData>
              <Data Name="ProcessGuid">{11111111-1111-1111-1111-111111111111}</Data>
              <Data Name="ProcessId">4242</Data>
              <Data Name="Image">C:\Windows\System32\cmd.exe</Data>
              <Data Name="CommandLine">cmd.exe /d /c exit 0</Data>
            </EventData></Event>
            """;
        var normalized = new SysmonNormalizer().Normalize(Record(1, 55, xml), "sensor-contract");
        var batch = new EventBatch
        {
            SensorId = "sensor-contract",
            BatchId = "batch-contract",
            Events = new[] { normalized }
        };

        using var document = JsonDocument.Parse(JsonSerializer.Serialize(batch, JsonDefaults.Options));
        var root = document.RootElement;
        var item = root.GetProperty("events")[0];
        Assert.Equal("1.0", root.GetProperty("schema_version").GetString());
        Assert.Equal("sensor-contract", root.GetProperty("sensor_id").GetString());
        Assert.Equal("process_start", item.GetProperty("event_type").GetString());
        Assert.Equal(JsonValueKind.String, item.GetProperty("source").GetProperty("record_id").ValueKind);
        Assert.Equal("55", item.GetProperty("source").GetProperty("record_id").GetString());
        Assert.Equal("sysmon:sensor-contract:55", item.GetProperty("raw_event_ref").GetString());
        Assert.False(item.TryGetProperty("raw", out _));
        Assert.False(item.TryGetProperty("schema_version", out _));
        Assert.False(item.TryGetProperty("sensor_id", out _));
        Assert.False(item.TryGetProperty("event", out _));
        Assert.DoesNotContain("<Event", JsonSerializer.Serialize(batch, JsonDefaults.Options), StringComparison.Ordinal);
    }

    [Fact]
    public void RegistryRunValueSeparatesParentKeyFromValueName()
    {
        const string xml = """
            <Event><EventData>
              <Data Name="ProcessId">12</Data>
              <Data Name="Image">C:\Windows\reg.exe</Data>
              <Data Name="TargetObject">HKU\S-1-5-21\Software\Microsoft\Windows\CurrentVersion\Run\SentinelForgeBenign</Data>
              <Data Name="Details">C:\Lab\benign.exe</Data>
            </EventData></Event>
            """;
        var normalized = new SysmonNormalizer().Normalize(Record(13, 56, xml), "sensor-contract");
        var json = JsonSerializer.SerializeToElement(normalized, JsonDefaults.Options);

        Assert.Equal("registry_set", json.GetProperty("event_type").GetString());
        Assert.Equal("HKU\\S-1-5-21\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            json.GetProperty("registry").GetProperty("key_path").GetString());
        Assert.Equal("SentinelForgeBenign", json.GetProperty("registry").GetProperty("value_name").GetString());
        Assert.Equal("set", json.GetProperty("registry").GetProperty("operation").GetString());
    }

    [Fact]
    public void HeartbeatMatchesStrictBackendShape()
    {
        var state = new SensorHealthState();
        state.RecordEvent(DateTimeOffset.Parse("2026-01-02T03:04:05Z"));
        state.RecordError("upload:HttpRequestException");
        var json = JsonSerializer.SerializeToElement(state.Snapshot(7, 4096), JsonDefaults.Options);
        var names = json.EnumerateObject().Select(property => property.Name).ToHashSet(StringComparer.Ordinal);

        Assert.Equal(
            new[] { "agent_version", "error_codes", "last_event_time", "service_mode", "spool_bytes", "spool_event_count", "status" }.Order(),
            names.Order());
        Assert.Equal("degraded", json.GetProperty("status").GetString());
        Assert.Equal(7, json.GetProperty("spool_event_count").GetInt32());
        Assert.DoesNotContain("HttpRequestException", json.GetRawText(), StringComparison.Ordinal);
    }

    private static SysmonRecord Record(int eventId, long recordId, string xml) => new(
        recordId,
        eventId,
        DateTimeOffset.Parse("2026-01-02T03:04:05Z"),
        "LAB-WS01",
        "Microsoft-Windows-Sysmon/Operational",
        "Microsoft-Windows-Sysmon",
        xml);
}
