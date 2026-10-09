namespace SentinelForge.Agent.Events;

public sealed record SysmonRecord(
    long RecordId,
    int EventId,
    DateTimeOffset EventTime,
    string Computer,
    string Channel,
    string Provider,
    string Xml);
