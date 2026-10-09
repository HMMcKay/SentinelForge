namespace SentinelForge.Agent.Events;

public sealed class UnsupportedSysmonEventException : Exception
{
    public UnsupportedSysmonEventException(int eventId)
        : base($"Sysmon event ID {eventId} is not supported by normalized schema 1.0.")
    {
        EventId = eventId;
    }

    public int EventId { get; }
}
