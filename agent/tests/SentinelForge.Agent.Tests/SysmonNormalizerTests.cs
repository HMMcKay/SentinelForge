using System.Xml;
using SentinelForge.Agent.Events;

namespace SentinelForge.Agent.Tests;

public sealed class SysmonNormalizerTests
{
    private const string ProcessCreateXml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID></System>
          <EventData>
            <Data Name="RuleName">technique_id=T1059.001</Data>
            <Data Name="UtcTime">2026-01-02 03:04:05.000</Data>
            <Data Name="ProcessGuid">{11111111-1111-1111-1111-111111111111}</Data>
            <Data Name="ProcessId">4242</Data>
            <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
            <Data Name="CommandLine">powershell.exe -NoProfile</Data>
            <Data Name="CurrentDirectory">C:\Lab\</Data>
            <Data Name="User">LAB\analyst</Data>
            <Data Name="ParentProcessGuid">{22222222-2222-2222-2222-222222222222}</Data>
            <Data Name="ParentProcessId">1200</Data>
            <Data Name="ParentImage">C:\Windows\System32\cmd.exe</Data>
            <Data Name="ParentCommandLine">cmd.exe /d /c</Data>
            <Data Name="Hashes">SHA256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,MD5=1234</Data>
          </EventData>
        </Event>
        """;

    [Fact]
    public void NormalizesProcessLineageAndAttackTag()
    {
        var normalizer = new SysmonNormalizer();
        var record = Record(1, 99, ProcessCreateXml);

        var result = normalizer.Normalize(record, "sensor-1", DateTimeOffset.Parse("2026-01-02T03:05:00Z"));

        Assert.Equal("process_start", result.EventType);
        Assert.Equal(4242, result.Process?.Pid);
        Assert.Equal("powershell.exe", result.Process?.Name);
        Assert.Equal("cmd.exe", result.Process?.ParentName);
        Assert.Equal("analyst", result.User?.Name);
        Assert.Equal("LAB", result.User?.Domain);
        Assert.Equal(new string('A', 64), result.Process?.Sha256);
        Assert.Contains("T1059.001", result.AttackTags);
        Assert.Equal("99", result.Source.RecordId);
        Assert.Equal("sysmon:sensor-1:99", result.RawEventRef);
    }

    [Fact]
    public void NormalizesRegistryValue()
    {
        const string xml = """
            <Event><EventData>
              <Data Name="ProcessId">41</Data><Data Name="Image">C:\Windows\reg.exe</Data>
              <Data Name="TargetObject">HKU\S-1-5-21\Software\SentinelForgeLab\CurrentVersion\Run\Demo</Data>
              <Data Name="Details">C:\Lab\benign.exe</Data>
            </EventData></Event>
            """;

        var result = new SysmonNormalizer().Normalize(Record(13, 100, xml), "sensor-1");

        Assert.Equal("registry_set", result.EventType);
        Assert.Equal("HKU\\S-1-5-21\\Software\\SentinelForgeLab\\CurrentVersion\\Run", result.Registry?.KeyPath);
        Assert.Equal("Demo", result.Registry?.ValueName);
        Assert.Equal("C:\\Lab\\benign.exe", result.Registry?.ValueData);
    }

    [Fact]
    public void EventIdentifierIsDeterministic()
    {
        var normalizer = new SysmonNormalizer();
        var first = normalizer.Normalize(Record(1, 101, ProcessCreateXml), "sensor-a");
        var second = normalizer.Normalize(Record(1, 101, ProcessCreateXml), "sensor-a");
        var other = normalizer.Normalize(Record(1, 102, ProcessCreateXml), "sensor-a");

        Assert.Equal(first.EventId, second.EventId);
        Assert.NotEqual(first.EventId, other.EventId);
    }

    [Fact]
    public void RejectsDocumentTypeDeclarations()
    {
        const string xml = "<!DOCTYPE Event [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><Event><EventData><Data Name='Image'>&xxe;</Data></EventData></Event>";
        Assert.Throws<XmlException>(() => new SysmonNormalizer().Normalize(Record(1, 1, xml), "sensor-a"));
    }

    [Fact]
    public void RejectsUnsupportedEventIdsBeforeSerialization()
    {
        const string xml = "<Event><EventData><Data Name='Image'>C:\\Windows\\example.dll</Data></EventData></Event>";
        Assert.Throws<UnsupportedSysmonEventException>(() => new SysmonNormalizer().Normalize(Record(7, 7, xml), "sensor-a"));
    }

    [Fact]
    public void DerivesScenarioRunIdOnlyFromSentinelForgeNamespace()
    {
        const string runId = "12345678-1234-4234-9234-123456789abc";
        var xml = $"""
            <Event><EventData>
              <Data Name="ProcessId">101</Data>
              <Data Name="Image">C:\Windows\System32\cmd.exe</Data>
              <Data Name="CommandLine">cmd.exe /d /c type C:\Temp\SentinelForgeLab\runs\{runId}\marker.txt</Data>
            </EventData></Event>
            """;

        var result = new SysmonNormalizer().Normalize(Record(1, 103, xml), "sensor-a");
        Assert.Equal(runId, result.ScenarioRunId);
    }

    [Theory]
    [InlineData("cmd.exe /c echo 12345678-1234-4234-9234-123456789abc")]
    [InlineData("C:\\Temp\\NotSentinelForgeLab\\Runs\\12345678-1234-4234-9234-123456789abc\\file.txt")]
    [InlineData("C:\\Temp\\SentinelForgeLabFake\\Runs\\12345678-1234-4234-9234-123456789abc\\file.txt")]
    public void DoesNotDeriveScenarioRunIdFromBareOrLookalikeUuid(string commandLine)
    {
        var xml = $"<Event><EventData><Data Name='ProcessId'>101</Data><Data Name='Image'>C:\\Windows\\cmd.exe</Data><Data Name='CommandLine'>{commandLine}</Data></EventData></Event>";
        var result = new SysmonNormalizer().Normalize(Record(1, 104, xml), "sensor-a");
        Assert.Null(result.ScenarioRunId);
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
