using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using SentinelForge.Agent.Models;

namespace SentinelForge.Agent.Events;

public sealed class SysmonNormalizer : ISysmonNormalizer
{
    private const long MaxXmlCharacters = 2 * 1024 * 1024;

    public NormalizedEvent Normalize(SysmonRecord record, string sensorId, DateTimeOffset? ingestTime = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sensorId);
        _ = ingestTime;
        var data = ParseEventData(record.Xml);
        var image = Get(data, "Image");
        var targetFilename = Get(data, "TargetFilename");
        var targetObject = Get(data, "TargetObject");
        var user = SplitUser(Get(data, "User"), Get(data, "UserId"));
        var eventType = MapEventType(record.EventId, data);
        var process = BuildProcess(data, image);
        if (record.EventId is 1 or 5 && process is null)
        {
            throw new InvalidDataException($"Sysmon event ID {record.EventId} is missing its process identity fields.");
        }

        return new NormalizedEvent
        {
            EventId = StableEventId(sensorId, record.Channel, record.RecordId),
            EventTime = record.EventTime.ToUniversalTime(),
            EventType = eventType,
            Host = new HostFields
            {
                Hostname = string.IsNullOrWhiteSpace(record.Computer) ? throw new InvalidDataException("Sysmon record has no computer name.") : record.Computer,
                HostId = sensorId,
                OsVersion = Environment.OSVersion.VersionString
            },
            Source = new SourceFields(
                record.Provider,
                record.Channel,
                record.EventId.ToString(CultureInfo.InvariantCulture),
                record.RecordId.ToString(CultureInfo.InvariantCulture)),
            User = user,
            Process = process,
            File = record.EventId is 11 or 23 or 26 ? BuildFile(record.EventId, targetFilename, data) : null,
            Registry = record.EventId is 12 or 13 or 14 ? BuildRegistry(record.EventId, targetObject, data) : null,
            Network = record.EventId is 3 or 22 ? BuildNetwork(record.EventId, data) : null,
            ScenarioRunId = ParseScenarioRunId(Get(data, "ScenarioRunId")) ?? DeriveScenarioRunId(data),
            RawEventRef = $"sysmon:{sensorId}:{record.RecordId}",
            AttackTags = BuildAttackTags(Get(data, "RuleName")),
            Metadata = BuildMetadata(data)
        };
    }

    private static IReadOnlyDictionary<string, string> ParseEventData(string xml)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = MaxXmlCharacters
        };
        using var stringReader = new StringReader(xml);
        using var reader = XmlReader.Create(stringReader, settings);
        var document = XDocument.Load(reader, LoadOptions.None);
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var element in document.Descendants().Where(item => item.Name.LocalName == "Data"))
        {
            var name = element.Attributes().FirstOrDefault(attribute => attribute.Name.LocalName == "Name")?.Value;
            if (!string.IsNullOrWhiteSpace(name)) result[name] = element.Value;
        }

        return result;
    }

    private static ProcessFields? BuildProcess(IReadOnlyDictionary<string, string> data, string? image)
    {
        var processGuid = EmptyToNull(Get(data, "ProcessGuid"));
        var processId = ParseInt(Get(data, "ProcessId"));
        if (image is null && processGuid is null && processId is null) return null;

        var parentImage = EmptyToNull(Get(data, "ParentImage"));
        return new ProcessFields
        {
            Pid = processId,
            Guid = processGuid,
            Name = SafeFileName(image),
            Executable = EmptyToNull(image),
            CommandLine = EmptyToNull(Get(data, "CommandLine")),
            ParentPid = ParseInt(Get(data, "ParentProcessId")),
            ParentGuid = EmptyToNull(Get(data, "ParentProcessGuid")),
            ParentName = SafeFileName(parentImage),
            ParentExecutable = parentImage,
            IntegrityLevel = EmptyToNull(Get(data, "IntegrityLevel")),
            Sha256 = GetHash(Get(data, "Hashes"), "sha256")
        };
    }

    private static FileFields BuildFile(int eventId, string? path, IReadOnlyDictionary<string, string> data)
    {
        path = EmptyToNull(path);
        if (path is null) throw new InvalidDataException($"Sysmon event ID {eventId} has no TargetFilename.");
        return new FileFields
        {
            Path = path,
            Operation = eventId is 23 or 26 ? "delete" : "create",
            Sha256 = GetHash(Get(data, "Hashes"), "sha256"),
            Size = ParseNonNegativeLong(Get(data, "FileSize"))
        };
    }

    private static RegistryFields BuildRegistry(int eventId, string? targetObject, IReadOnlyDictionary<string, string> data)
    {
        var path = EmptyToNull(targetObject);
        if (path is null) throw new InvalidDataException($"Sysmon event ID {eventId} has no TargetObject.");
        string? value = null;
        if (eventId is 13 or 14)
        {
            var separator = path.LastIndexOf('\\');
            if (separator >= 0 && separator < path.Length - 1)
            {
                value = path[(separator + 1)..];
                path = path[..separator];
            }
        }

        var eventType = EmptyToNull(Get(data, "EventType"));
        var operation = eventId switch
        {
            12 when eventType?.Contains("Delete", StringComparison.OrdinalIgnoreCase) == true => "delete_key",
            12 => "create_key",
            _ => "set"
        };
        return new RegistryFields
        {
            KeyPath = path,
            ValueName = value,
            ValueData = EmptyToNull(Get(data, "Details")),
            Operation = operation
        };
    }

    private static NetworkFields BuildNetwork(int eventId, IReadOnlyDictionary<string, string> data) => new()
    {
        SourceIp = EmptyToNull(Get(data, "SourceIp")),
        SourcePort = ParsePort(Get(data, "SourcePort")),
        DestinationIp = EmptyToNull(Get(data, "DestinationIp")),
        DestinationPort = ParsePort(Get(data, "DestinationPort")),
        Protocol = EmptyToNull(Get(data, "Protocol"))?.ToLowerInvariant() ?? (eventId == 22 ? "dns" : null),
        DnsQuestion = EmptyToNull(Get(data, "QueryName"))
    };

    private static UserFields? SplitUser(string? account, string? id)
    {
        account = EmptyToNull(account);
        id = EmptyToNull(id);
        if (account is null && id is null) return null;
        var separator = account?.IndexOf('\\') ?? -1;
        return separator > 0
            ? new UserFields(account![(separator + 1)..], account[..separator], id)
            : new UserFields(account, null, id);
    }

    private static IReadOnlyList<string> BuildAttackTags(string? ruleName)
    {
        var values = (ruleName ?? string.Empty)
            .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        var techniques = values
            .SelectMany(value => value.Split('=', StringSplitOptions.TrimEntries))
            .Where(value => Regex.IsMatch(value, "^T[0-9]{4}(?:\\.[0-9]{3})?$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        return techniques;
    }

    private static IReadOnlyDictionary<string, string> BuildMetadata(IReadOnlyDictionary<string, string> data)
    {
        var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        AddIfPresent(metadata, "sysmon_rule_name", Get(data, "RuleName"));
        AddIfPresent(metadata, "sysmon_utc_time", Get(data, "UtcTime"));
        AddIfPresent(metadata, "registry_event_type", Get(data, "EventType"));
        AddIfPresent(metadata, "current_directory", Get(data, "CurrentDirectory"));
        AddIfPresent(metadata, "parent_command_line", Get(data, "ParentCommandLine"));
        AddIfPresent(metadata, "network_initiated", Get(data, "Initiated"));
        return metadata;
    }

    private static IReadOnlyDictionary<string, string> ParseHashes(string? value)
    {
        var hashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in (value ?? string.Empty).Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = entry.IndexOf('=');
            if (separator > 0 && separator < entry.Length - 1)
            {
                hashes[entry[..separator].ToLowerInvariant()] = entry[(separator + 1)..];
            }
        }
        return hashes;
    }

    private static string StableEventId(string sensorId, string channel, long recordId)
    {
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes($"{sensorId}\n{channel}\n{recordId}"));
        return Convert.ToHexString(digest).ToLowerInvariant();
    }

    private static string MapEventType(int eventId, IReadOnlyDictionary<string, string> data) => eventId switch
    {
        1 => "process_start",
        3 => "network_connection",
        5 => "process_end",
        11 => "file_create",
        12 when Get(data, "EventType")?.Contains("Delete", StringComparison.OrdinalIgnoreCase) == true => "registry_delete",
        12 => "registry_set",
        13 or 14 => "registry_set",
        22 => "dns_query",
        23 or 26 => "file_delete",
        _ => throw new UnsupportedSysmonEventException(eventId)
    };

    private static string? Get(IReadOnlyDictionary<string, string> data, string key) =>
        data.TryGetValue(key, out var value) ? EmptyToNull(value) : null;

    private static int? ParseInt(string? value) =>
        int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var result) ? result : null;

    private static long? ParseNonNegativeLong(string? value) =>
        long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var result) && result >= 0 ? result : null;

    private static int? ParsePort(string? value) =>
        int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var result) && result is >= 0 and <= 65535 ? result : null;

    private static string? GetHash(string? value, string algorithm)
    {
        var hashes = ParseHashes(value);
        return hashes.TryGetValue(algorithm, out var hash) && Regex.IsMatch(hash, "^[A-Fa-f0-9]{64}$", RegexOptions.CultureInvariant)
            ? hash
            : null;
    }

    private static string? ParseScenarioRunId(string? value)
    {
        value = EmptyToNull(value);
        if (value is null) return null;
        return Regex.IsMatch(value, "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$", RegexOptions.CultureInvariant)
            ? value
            : null;
    }

    private static string? DeriveScenarioRunId(IReadOnlyDictionary<string, string> data)
    {
        // Attribution requires an observable SentinelForge namespace. A bare UUID in a command
        // line is deliberately insufficient because it could associate unrelated activity.
        const string pattern = @"(?:^|[\\/\""'])(?:SentinelForgeLab)[\\/](?:Runs[\\/])?(?<run>[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})(?=$|[\\/\""']|-[A-Za-z0-9_-]+)";
        foreach (var field in new[] { "TargetFilename", "TargetObject", "Image", "CommandLine", "ParentCommandLine", "TaskName" })
        {
            var value = Get(data, field);
            if (value is null) continue;
            var match = Regex.Match(
                value,
                pattern,
                RegexOptions.CultureInvariant | RegexOptions.IgnoreCase,
                TimeSpan.FromMilliseconds(50));
            if (match.Success) return match.Groups["run"].Value.ToLowerInvariant();
        }
        return null;
    }

    private static string? EmptyToNull(string? value) => string.IsNullOrWhiteSpace(value) || value == "-" ? null : value;

    private static string? SafeFileName(string? path)
    {
        path = EmptyToNull(path);
        if (path is null) return null;
        var separator = Math.Max(path.LastIndexOf('\\'), path.LastIndexOf('/'));
        return separator >= 0 && separator < path.Length - 1 ? path[(separator + 1)..] : path;
    }

    private static void AddIfPresent(IDictionary<string, string> destination, string key, string? value)
    {
        value = EmptyToNull(value);
        if (value is not null) destination[key] = value;
    }
}
