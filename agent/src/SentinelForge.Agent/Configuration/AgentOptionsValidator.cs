using Microsoft.Extensions.Options;

namespace SentinelForge.Agent.Configuration;

public sealed class AgentOptionsValidator : IValidateOptions<AgentOptions>
{
    public ValidateOptionsResult Validate(string? name, AgentOptions options)
    {
        var errors = new List<string>();
        if (!Uri.TryCreate(options.BaseUrl, UriKind.Absolute, out var baseUri) ||
            (baseUri.Scheme != Uri.UriSchemeHttp && baseUri.Scheme != Uri.UriSchemeHttps))
        {
            errors.Add("Agent:BaseUrl must be an absolute HTTP(S) URL.");
        }
        else if (baseUri.Scheme == Uri.UriSchemeHttp && !IsLoopback(baseUri) && !options.AllowInsecureHttp)
        {
            errors.Add("Plain HTTP is allowed only for loopback unless Agent:AllowInsecureHttp is explicitly enabled.");
        }

        ValidateRelativeApiPath(options.EnrollmentPath, "EnrollmentPath", errors);
        ValidateRelativeApiPath(options.IngestionPath, "IngestionPath", errors);
        ValidateRelativeApiPath(options.HeartbeatPathTemplate.Replace("{sensor_id}", "sensor", StringComparison.Ordinal), "HeartbeatPathTemplate", errors);

        if (options.BatchSize is < 1 or > 500) errors.Add("Agent:BatchSize must be between 1 and 500.");
        if (options.PollIntervalSeconds is < 1 or > 300) errors.Add("Agent:PollIntervalSeconds must be between 1 and 300.");
        if (options.HeartbeatIntervalSeconds is < 5 or > 3600) errors.Add("Agent:HeartbeatIntervalSeconds must be between 5 and 3600.");
        if (options.RequestTimeoutSeconds is < 1 or > 120) errors.Add("Agent:RequestTimeoutSeconds must be between 1 and 120.");
        if (options.MaxRetryAttempts is < 1 or > 10) errors.Add("Agent:MaxRetryAttempts must be between 1 and 10.");
        if (options.RetryBaseDelayMilliseconds is < 10 or > 60_000) errors.Add("Agent:RetryBaseDelayMilliseconds must be between 10 and 60000.");
        if (options.RetryMaxDelaySeconds is < 1 or > 300) errors.Add("Agent:RetryMaxDelaySeconds must be between 1 and 300.");
        if (options.SpoolMaxBytes is < 1_048_576 or > 10_737_418_240) errors.Add("Agent:SpoolMaxBytes must be between 1 MiB and 10 GiB.");
        if (!options.EventSource.Equals("sysmon", StringComparison.OrdinalIgnoreCase) &&
            !options.EventSource.Equals("idle", StringComparison.OrdinalIgnoreCase))
        {
            errors.Add("Agent:EventSource must be 'sysmon' or 'idle'.");
        }

        ValidatePath(options.SpoolDirectory, "SpoolDirectory", errors);
        ValidatePath(options.IdentityPath, "IdentityPath", errors);
        ValidatePath(options.CursorPath, "CursorPath", errors);
        ValidatePath(options.HealthPath, "HealthPath", errors);

        var hasSensorId = !string.IsNullOrWhiteSpace(options.SensorId);
        var hasIngestionToken = !string.IsNullOrWhiteSpace(options.IngestionToken);
        if (hasSensorId != hasIngestionToken)
        {
            errors.Add("Agent:SensorId and Agent:IngestionToken must be configured together.");
        }
        if (hasSensorId && !Guid.TryParseExact(options.SensorId, "D", out _))
        {
            errors.Add("Agent:SensorId must be a canonical UUID.");
        }

        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }

    private static bool IsLoopback(Uri uri) =>
        uri.IsLoopback || uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase);

    private static void ValidateRelativeApiPath(string value, string field, ICollection<string> errors)
    {
        if (string.IsNullOrWhiteSpace(value) || !value.StartsWith("/", StringComparison.Ordinal) ||
            value.StartsWith("//", StringComparison.Ordinal) || Uri.TryCreate(value, UriKind.Absolute, out _))
        {
            errors.Add($"Agent:{field} must be a root-relative API path.");
        }
    }

    private static void ValidatePath(string value, string field, ICollection<string> errors)
    {
        try
        {
            var expanded = Path.GetFullPath(Environment.ExpandEnvironmentVariables(value));
            if (string.IsNullOrWhiteSpace(Path.GetFileName(expanded)) && field != "SpoolDirectory")
            {
                errors.Add($"Agent:{field} must identify a file.");
            }
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            errors.Add($"Agent:{field} is invalid.");
        }
    }
}
