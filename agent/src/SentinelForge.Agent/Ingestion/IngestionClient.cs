using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Extensions.Options;
using SentinelForge.Agent.Configuration;
using SentinelForge.Agent.Models;
using SentinelForge.Agent.Runtime;

namespace SentinelForge.Agent.Ingestion;

public sealed class IngestionClient : IIngestionClient
{
    private static readonly Version AgentVersion = typeof(IngestionClient).Assembly.GetName().Version ?? new Version(0, 0);
    private readonly HttpClient _httpClient;
    private readonly AgentOptions _options;
    private readonly ILogger<IngestionClient> _logger;

    public IngestionClient(HttpClient httpClient, IOptions<AgentOptions> options, ILogger<IngestionClient> logger)
    {
        _httpClient = httpClient;
        _options = options.Value;
        _logger = logger;
        _httpClient.BaseAddress = new Uri(_options.BaseUrl, UriKind.Absolute);
        _httpClient.Timeout = TimeSpan.FromSeconds(_options.RequestTimeoutSeconds);
        _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd($"SentinelForge-Agent/{AgentVersion}");
    }

    public async Task<SensorIdentity> EnrollAsync(CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(_options.EnrollmentToken))
        {
            throw new InvalidOperationException("No persisted sensor identity exists and Agent:EnrollmentToken is not configured.");
        }

        var requestBody = new EnrollmentRequest(
            string.IsNullOrWhiteSpace(_options.SensorName) ? Environment.MachineName : _options.SensorName,
            Environment.MachineName,
            Environment.MachineName,
            "Windows",
            RuntimeInformation.OSDescription,
            new Dictionary<string, string> { ["agent_version"] = AgentVersion.ToString(3) });

        using var response = await SendWithRetryAsync(() =>
        {
            var request = new HttpRequestMessage(HttpMethod.Post, _options.EnrollmentPath)
            {
                Content = JsonContent.Create(requestBody, options: JsonDefaults.Options)
            };
            request.Headers.Add("X-Enrollment-Key", _options.EnrollmentToken);
            return request;
        }, cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"Sensor enrollment failed with HTTP {(int)response.StatusCode}.", null, response.StatusCode);
        }

        var result = await response.Content.ReadFromJsonAsync<EnrollmentResponse>(JsonDefaults.Options, cancellationToken);
        if (result is null || !Guid.TryParseExact(result.SensorId, "D", out _) || string.IsNullOrWhiteSpace(result.IngestionToken))
        {
            throw new InvalidDataException("The enrollment response did not include a canonical sensor UUID and ingestion token.");
        }
        return new SensorIdentity(result.SensorId, result.IngestionToken);
    }

    public async Task<IngestionResult> SendBatchAsync(EventBatch batch, SensorIdentity identity, CancellationToken cancellationToken)
    {
        using var response = await SendWithRetryAsync(() => CreateAuthenticatedJsonRequest(
            HttpMethod.Post, _options.IngestionPath, batch, identity.IngestionToken), cancellationToken);
        return ToResult(response, acceptedConflict: true);
    }

    public async Task<IngestionResult> SendHeartbeatAsync(SensorHealthSnapshot health, SensorIdentity identity, CancellationToken cancellationToken)
    {
        var path = _options.HeartbeatPathTemplate.Replace(
            "{sensor_id}", Uri.EscapeDataString(identity.SensorId), StringComparison.Ordinal);
        using var response = await SendWithRetryAsync(() => CreateAuthenticatedJsonRequest(
            HttpMethod.Post, path, health, identity.IngestionToken), cancellationToken);
        return ToResult(response, acceptedConflict: false);
    }

    private async Task<HttpResponseMessage> SendWithRetryAsync(
        Func<HttpRequestMessage> requestFactory,
        CancellationToken cancellationToken)
    {
        Exception? lastException = null;
        for (var attempt = 1; attempt <= _options.MaxRetryAttempts; attempt++)
        {
            try
            {
                using var request = requestFactory();
                var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                if (!IsTransient(response.StatusCode) || attempt == _options.MaxRetryAttempts) return response;

                var delay = RetryDelay(attempt, response.Headers.RetryAfter);
                _logger.LogWarning("Request returned transient HTTP {StatusCode}; retrying in {DelayMs} ms (attempt {Attempt}/{MaxAttempts})",
                    (int)response.StatusCode, delay.TotalMilliseconds, attempt, _options.MaxRetryAttempts);
                response.Dispose();
                await Task.Delay(delay, cancellationToken);
            }
            catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
            {
                if (cancellationToken.IsCancellationRequested) throw;
                lastException = exception;
                if (attempt == _options.MaxRetryAttempts) throw;
                var delay = RetryDelay(attempt, retryAfter: null);
                _logger.LogWarning(exception, "Request failed transiently; retrying in {DelayMs} ms (attempt {Attempt}/{MaxAttempts})",
                    delay.TotalMilliseconds, attempt, _options.MaxRetryAttempts);
                await Task.Delay(delay, cancellationToken);
            }
        }

        throw new HttpRequestException("Request failed after bounded retries.", lastException);
    }

    private TimeSpan RetryDelay(int attempt, RetryConditionHeaderValue? retryAfter)
    {
        var cap = TimeSpan.FromSeconds(_options.RetryMaxDelaySeconds);
        if (retryAfter?.Delta is { } serverDelay) return serverDelay < cap ? serverDelay : cap;
        if (retryAfter?.Date is { } date)
        {
            var serverDelayFromDate = date - DateTimeOffset.UtcNow;
            if (serverDelayFromDate > TimeSpan.Zero) return serverDelayFromDate < cap ? serverDelayFromDate : cap;
        }

        var exponential = _options.RetryBaseDelayMilliseconds * Math.Pow(2, attempt - 1);
        var jitter = Random.Shared.NextDouble() * Math.Max(1, exponential * 0.25);
        return TimeSpan.FromMilliseconds(Math.Min(cap.TotalMilliseconds, exponential + jitter));
    }

    private static HttpRequestMessage CreateAuthenticatedJsonRequest<T>(HttpMethod method, string path, T body, string token)
    {
        var request = new HttpRequestMessage(method, path)
        {
            Content = JsonContent.Create(body, options: JsonDefaults.Options)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return request;
    }

    private static IngestionResult ToResult(HttpResponseMessage response, bool acceptedConflict)
    {
        var accepted = response.IsSuccessStatusCode || (acceptedConflict && response.StatusCode == HttpStatusCode.Conflict);
        var permanent = !accepted && !IsTransient(response.StatusCode);
        return new IngestionResult(accepted, permanent, (int)response.StatusCode, accepted ? null : $"HTTP {(int)response.StatusCode}");
    }

    private static bool IsTransient(HttpStatusCode statusCode) =>
        statusCode is HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests || (int)statusCode >= 500;

    private sealed record EnrollmentRequest(
        [property: System.Text.Json.Serialization.JsonPropertyName("name")] string Name,
        [property: System.Text.Json.Serialization.JsonPropertyName("host_identifier")] string HostIdentifier,
        [property: System.Text.Json.Serialization.JsonPropertyName("hostname")] string Hostname,
        [property: System.Text.Json.Serialization.JsonPropertyName("os_name")] string OsName,
        [property: System.Text.Json.Serialization.JsonPropertyName("os_version")] string OsVersion,
        [property: System.Text.Json.Serialization.JsonPropertyName("metadata")] IReadOnlyDictionary<string, string> Metadata);

    private sealed record EnrollmentResponse(
        [property: System.Text.Json.Serialization.JsonPropertyName("sensor_id")] string SensorId,
        [property: System.Text.Json.Serialization.JsonPropertyName("ingestion_token")] string IngestionToken,
        [property: System.Text.Json.Serialization.JsonPropertyName("token_type")] string? TokenType);
}
