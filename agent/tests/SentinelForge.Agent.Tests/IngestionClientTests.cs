using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SentinelForge.Agent.Configuration;
using SentinelForge.Agent.Ingestion;
using SentinelForge.Agent.Models;

namespace SentinelForge.Agent.Tests;

public sealed class IngestionClientTests
{
    [Fact]
    public async Task RetriesTransientResponseAndSendsBearerToken()
    {
        var handler = new RecordingHandler(
            new HttpResponseMessage(HttpStatusCode.ServiceUnavailable),
            new HttpResponseMessage(HttpStatusCode.Accepted));
        var client = CreateClient(handler);

        var result = await client.SendBatchAsync(Batch(), new SensorIdentity("sensor-1", "secret-token"), CancellationToken.None);

        Assert.True(result.Accepted);
        Assert.Equal(2, handler.RequestCount);
        Assert.All(handler.Authorization, value => Assert.Equal("Bearer secret-token", value));
        Assert.All(handler.Paths, value => Assert.Equal("/api/v1/events/batch", value));
    }

    [Fact]
    public async Task DoesNotRetryPermanentClientError()
    {
        var handler = new RecordingHandler(new HttpResponseMessage(HttpStatusCode.UnprocessableEntity));
        var client = CreateClient(handler);

        var result = await client.SendBatchAsync(Batch(), new SensorIdentity("sensor-1", "secret-token"), CancellationToken.None);

        Assert.False(result.Accepted);
        Assert.True(result.PermanentFailure);
        Assert.Equal(1, handler.RequestCount);
    }

    [Fact]
    public async Task EnrollmentUsesDedicatedHeaderAndCanonicalBody()
    {
        var response = new HttpResponseMessage(HttpStatusCode.Created)
        {
            Content = new StringContent("{\"sensor_id\":\"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\",\"ingestion_token\":\"issued-token\",\"token_type\":\"bearer\"}", Encoding.UTF8, "application/json")
        };
        var handler = new RecordingHandler(response);
        var client = CreateClient(handler, new AgentOptions
        {
            BaseUrl = "http://127.0.0.1:8000",
            EnrollmentToken = "enrollment-secret",
            RetryBaseDelayMilliseconds = 1,
            RetryMaxDelaySeconds = 1
        });

        var identity = await client.EnrollAsync(CancellationToken.None);

        Assert.Equal("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", identity.SensorId);
        Assert.Equal("issued-token", identity.IngestionToken);
        Assert.Equal("enrollment-secret", handler.EnrollmentKeys.Single());
        Assert.Contains("\"host_identifier\"", handler.Bodies.Single(), StringComparison.Ordinal);
        Assert.DoesNotContain("enrollment-secret", handler.Bodies.Single(), StringComparison.Ordinal);
    }

    private static IngestionClient CreateClient(RecordingHandler handler, AgentOptions? options = null) => new(
        new HttpClient(handler),
        Options.Create(options ?? new AgentOptions
        {
            BaseUrl = "http://127.0.0.1:8000",
            MaxRetryAttempts = 3,
            RetryBaseDelayMilliseconds = 1,
            RetryMaxDelaySeconds = 1
        }),
        NullLogger<IngestionClient>.Instance);

    private static EventBatch Batch() => new()
    {
        SensorId = "sensor-1",
        BatchId = "batch-1",
        Events = Array.Empty<NormalizedEvent>()
    };

    private sealed class RecordingHandler : HttpMessageHandler
    {
        private readonly Queue<HttpResponseMessage> _responses;
        public int RequestCount { get; private set; }
        public List<string?> Authorization { get; } = new();
        public List<string?> EnrollmentKeys { get; } = new();
        public List<string> Paths { get; } = new();
        public List<string> Bodies { get; } = new();

        public RecordingHandler(params HttpResponseMessage[] responses) => _responses = new Queue<HttpResponseMessage>(responses);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestCount++;
            Authorization.Add(request.Headers.Authorization?.ToString());
            EnrollmentKeys.Add(request.Headers.TryGetValues("X-Enrollment-Key", out var values) ? values.Single() : null);
            Paths.Add(request.RequestUri?.AbsolutePath ?? string.Empty);
            Bodies.Add(request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken));
            return _responses.Dequeue();
        }
    }
}
