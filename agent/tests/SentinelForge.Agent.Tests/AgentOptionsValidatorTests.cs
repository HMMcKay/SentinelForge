using SentinelForge.Agent.Configuration;

namespace SentinelForge.Agent.Tests;

public sealed class AgentOptionsValidatorTests
{
    [Fact]
    public void RejectsRemotePlainHttpByDefault()
    {
        var result = new AgentOptionsValidator().Validate(null, Valid() with { BaseUrl = "http://192.0.2.10:8000" });
        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, failure => failure.Contains("Plain HTTP", StringComparison.Ordinal));
    }

    [Fact]
    public void AcceptsLoopbackDevelopmentEndpoint()
    {
        var result = new AgentOptionsValidator().Validate(null, Valid());
        Assert.True(result.Succeeded);
    }

    [Fact]
    public void RejectsPartialStaticIdentity()
    {
        var result = new AgentOptionsValidator().Validate(null, Valid() with { SensorId = "sensor-only" });
        Assert.True(result.Failed);
    }

    private static AgentOptions Valid() => new()
    {
        BaseUrl = "http://127.0.0.1:8000",
        SpoolDirectory = Path.Combine(Path.GetTempPath(), "sf", "spool"),
        IdentityPath = Path.Combine(Path.GetTempPath(), "sf", "identity.bin"),
        CursorPath = Path.Combine(Path.GetTempPath(), "sf", "cursor.txt"),
        HealthPath = Path.Combine(Path.GetTempPath(), "sf", "health.json")
    };
}
