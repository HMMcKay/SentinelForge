using System.Text;
using Microsoft.Extensions.Options;
using SentinelForge.Agent.Configuration;
using SentinelForge.Agent.Identity;
using SentinelForge.Agent.Models;

namespace SentinelForge.Agent.Tests;

public sealed class IdentityStoreTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "sentinelforge-identity-tests", Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task IdentityStoreUsesProtectorAndRoundTripsWithoutPlaintextTokenOnDisk()
    {
        var path = Path.Combine(_directory, "identity.bin");
        var options = Options.Create(new AgentOptions
        {
            IdentityPath = path
        });
        var protector = new TestProtector();
        var store = new FileSensorIdentityStore(options, protector);
        var expected = new SensorIdentity("sensor-test", "token-that-must-not-appear-unwrapped");

        await store.SaveAsync(expected, CancellationToken.None);
        var actual = await store.LoadAsync(CancellationToken.None);
        var diskText = Encoding.UTF8.GetString(await File.ReadAllBytesAsync(path));

        Assert.Equal(expected, actual);
        Assert.DoesNotContain(expected.IngestionToken, diskText, StringComparison.Ordinal);
        Assert.True(protector.ProtectCalled);
        Assert.True(protector.UnprotectCalled);
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory)) Directory.Delete(_directory, recursive: true);
    }

    private sealed class TestProtector : IIdentityProtector
    {
        public bool ProtectCalled { get; private set; }
        public bool UnprotectCalled { get; private set; }

        public byte[] Protect(ReadOnlySpan<byte> plaintext)
        {
            ProtectCalled = true;
            return plaintext.ToArray().Select(value => (byte)(value ^ 0xA5)).ToArray();
        }

        public byte[] Unprotect(ReadOnlySpan<byte> protectedData)
        {
            UnprotectCalled = true;
            return protectedData.ToArray().Select(value => (byte)(value ^ 0xA5)).ToArray();
        }
    }
}
