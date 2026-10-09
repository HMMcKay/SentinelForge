using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using SentinelForge.Agent.Configuration;

namespace SentinelForge.Agent.Identity;

public sealed class PlatformIdentityProtector : IIdentityProtector
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("SentinelForge.SensorIdentity.v1");
    private static readonly byte[] TestHeader = Encoding.ASCII.GetBytes("SF-PLAINTEXT-TEST\0");
    private readonly bool _allowPlaintextTestFallback;

    public PlatformIdentityProtector(IOptions<AgentOptions> options)
    {
        _allowPlaintextTestFallback = options.Value.AllowPlaintextIdentityForTests;
    }

    public byte[] Protect(ReadOnlySpan<byte> plaintext)
    {
        if (OperatingSystem.IsWindows())
        {
            return ProtectedData.Protect(plaintext.ToArray(), Entropy, DataProtectionScope.CurrentUser);
        }

        EnsureTestFallbackAllowed();
        var result = new byte[TestHeader.Length + plaintext.Length];
        TestHeader.CopyTo(result, 0);
        plaintext.CopyTo(result.AsSpan(TestHeader.Length));
        return result;
    }

    public byte[] Unprotect(ReadOnlySpan<byte> protectedData)
    {
        if (OperatingSystem.IsWindows())
        {
            return ProtectedData.Unprotect(protectedData.ToArray(), Entropy, DataProtectionScope.CurrentUser);
        }

        EnsureTestFallbackAllowed();
        if (!protectedData.StartsWith(TestHeader))
        {
            throw new CryptographicException("The non-Windows test identity header is invalid.");
        }
        return protectedData[TestHeader.Length..].ToArray();
    }

    private void EnsureTestFallbackAllowed()
    {
        if (!_allowPlaintextTestFallback)
        {
            throw new PlatformNotSupportedException(
                "DPAPI is unavailable. Plaintext identity storage is disabled; enable AllowPlaintextIdentityForTests only in an isolated test environment.");
        }
    }
}
