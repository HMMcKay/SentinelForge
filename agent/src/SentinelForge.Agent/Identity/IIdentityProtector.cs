namespace SentinelForge.Agent.Identity;

public interface IIdentityProtector
{
    byte[] Protect(ReadOnlySpan<byte> plaintext);
    byte[] Unprotect(ReadOnlySpan<byte> protectedData);
}
