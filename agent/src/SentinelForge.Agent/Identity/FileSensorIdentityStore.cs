using System.Text.Json;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using SentinelForge.Agent.Configuration;
using SentinelForge.Agent.Models;

namespace SentinelForge.Agent.Identity;

public sealed class FileSensorIdentityStore : ISensorIdentityStore
{
    private readonly string _path;
    private readonly IIdentityProtector _protector;

    public FileSensorIdentityStore(IOptions<AgentOptions> options, IIdentityProtector protector)
    {
        _path = options.Value.ExpandedIdentityPath;
        _protector = protector;
    }

    public async Task<SensorIdentity?> LoadAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_path)) return null;
        var protectedData = await File.ReadAllBytesAsync(_path, cancellationToken);
        var plaintext = _protector.Unprotect(protectedData);
        try
        {
            var identity = JsonSerializer.Deserialize<SensorIdentity>(plaintext, JsonDefaults.Options);
            if (identity is null || string.IsNullOrWhiteSpace(identity.SensorId) || string.IsNullOrWhiteSpace(identity.IngestionToken))
            {
                throw new InvalidDataException("The sensor identity file is incomplete.");
            }
            return identity;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public async Task SaveAsync(SensorIdentity identity, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identity.SensorId);
        ArgumentException.ThrowIfNullOrWhiteSpace(identity.IngestionToken);
        var directory = Path.GetDirectoryName(_path) ?? throw new InvalidOperationException("Identity path has no parent directory.");
        Directory.CreateDirectory(directory);
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(identity, JsonDefaults.Options);
        try
        {
            var protectedData = _protector.Protect(plaintext);
            var temporaryPath = _path + ".tmp-" + Guid.NewGuid().ToString("N");
            try
            {
                await File.WriteAllBytesAsync(temporaryPath, protectedData, cancellationToken);
                if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(temporaryPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                File.Move(temporaryPath, _path, overwrite: true);
            }
            finally
            {
                if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }
}
