using System.Globalization;
using Microsoft.Extensions.Options;
using SentinelForge.Agent.Configuration;

namespace SentinelForge.Agent.Spool;

public sealed class FileCursorStore : ICursorStore
{
    private readonly string _path;

    public FileCursorStore(IOptions<AgentOptions> options) => _path = options.Value.ExpandedCursorPath;

    public async Task<long> LoadAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_path)) return 0;
        var value = await File.ReadAllTextAsync(_path, cancellationToken);
        return long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var cursor) && cursor >= 0
            ? cursor
            : throw new InvalidDataException("The event cursor file is invalid.");
    }

    public async Task SaveAsync(long recordId, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(recordId);
        var directory = Path.GetDirectoryName(_path) ?? throw new InvalidOperationException("Cursor path has no parent directory.");
        Directory.CreateDirectory(directory);
        var temporaryPath = _path + ".tmp";
        try
        {
            await File.WriteAllTextAsync(temporaryPath, recordId.ToString(CultureInfo.InvariantCulture), cancellationToken);
            File.Move(temporaryPath, _path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }
}
