[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $MarkerPath
)

Set-StrictMode -Version Latest
$resolvedParent = [IO.Path]::GetFullPath((Split-Path -Parent $MarkerPath))
if (-not (Test-Path -LiteralPath $resolvedParent -PathType Container)) {
    throw 'The marker parent directory does not exist.'
}

$process = Start-Process -FilePath $env:ComSpec -ArgumentList @('/d', '/c', 'exit 0') -NoNewWindow -Wait -PassThru
if ($process.ExitCode -ne 0) { throw "The fixed benign cmd.exe child exited with $($process.ExitCode)." }
[IO.File]::WriteAllText($MarkerPath, 'SentinelForge benign process chain')
