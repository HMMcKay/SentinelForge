[CmdletBinding()]
param(
    [switch]$NoStart
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$envPath = Join-Path $repoRoot '.env'
$examplePath = Join-Path $repoRoot '.env.example'

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker is required. Install Docker Desktop or Docker Engine with Compose v2.'
}

if (-not (Test-Path $envPath)) {
    $bytes = New-Object byte[] 36
    [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $databaseSecret = [Convert]::ToBase64String($bytes).Replace('/', '_').Replace('+', '-').TrimEnd('=')
    [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $enrollmentSecret = [Convert]::ToBase64String($bytes).Replace('/', '_').Replace('+', '-').TrimEnd('=')
    [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $adminSecret = [Convert]::ToBase64String($bytes).Replace('/', '_').Replace('+', '-').TrimEnd('=')
    [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $tokenPepper = [Convert]::ToBase64String($bytes).Replace('/', '_').Replace('+', '-').TrimEnd('=')

    $content = Get-Content -Raw $examplePath
    $content = $content.Replace('change-this-local-password', $databaseSecret)
    $content = $content.Replace('change-this-enrollment-secret-at-least-32-chars', $enrollmentSecret)
    $content = $content.Replace('change-this-admin-secret-at-least-32-chars', $adminSecret)
    $content = $content.Replace('change-this-token-pepper-at-least-32-chars', $tokenPepper)
    [IO.File]::WriteAllText($envPath, $content, [Text.UTF8Encoding]::new($false))
    Write-Host 'Created .env with generated local secrets.'
}

if ((Get-Content -Raw $envPath) -match '(?m)=change-this-') {
    throw '.env still contains example credentials. Replace every change-this-* value or remove .env and rerun bootstrap.'
}

Push-Location $repoRoot
try {
    docker compose config --quiet
    if (-not $NoStart) {
        docker compose up --build -d
        docker compose ps
    }
}
finally {
    Pop-Location
}
