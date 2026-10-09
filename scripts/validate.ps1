[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

function Assert-NativeSuccess {
    param([Parameter(Mandatory)][int] $ExitCode, [Parameter(Mandatory)][string] $Step)
    if ($ExitCode -ne 0) { throw "$Step failed with exit code $ExitCode." }
}

Push-Location $repoRoot
try {
    if (-not (Test-Path '.env')) {
        Write-Warning 'No .env found; run scripts/bootstrap.ps1 first. Compose validation will use explicit non-production validation values.'
        $env:POSTGRES_PASSWORD = 'validation-only-password'
        $env:SENTINELFORGE_ENROLLMENT_KEY = 'validation-only-secret-at-least-32-characters'
        $env:SENTINELFORGE_ADMIN_KEY = 'validation-admin-secret-at-least-32-characters'
        $env:SENTINELFORGE_TOKEN_PEPPER = 'validation-token-pepper-at-least-32-characters'
    }

    docker compose config --quiet
    Assert-NativeSuccess -ExitCode $LASTEXITCODE -Step 'Compose configuration validation'
    docker compose -f compose.test.yaml build
    Assert-NativeSuccess -ExitCode $LASTEXITCODE -Step 'Test image build'
    docker compose -f compose.test.yaml run --rm backend-tests ruff check .
    Assert-NativeSuccess -ExitCode $LASTEXITCODE -Step 'Backend lint'
    docker compose -f compose.test.yaml run --rm backend-tests pytest -q
    Assert-NativeSuccess -ExitCode $LASTEXITCODE -Step 'Backend tests'
    docker compose -f compose.test.yaml run --rm frontend-tests npm run lint
    Assert-NativeSuccess -ExitCode $LASTEXITCODE -Step 'Frontend lint'
    docker compose -f compose.test.yaml run --rm frontend-tests npm test
    Assert-NativeSuccess -ExitCode $LASTEXITCODE -Step 'Frontend tests'
    docker compose -f compose.test.yaml run --rm frontend-tests npm run build
    Assert-NativeSuccess -ExitCode $LASTEXITCODE -Step 'Frontend build'
    docker compose -f compose.test.yaml run --rm cli-tests ruff check .
    Assert-NativeSuccess -ExitCode $LASTEXITCODE -Step 'CLI lint'
    docker compose -f compose.test.yaml run --rm cli-tests pytest -q
    Assert-NativeSuccess -ExitCode $LASTEXITCODE -Step 'CLI tests'
    dotnet restore agent/SentinelForge.Agent.sln --locked-mode --configfile agent/NuGet.Config
    Assert-NativeSuccess -ExitCode $LASTEXITCODE -Step 'Locked sensor restore'
    dotnet test agent/SentinelForge.Agent.sln --configuration Release --no-restore
    Assert-NativeSuccess -ExitCode $LASTEXITCODE -Step 'Sensor tests'
    pwsh -NoProfile -File simulations/tests/Run-SafetyTests.ps1
    Assert-NativeSuccess -ExitCode $LASTEXITCODE -Step 'Simulation safety tests'
}
finally {
    Pop-Location
}
