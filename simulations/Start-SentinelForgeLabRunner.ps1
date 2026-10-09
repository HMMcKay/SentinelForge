[CmdletBinding()]
param(
    [string] $BaseUrl = 'http://127.0.0.1:8000',
    [string] $SensorToken = $env:SENTINELFORGE_SENSOR_TOKEN,
    [string] $SandboxRoot = ([IO.Path]::Combine([IO.Path]::GetTempPath(), 'SentinelForgeLab')),
    [ValidateRange(1, 300)][int] $PollIntervalSeconds = 3,
    [switch] $Once,
    [switch] $AllowInsecureHttp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:SENTINELFORGE_LAB_MODE -cne '1') {
    throw 'Lab runner blocked: set SENTINELFORGE_LAB_MODE=1 only inside an isolated lab.'
}
if ([string]::IsNullOrWhiteSpace($SensorToken)) {
    throw 'SensorToken is required (or set SENTINELFORGE_SENSOR_TOKEN).'
}
$baseUri = [Uri]($BaseUrl.TrimEnd('/') + '/')
if ($baseUri.Scheme -notin @('http', 'https')) { throw 'BaseUrl must use HTTP or HTTPS.' }
if ($baseUri.Scheme -eq 'http' -and -not $baseUri.IsLoopback -and -not $AllowInsecureHttp) {
    throw 'Remote plain HTTP is blocked. Use HTTPS or explicitly pass -AllowInsecureHttp inside the isolated lab.'
}

Import-Module (Join-Path $PSScriptRoot 'SentinelForge.Simulations.psd1') -Force
$allowedIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($scenario in @(Get-SentinelForgeScenario)) { $null = $allowedIds.Add([string]$scenario.id) }
$headers = @{
    Authorization = "Bearer $SensorToken"
    'User-Agent' = 'SentinelForge-LabRunner/1.0'
}

function Get-ApiUri {
    param([string] $RelativePath)
    [Uri]::new($baseUri, $RelativePath.TrimStart('/'))
}

function Send-RunStatus {
    param(
        [string] $RunId,
        [ValidateSet('running', 'completed', 'failed')][string] $Status,
        [Nullable[bool]] $CleanupVerified,
        [string] $ErrorSummary
    )
    $body = [ordered]@{ status = $Status }
    if ($null -ne $CleanupVerified) { $body.cleanup_verified = [bool]$CleanupVerified }
    if (-not [string]::IsNullOrWhiteSpace($ErrorSummary)) {
        $sanitized = $ErrorSummary -replace '[\x00-\x1F]', ' '
        $body.error_summary = $sanitized.Substring(0, [Math]::Min(1000, $sanitized.Length))
    }
    $escapedRunId = [Uri]::EscapeDataString($RunId)
    $null = Invoke-RestMethod -Method Post -Uri (Get-ApiUri "/api/v1/scenario-runs/$escapedRunId/status") `
        -Headers $headers -ContentType 'application/json' -Body ($body | ConvertTo-Json -Compress)
}

function Send-SyntheticControlEvent {
    param(
        [string] $SensorId,
        [string] $RunId,
        [pscustomobject] $Event
    )
    $uuidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'
    if ($SensorId -notmatch $uuidPattern -or $RunId -notmatch $uuidPattern) {
        throw 'Synthetic control ingestion requires backend-issued sensor and run UUIDs.'
    }
    if ($null -eq $Event -or $Event.event_type -cne 'security_control' -or
        $Event.source.provider -cne 'SentinelForge-Synthetic' -or $Event.scenario_run_id -cne $RunId -or
        $Event.metadata.synthetic -ne $true -or $Event.metadata.action -cne 'disable' -or
        $Event.metadata.operating_system_modified -ne $false -or 'T1685' -notin @($Event.attack_tags)) {
        throw 'Refusing to upload a synthetic event that does not match the fixed security-control contract.'
    }
    $batch = [ordered]@{
        sensor_id = $SensorId
        schema_version = '1.0'
        batch_id = [Guid]::NewGuid().ToString('D')
        events = @($Event)
    }
    $null = Invoke-RestMethod -Method Post -Uri (Get-ApiUri '/api/v1/events/batch') -Headers $headers `
        -ContentType 'application/json' -Body ($batch | ConvertTo-Json -Depth 20 -Compress)
}

do {
    $pending = Invoke-RestMethod -Method Get -Uri (Get-ApiUri '/api/v1/scenario-runs/pending') -Headers $headers
    $run = $pending.run
    if ($null -eq $run) {
        if (-not $Once) { Start-Sleep -Seconds $PollIntervalSeconds }
        continue
    }

    $runId = [string]$run.run_id
    $scenarioId = [string]$run.scenario_id
    if ($runId -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$') {
        throw 'Backend returned an invalid run ID; no scenario was executed.'
    }
    if (-not $allowedIds.Contains($scenarioId)) {
        Send-RunStatus -RunId $runId -Status failed -CleanupVerified $true -ErrorSummary "Scenario ID is not in the local allowlist: $scenarioId"
        if (-not $Once) { Start-Sleep -Seconds $PollIntervalSeconds }
        continue
    }

    $claimed = $false
    try {
        Send-RunStatus -RunId $runId -Status running
        $claimed = $true
    }
    catch {
        $statusCode = $null
        if ($null -ne $_.Exception.Response) {
            try { $statusCode = [int]$_.Exception.Response.StatusCode } catch { $statusCode = $null }
        }
        if ($statusCode -eq 409) {
            Write-Verbose "Run $runId was claimed by another runner; skipping without changing its status."
        }
        else {
            Write-Warning "Could not claim run $runId; it was not executed or marked failed."
        }
    }
    if (-not $claimed) {
        if (-not $Once) { Start-Sleep -Seconds $PollIntervalSeconds }
        continue
    }

    try {
        if ([bool]$run.dry_run) {
            $null = Invoke-SentinelForgeScenario -ScenarioId $scenarioId -RunId $runId -SandboxRoot $SandboxRoot -DryRun
            $cleanupVerified = $true
        }
        else {
            $result = Invoke-SentinelForgeScenario -ScenarioId $scenarioId -RunId $runId -SandboxRoot $SandboxRoot -CleanupAfterRun
            $cleanupVerified = [bool]$result.cleanup_verified
            if ($scenarioId -ceq 'security-control-events') {
                Send-SyntheticControlEvent -SensorId ([string]$run.sensor_id) -RunId $runId -Event $result.synthetic_event
            }
        }
        if (-not $cleanupVerified) { throw 'Scenario completed but cleanup verification did not pass.' }
        Send-RunStatus -RunId $runId -Status completed -CleanupVerified $true
    }
    catch {
        $expectedRunDirectory = Join-Path (Join-Path ([IO.Path]::GetFullPath($SandboxRoot)) 'runs') $runId
        $cleanupVerified = -not (Test-Path -LiteralPath $expectedRunDirectory)
        try {
            Send-RunStatus -RunId $runId -Status failed -CleanupVerified $cleanupVerified -ErrorSummary $_.Exception.Message
        }
        catch {
            Write-Error 'Scenario failed and the backend status update also failed. Inspect the local run manifest before retrying.'
        }
    }
    if (-not $Once) { Start-Sleep -Seconds $PollIntervalSeconds }
} while (-not $Once)
