[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$modulePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'SentinelForge.Simulations.psd1'
Import-Module $modulePath -Force
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ("SentinelForgeSafetyTests-{0}" -f [Guid]::NewGuid().ToString('N'))
$previousLabMode = $env:SENTINELFORGE_LAB_MODE
$passed = 0

function Assert-True {
    param([bool] $Condition, [string] $Message)
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
    $script:passed++
}

function Assert-Throws {
    param([scriptblock] $Action, [string] $MessagePattern)
    $threw = $false
    try { & $Action }
    catch {
        $threw = $true
        if ($_.Exception.Message -notmatch $MessagePattern) {
            throw "Expected error matching '$MessagePattern', received '$($_.Exception.Message)'."
        }
    }
    if (-not $threw) { throw "Expected action to throw matching '$MessagePattern'." }
    $script:passed++
}

try {
    $null = New-Item -ItemType Directory -Path $testRoot -Force
    $child = Join-Path $testRoot 'runs\child'
    $sibling = $testRoot + '-sibling\child'
    Assert-True (Test-SentinelForgeContainedPath -Root $testRoot -Candidate $child) 'A child path should pass containment.'
    Assert-True (-not (Test-SentinelForgeContainedPath -Root $testRoot -Candidate $testRoot)) 'The root itself should not pass containment by default.'
    Assert-True (-not (Test-SentinelForgeContainedPath -Root $testRoot -Candidate $sibling)) 'A same-prefix sibling must not pass containment.'

    $catalog = @(Get-SentinelForgeScenario)
    Assert-True ($catalog.Count -eq 8) 'The catalog should expose exactly eight vetted scenarios.'
    Assert-True ((@($catalog.id | Sort-Object -Unique)).Count -eq $catalog.Count) 'Scenario IDs must be unique.'

    $env:SENTINELFORGE_LAB_MODE = $null
    Assert-Throws { Invoke-SentinelForgeScenario -ScenarioId 'dns-localhost' -DryRun -SandboxRoot $testRoot } 'LAB_MODE=1'

    $env:SENTINELFORGE_LAB_MODE = '1'
    Assert-Throws { Invoke-SentinelForgeScenario -ScenarioId 'not-allowlisted' -DryRun -SandboxRoot $testRoot } 'not in the local allowlist'
    foreach ($scenario in $catalog) {
        $dryRunId = 'dry-' + ($scenario.id -replace '[^A-Za-z0-9_-]', '-')
        $preview = Invoke-SentinelForgeScenario -ScenarioId $scenario.id -RunId $dryRunId -DryRun -SandboxRoot $testRoot
        Assert-True ($preview.dry_run -and $preview.lab_mode_verified) "Dry-run should succeed for $($scenario.id)."
        Assert-True (-not (Test-Path -LiteralPath $preview.would_create)) "Dry-run must not create a run directory for $($scenario.id)."
    }

    $canary = Join-Path $testRoot 'outside-canary.txt'
    [IO.File]::WriteAllText($canary, 'must remain unchanged')
    foreach ($scenarioId in @('dns-localhost', 'ransomware-emulator', 'security-control-events')) {
        $runId = 'actual-' + $scenarioId
        $result = Invoke-SentinelForgeScenario -ScenarioId $scenarioId -RunId $runId -SandboxRoot $testRoot -CleanupAfterRun
        Assert-True $result.cleanup_verified "Cleanup should verify for $scenarioId."
        Assert-True (-not (Test-Path -LiteralPath $result.run_directory)) "Run directory should be gone for $scenarioId."
        Assert-True ((Get-Content -LiteralPath $canary -Raw) -eq 'must remain unchanged') "Outside canary changed during $scenarioId."
        if ($scenarioId -ceq 'security-control-events') {
            Assert-True ($result.synthetic_event.event_type -ceq 'security_control') 'Cleanup result should carry the fixed synthetic control event.'
            Assert-True ($result.synthetic_event.metadata.synthetic -eq $true) 'Synthetic control metadata must use a boolean true marker.'
            Assert-True ($result.synthetic_event.metadata.action -ceq 'disable') 'Synthetic control metadata must match the fixed disable action.'
            Assert-True ('T1685' -in @($result.synthetic_event.attack_tags)) 'Synthetic control event must carry T1685.'
        }
    }

    $labeledResult = Invoke-SentinelForgeScenario -ScenarioId 'security-control-events' -RunId 'human-readable-run' -SandboxRoot $testRoot
    $labeledEvent = Get-Content -LiteralPath (Join-Path $labeledResult.run_directory 'synthetic-security-control-event.json') -Raw | ConvertFrom-Json
    Assert-True (-not ($labeledEvent.PSObject.Properties.Name -contains 'scenario_run_id')) 'A non-UUID local RunId must not be emitted into the normalized scenario_run_id field.'
    $null = Undo-SentinelForgeScenario -ManifestPath $labeledResult.manifest_path -PassThru

    $uuidRunId = [Guid]::NewGuid().ToString('D')
    $uuidResult = Invoke-SentinelForgeScenario -ScenarioId 'security-control-events' -RunId $uuidRunId -SandboxRoot $testRoot
    $uuidEvent = Get-Content -LiteralPath (Join-Path $uuidResult.run_directory 'synthetic-security-control-event.json') -Raw | ConvertFrom-Json
    Assert-True ($uuidEvent.scenario_run_id -ceq $uuidRunId) 'A backend-compatible UUID RunId should be emitted as scenario_run_id.'
    $null = Undo-SentinelForgeScenario -ManifestPath $uuidResult.manifest_path -PassThru

    if ($IsWindows) {
        # Registry and Task Scheduler integration require host policy access and are covered by
        # dry-run/allowlist tests here; execute them manually in the disposable lab VM.
        foreach ($scenarioId in @('benign-process-chain', 'encoded-powershell', 'user-writable-execution')) {
            $runId = 'windows-' + $scenarioId
            $result = Invoke-SentinelForgeScenario -ScenarioId $scenarioId -RunId $runId -SandboxRoot $testRoot -CleanupAfterRun
            Assert-True $result.cleanup_verified "Cleanup should verify for $scenarioId."
            Assert-True (-not (Test-Path -LiteralPath $result.run_directory)) "Run directory should be gone for $scenarioId."
        }
    }

    $tamperRun = Join-Path $testRoot 'runs\tamper'
    $null = New-Item -ItemType Directory -Path $tamperRun -Force
    $tamperManifest = Join-Path $tamperRun 'cleanup-manifest.json'
    @{
        schema_version = '1.0'; scenario_id = 'security-control-events'; run_id = 'tamper'
        sandbox_root = $testRoot; run_directory = $tamperRun; status = 'completed'
        actions = @(@{ type = 'delete_directory'; path = $testRoot })
    } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $tamperManifest -Encoding utf8NoBOM
    Assert-Throws { Undo-SentinelForgeScenario -ManifestPath $tamperManifest -PassThru } 'exact run directory'
    Assert-True (Test-Path -LiteralPath $canary) 'A tampered manifest must not delete the outside canary.'

    "Simulation safety tests passed: $passed assertions."
}
finally {
    $env:SENTINELFORGE_LAB_MODE = $previousLabMode
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
