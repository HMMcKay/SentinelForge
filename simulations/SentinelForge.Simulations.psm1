Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ModuleRoot = $PSScriptRoot
$script:CatalogPath = Join-Path $PSScriptRoot 'catalog.json'
$script:ManifestName = 'cleanup-manifest.json'

function Assert-SentinelForgeLabMode {
    if ($env:SENTINELFORGE_LAB_MODE -cne '1') {
        throw 'Simulation blocked: set SENTINELFORGE_LAB_MODE=1 only inside an isolated lab.'
    }
}

function Get-SentinelForgeDefaultSandboxRoot {
    [IO.Path]::Combine([IO.Path]::GetTempPath(), 'SentinelForgeLab')
}

function Get-SentinelForgePathComparison {
    if ($IsWindows) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
}

function Assert-SentinelForgeNotReparsePoint {
    param([string] $Path)
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Reparse points and symbolic links are not accepted in the simulation sandbox: $Path"
        }
    }
}

function Resolve-SentinelForgeSandboxRoot {
    param([string] $SandboxRoot)
    if ([string]::IsNullOrWhiteSpace($SandboxRoot)) { $SandboxRoot = Get-SentinelForgeDefaultSandboxRoot }
    $full = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($SandboxRoot)).TrimEnd(
        [IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $volumeRoot = [IO.Path]::GetPathRoot($full).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    if ([string]::IsNullOrWhiteSpace($full) -or $full.Equals($volumeRoot, (Get-SentinelForgePathComparison))) {
        throw 'The sandbox root cannot be a filesystem volume root.'
    }
    if ($full.StartsWith('\\', [StringComparison]::Ordinal)) {
        throw 'UNC paths are not accepted as simulation sandbox roots.'
    }
    Assert-SentinelForgeNotReparsePoint $full
    $full
}

function Test-SentinelForgeContainedPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Root,
        [Parameter(Mandatory)][string] $Candidate,
        [switch] $AllowRoot
    )
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $candidateFull = [IO.Path]::GetFullPath($Candidate).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $comparison = Get-SentinelForgePathComparison
    if ($AllowRoot -and $candidateFull.Equals($rootFull, $comparison)) { return $true }
    $prefix = $rootFull + [IO.Path]::DirectorySeparatorChar
    $candidateFull.StartsWith($prefix, $comparison)
}

function Assert-SentinelForgeRunId {
    param([string] $RunId)
    if ($RunId -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$') {
        throw 'RunId must contain 1-64 ASCII letters, digits, underscores, or hyphens and begin with a letter or digit.'
    }
}

function Get-SentinelForgeScenario {
    [CmdletBinding()]
    param([string] $Id)
    $catalog = Get-Content -LiteralPath $script:CatalogPath -Raw | ConvertFrom-Json -Depth 20
    if ($catalog.schema_version -ne '1.0') { throw 'Unsupported scenario catalog version.' }
    $scenarios = @($catalog.scenarios)
    if ([string]::IsNullOrWhiteSpace($Id)) { return $scenarios }
    $match = @($scenarios | Where-Object id -CEQ $Id)
    if ($match.Count -ne 1) { throw "Scenario '$Id' is not in the local allowlist." }
    $match[0]
}

function Save-SentinelForgeManifest {
    param([pscustomobject] $Manifest)
    $path = Join-Path $Manifest.run_directory $script:ManifestName
    $temporary = $path + '.tmp'
    $Manifest | Add-Member -NotePropertyName updated_at -NotePropertyValue ([DateTimeOffset]::UtcNow.ToString('o')) -Force
    $Manifest | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $temporary -Encoding utf8NoBOM
    Move-Item -LiteralPath $temporary -Destination $path -Force
}

function Add-SentinelForgeCleanupAction {
    param([pscustomobject] $Manifest, [hashtable] $Action)
    $Manifest.actions = @($Manifest.actions) + [pscustomobject]$Action
    Save-SentinelForgeManifest $Manifest
}

function New-SentinelForgeRunContext {
    param([pscustomobject] $Scenario, [string] $RunId, [string] $SandboxRoot)
    Assert-SentinelForgeRunId $RunId
    $root = Resolve-SentinelForgeSandboxRoot $SandboxRoot
    $runsRoot = Join-Path $root 'runs'
    Assert-SentinelForgeNotReparsePoint $runsRoot
    $runDirectory = Join-Path $runsRoot $RunId
    if (-not (Test-SentinelForgeContainedPath -Root $root -Candidate $runDirectory)) {
        throw 'Computed run directory escaped the sandbox root.'
    }
    if (Test-Path -LiteralPath $runDirectory) {
        throw "Run directory already exists: $runDirectory. Clean it explicitly before reusing a RunId."
    }
    $null = New-Item -ItemType Directory -Path $runDirectory -Force
    Assert-SentinelForgeNotReparsePoint $runDirectory
    $manifest = [pscustomobject]@{
        schema_version = '1.0'
        scenario_id = $Scenario.id
        run_id = $RunId
        sandbox_root = $root
        run_directory = $runDirectory
        created_at = [DateTimeOffset]::UtcNow.ToString('o')
        updated_at = [DateTimeOffset]::UtcNow.ToString('o')
        status = 'running'
        actions = @()
    }
    Save-SentinelForgeManifest $manifest
    Add-SentinelForgeCleanupAction -Manifest $manifest -Action @{ type = 'delete_directory'; path = $runDirectory }
    [pscustomobject]@{ Scenario = $Scenario; Root = $root; RunDirectory = $runDirectory; Manifest = $manifest }
}

function Assert-SentinelForgeWindowsScenario {
    param([pscustomobject] $Scenario)
    if ($Scenario.requires_windows -and -not $IsWindows) {
        throw "Scenario '$($Scenario.id)' requires Windows. Use -DryRun to inspect it on another platform."
    }
}

function Write-SentinelForgeEvidence {
    param([pscustomobject] $Context, [hashtable] $Evidence)
    $path = Join-Path $Context.RunDirectory 'evidence.json'
    $Evidence['scenario_id'] = $Context.Scenario.id
    $Evidence['run_id'] = $Context.Manifest.run_id
    $Evidence['recorded_at'] = [DateTimeOffset]::UtcNow.ToString('o')
    $Evidence | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $path -Encoding utf8NoBOM
    $path
}

function Invoke-RegistryRunKeyScenario {
    param([pscustomobject] $Context)
    $key = "Registry::HKEY_CURRENT_USER\Software\SentinelForgeLab\Runs\$($Context.Manifest.run_id)\Software\Microsoft\Windows\CurrentVersion\Run"
    $valueName = 'SentinelForgeBenign'
    $valueData = Join-Path $Context.RunDirectory 'benign-placeholder.exe'
    Add-SentinelForgeCleanupAction $Context.Manifest @{ type = 'registry_key'; path = "Registry::HKEY_CURRENT_USER\Software\SentinelForgeLab\Runs\$($Context.Manifest.run_id)" }
    $null = New-Item -Path $key -Force
    $null = New-ItemProperty -Path $key -Name $valueName -Value $valueData -PropertyType String -Force
    $actual = (Get-ItemProperty -Path $key -Name $valueName).$valueName
    if ($actual -ne $valueData) { throw 'Scoped Run-key value verification failed.' }
    Write-SentinelForgeEvidence $Context @{
        effect = 'scoped_registry_value'
        registry_path = $key
        value_name = $valueName
        real_autostart_key_touched = $false
    }
}

function Invoke-ScheduledTaskScenario {
    param([pscustomobject] $Context)
    if ([string]$Context.Manifest.run_id -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$') {
        throw 'The scheduled-task scenario requires a hyphenated UUID RunId so its task name is strictly scoped.'
    }
    $taskPath = '\SentinelForgeLab\'
    $taskName = "$($Context.Manifest.run_id)-Benign-NoOp"
    Add-SentinelForgeCleanupAction $Context.Manifest @{ type = 'scheduled_task'; task_path = $taskPath; task_name = $taskName }
    $taskXmlPath = Join-Path $Context.RunDirectory 'disabled-task.xml'
    $currentUser = [Security.SecurityElement]::Escape([Security.Principal.WindowsIdentity]::GetCurrent().Name)
    $command = [Security.SecurityElement]::Escape($env:ComSpec)
    $taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>SentinelForge disabled benign lab task</Description></RegistrationInfo>
  <Triggers><TimeTrigger><StartBoundary>2099-12-31T23:59:00</StartBoundary><Enabled>false</Enabled></TimeTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>$currentUser</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>false</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><IdleSettings><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><AllowStartOnDemand>false</AllowStartOnDemand><Enabled>false</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT1M</ExecutionTimeLimit><Priority>7</Priority></Settings>
  <Actions Context="Author"><Exec><Command>$command</Command><Arguments>/d /c exit 0</Arguments></Exec></Actions>
</Task>
"@
    Set-Content -LiteralPath $taskXmlPath -Value $taskXml -Encoding unicode
    if (-not (Test-SentinelForgeContainedPath -Root $Context.RunDirectory -Candidate $taskXmlPath)) {
        throw 'Generated task XML escaped the run directory.'
    }
    $taskFullName = "$taskPath$taskName"
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = Join-Path $env:SystemRoot 'System32\schtasks.exe'
    $start.UseShellExecute = $false
    $start.ArgumentList.Add('/Create')
    $start.ArgumentList.Add('/TN')
    $start.ArgumentList.Add($taskFullName)
    $start.ArgumentList.Add('/XML')
    $start.ArgumentList.Add($taskXmlPath)
    $start.ArgumentList.Add('/F')
    $creatorPid = Start-SentinelForgeFixedProcess $start
    $task = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName
    if ($task.State -ne 'Disabled') { throw 'The lab task was not registered in the required disabled state.' }
    Write-SentinelForgeEvidence $Context @{
        effect = 'disabled_scheduled_task'
        task_path = $taskPath
        task_name = $taskName
        enabled = $false
        creator = 'schtasks.exe /Create'
        creator_pid = $creatorPid
        task_xml = $taskXmlPath
        fixed_action = 'cmd.exe /d /c exit 0'
    }
}

function Start-SentinelForgeFixedProcess {
    param([Diagnostics.ProcessStartInfo] $StartInfo, [int] $TimeoutMilliseconds = 15000)
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $StartInfo
    if (-not $process.Start()) { throw 'The benign child process did not start.' }
    if (-not $process.WaitForExit($TimeoutMilliseconds)) {
        $process.Kill($true)
        throw 'The benign child process exceeded its bounded runtime and was terminated.'
    }
    if ($process.ExitCode -ne 0) { throw "The benign child process exited with code $($process.ExitCode)." }
    $process.Id
}

function Invoke-BenignProcessChainScenario {
    param([pscustomobject] $Context)
    $marker = Join-Path $Context.RunDirectory 'process-chain-marker.txt'
    $childScript = Join-Path $script:ModuleRoot 'assets/BenignProcessChild.ps1'
    $launcher = Join-Path $Context.RunDirectory 'launch-benign-chain.cmd'
    $launcherContent = @'
@echo off
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%SENTINELFORGE_CHILD_SCRIPT%" -MarkerPath "%SENTINELFORGE_MARKER_PATH%"
exit /b %ERRORLEVEL%
'@
    Set-Content -LiteralPath $launcher -Value $launcherContent -Encoding ascii
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $env:ComSpec
    $start.UseShellExecute = $false
    $start.Environment['SENTINELFORGE_CHILD_SCRIPT'] = $childScript
    $start.Environment['SENTINELFORGE_MARKER_PATH'] = $marker
    $start.ArgumentList.Add('/d')
    $start.ArgumentList.Add('/c')
    $start.ArgumentList.Add($launcher)
    $pid = Start-SentinelForgeFixedProcess $start
    if ((Get-Content -LiteralPath $marker -Raw) -ne 'SentinelForge benign process chain') {
        throw 'Process-chain marker verification failed.'
    }
    Write-SentinelForgeEvidence $Context @{
        effect = 'benign_process_chain'
        cmd_parent_pid = $pid
        child_image = 'powershell.exe'
        child_script = $childScript
        marker = $marker
    }
}

function Invoke-EncodedPowerShellScenario {
    param([pscustomobject] $Context)
    $marker = Join-Path $Context.RunDirectory 'encoded-powershell-marker.txt'
    $fixedCommand = "[IO.File]::WriteAllText(`$env:SENTINELFORGE_MARKER_PATH,'SentinelForge benign encoded payload')"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($fixedCommand))
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = (Join-Path $PSHOME 'pwsh.exe')
    $start.UseShellExecute = $false
    $start.Environment['SENTINELFORGE_MARKER_PATH'] = $marker
    $start.ArgumentList.Add('-NoLogo')
    $start.ArgumentList.Add('-NoProfile')
    $start.ArgumentList.Add('-NonInteractive')
    $start.ArgumentList.Add('-EncodedCommand')
    $start.ArgumentList.Add($encoded)
    $pid = Start-SentinelForgeFixedProcess $start
    if ((Get-Content -LiteralPath $marker -Raw) -ne 'SentinelForge benign encoded payload') {
        throw 'Encoded PowerShell marker verification failed.'
    }
    Write-SentinelForgeEvidence $Context @{ effect = 'benign_encoded_powershell'; child_pid = $pid; marker = $marker }
}

function Invoke-UserWritableExecutionScenario {
    param([pscustomobject] $Context)
    $copy = Join-Path $Context.RunDirectory 'sf-benign-cmd.exe'
    [IO.File]::Copy($env:ComSpec, $copy, $false)
    if (-not (Test-SentinelForgeContainedPath -Root $Context.RunDirectory -Candidate $copy)) {
        throw 'Executable copy escaped the run directory.'
    }
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $copy
    $start.UseShellExecute = $false
    $start.ArgumentList.Add('/d')
    $start.ArgumentList.Add('/c')
    $start.ArgumentList.Add('exit 0')
    $pid = Start-SentinelForgeFixedProcess $start
    Write-SentinelForgeEvidence $Context @{ effect = 'user_writable_execution'; child_pid = $pid; executable = $copy; fixed_arguments = '/d /c exit 0' }
}

function Invoke-DnsLocalhostScenario {
    param([pscustomobject] $Context)
    $addresses = [Net.Dns]::GetHostAddresses('localhost')
    if ($addresses.Count -lt 1) { throw 'localhost did not resolve.' }
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $client = $null
    $accepted = $null
    try {
        $listener.Start(1)
        $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
        $acceptTask = $listener.AcceptTcpClientAsync()
        $client = [Net.Sockets.TcpClient]::new()
        $client.ConnectAsync([Net.IPAddress]::Loopback, $port).GetAwaiter().GetResult()
        $accepted = $acceptTask.GetAwaiter().GetResult()
        $payload = [byte[]](0x53, 0x46)
        $client.GetStream().Write($payload, 0, $payload.Length)
        $received = [byte[]]::new(2)
        $count = $accepted.GetStream().Read($received, 0, 2)
        if ($count -ne 2 -or $received[0] -ne 0x53 -or $received[1] -ne 0x46) { throw 'Loopback payload verification failed.' }
        Write-SentinelForgeEvidence $Context @{
            effect = 'dns_and_loopback'
            dns_name = 'localhost'
            resolved_addresses = @($addresses | ForEach-Object ToString)
            destination_ip = '127.0.0.1'
            destination_port = $port
            external_network_used = $false
        }
    }
    finally {
        if ($null -ne $accepted) { $accepted.Dispose() }
        if ($null -ne $client) { $client.Dispose() }
        $listener.Stop()
    }
}

function Invoke-RansomwareSyntheticScenario {
    param([pscustomobject] $Context)
    $filesDirectory = Join-Path $Context.RunDirectory 'synthetic-files'
    $backupDirectory = Join-Path $Context.RunDirectory 'original-backup'
    $null = New-Item -ItemType Directory -Path $filesDirectory, $backupDirectory -Force
    $originalHashes = @{}
    $lockedPaths = @()
    foreach ($index in 1..12) {
        $path = Join-Path $filesDirectory ("sample-{0:D2}.txt" -f $index)
        $content = "SENTINELFORGE_SYNTHETIC_V1`nrun=$($Context.Manifest.run_id)`nindex=$index`nThis file was generated solely for a safe lab simulation.`n"
        [IO.File]::WriteAllText($path, $content, [Text.UTF8Encoding]::new($false))
        $originalHashes[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    }
    $restoreFiles = @($originalHashes.Keys | Sort-Object | ForEach-Object {
        @{
            original = $_
            backup = Join-Path $backupDirectory ([IO.Path]::GetFileName($_))
            locked = $_ + '.sf_locked'
            sha256 = $originalHashes[$_]
        }
    })
    Add-SentinelForgeCleanupAction $Context.Manifest @{
        type = 'restore_synthetic_files'
        files_directory = $filesDirectory
        backup_directory = $backupDirectory
        files = $restoreFiles
    }
    foreach ($path in @($originalHashes.Keys)) {
        if (-not (Test-SentinelForgeContainedPath -Root $filesDirectory -Candidate $path)) { throw 'Synthetic file escaped containment.' }
        $text = [IO.File]::ReadAllText($path)
        if (-not $text.StartsWith('SENTINELFORGE_SYNTHETIC_V1', [StringComparison]::Ordinal)) {
            throw 'Refusing to transform a file without the SentinelForge synthetic marker.'
        }
        $backup = Join-Path $backupDirectory ([IO.Path]::GetFileName($path))
        [IO.File]::Copy($path, $backup, $false)
        $bytes = [IO.File]::ReadAllBytes($path)
        for ($offset = 0; $offset -lt $bytes.Length; $offset++) { $bytes[$offset] = $bytes[$offset] -bxor 0x5A }
        [IO.File]::WriteAllBytes($path, $bytes)
        $locked = $path + '.sf_locked'
        [IO.File]::Move($path, $locked)
        $lockedPaths += $locked
    }
    foreach ($original in $originalHashes.Keys) {
        $backup = Join-Path $backupDirectory ([IO.Path]::GetFileName($original))
        if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $originalHashes[$original]) {
            throw 'Synthetic backup verification failed.'
        }
    }
    Write-SentinelForgeEvidence $Context @{
        effect = 'synthetic_file_transform_and_rename'
        generated_file_count = 12
        locked_paths = $lockedPaths
        originals_backed_up = $true
        outside_files_touched = $false
        transform = 'fixed XOR 0x5A (demonstration only)'
    }
}

function Invoke-SecurityControlSyntheticScenario {
    param([pscustomobject] $Context)
    $path = Join-Path $Context.RunDirectory 'synthetic-security-control-event.json'
    $event = [ordered]@{
        event_id = "synthetic-control-$($Context.Manifest.run_id)"
        event_time = [DateTimeOffset]::UtcNow.ToString('o')
        event_type = 'security_control'
        host = @{ hostname = [Environment]::MachineName; os_name = if ($IsWindows) { 'Windows' } else { 'non-Windows test host' } }
        source = @{ provider = 'SentinelForge-Synthetic'; event_code = 'CONTROL_CHANGE_SIMULATED' }
        attack_tags = @('T1685')
        metadata = @{
            control = 'windows_defender_realtime_monitoring'
            action = 'disable'
            synthetic = $true
            operating_system_modified = $false
        }
    }
    if ([string]$Context.Manifest.run_id -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$') {
        $event.scenario_run_id = [string]$Context.Manifest.run_id
    }
    $event | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $path -Encoding utf8NoBOM
    Write-SentinelForgeEvidence $Context @{ effect = 'synthetic_event_only'; event_path = $path; operating_system_modified = $false }
}

function Undo-SentinelForgeScenario {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string] $ManifestPath,
        [switch] $PassThru
    )
    $fullManifestPath = [IO.Path]::GetFullPath($ManifestPath)
    if (-not (Test-Path -LiteralPath $fullManifestPath -PathType Leaf)) {
        throw "Cleanup manifest does not exist: $fullManifestPath"
    }
    $manifest = Get-Content -LiteralPath $fullManifestPath -Raw | ConvertFrom-Json -Depth 20
    if ($manifest.schema_version -ne '1.0') { throw 'Unsupported cleanup manifest version.' }
    Assert-SentinelForgeRunId ([string]$manifest.run_id)
    $root = Resolve-SentinelForgeSandboxRoot ([string]$manifest.sandbox_root)
    $runDirectory = [IO.Path]::GetFullPath([string]$manifest.run_directory)
    Assert-SentinelForgeNotReparsePoint $runDirectory
    if (-not (Test-SentinelForgeContainedPath -Root $root -Candidate $runDirectory)) {
        throw 'Cleanup manifest run directory is outside its sandbox root.'
    }
    $expectedManifest = Join-Path $runDirectory $script:ManifestName
    $pathComparison = Get-SentinelForgePathComparison
    if (-not $fullManifestPath.Equals([IO.Path]::GetFullPath($expectedManifest), $pathComparison)) {
        throw 'Cleanup manifest path does not match its declared run directory.'
    }

    try {
        $actions = @($manifest.actions)
        if ($actions.Count -gt 32) { throw 'Cleanup manifest contains too many actions.' }
        [array]::Reverse($actions)
        foreach ($action in $actions) {
            switch -CaseSensitive ([string]$action.type) {
                'scheduled_task' {
                    if (-not $IsWindows) { throw 'A scheduled-task cleanup action cannot be handled off Windows.' }
                    if ($action.task_path -cne '\SentinelForgeLab\' -or
                        $action.task_name -notmatch ('^' + [Regex]::Escape([string]$manifest.run_id) + '-[A-Za-z0-9-]+$')) {
                        throw 'Cleanup manifest contains a scheduled task outside the SentinelForgeLab allowlist.'
                    }
                    if ($PSCmdlet.ShouldProcess("$($action.task_path)$($action.task_name)", 'Unregister lab scheduled task')) {
                        $task = Get-ScheduledTask -TaskPath $action.task_path -TaskName $action.task_name -ErrorAction SilentlyContinue
                        if ($null -ne $task) { Unregister-ScheduledTask -TaskPath $action.task_path -TaskName $action.task_name -Confirm:$false }
                    }
                }
                'registry_key' {
                    $allowedPrefix = "Registry::HKEY_CURRENT_USER\Software\SentinelForgeLab\Runs\$($manifest.run_id)"
                    if (-not ([string]$action.path).Equals($allowedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                        throw 'Cleanup manifest contains a registry key outside the per-run SentinelForgeLab key.'
                    }
                    if ($PSCmdlet.ShouldProcess($action.path, 'Remove scoped lab registry key')) {
                        if (Test-Path -LiteralPath $action.path) { Remove-Item -LiteralPath $action.path -Recurse -Force }
                    }
                }
                'restore_synthetic_files' {
                    $filesDirectory = [IO.Path]::GetFullPath([string]$action.files_directory)
                    $backupDirectory = [IO.Path]::GetFullPath([string]$action.backup_directory)
                    Assert-SentinelForgeNotReparsePoint $filesDirectory
                    Assert-SentinelForgeNotReparsePoint $backupDirectory
                    if (-not (Test-SentinelForgeContainedPath -Root $runDirectory -Candidate $filesDirectory) -or
                        -not (Test-SentinelForgeContainedPath -Root $runDirectory -Candidate $backupDirectory)) {
                        throw 'Synthetic restore directories are outside the run directory.'
                    }
                    $restoreFiles = @($action.files)
                    if ($restoreFiles.Count -gt 100) { throw 'Synthetic restore action contains too many files.' }
                    foreach ($file in $restoreFiles) {
                        $original = [IO.Path]::GetFullPath([string]$file.original)
                        $backup = [IO.Path]::GetFullPath([string]$file.backup)
                        $locked = [IO.Path]::GetFullPath([string]$file.locked)
                        if (-not (Test-SentinelForgeContainedPath -Root $filesDirectory -Candidate $original) -or
                            -not (Test-SentinelForgeContainedPath -Root $backupDirectory -Candidate $backup) -or
                            -not (Test-SentinelForgeContainedPath -Root $filesDirectory -Candidate $locked)) {
                            throw 'Synthetic restore file escaped its allowlisted directory.'
                        }
                        if ([string]$file.sha256 -notmatch '^[A-Fa-f0-9]{64}$' -or -not (Test-Path -LiteralPath $backup -PathType Leaf) -or
                            (Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne [string]$file.sha256) {
                            throw 'Synthetic restore backup hash verification failed.'
                        }
                        if ($PSCmdlet.ShouldProcess($original, 'Restore generated synthetic file')) {
                            if (Test-Path -LiteralPath $locked) { Remove-Item -LiteralPath $locked -Force }
                            [IO.File]::Copy($backup, $original, $true)
                            if ((Get-FileHash -LiteralPath $original -Algorithm SHA256).Hash -ne [string]$file.sha256) {
                                throw 'Restored synthetic file hash verification failed.'
                            }
                        }
                    }
                }
                'delete_directory' {
                    $actionPath = [IO.Path]::GetFullPath([string]$action.path)
                    if (-not $actionPath.Equals($runDirectory, $pathComparison)) {
                        throw 'Cleanup manifest may delete only its exact run directory.'
                    }
                    if ($PSCmdlet.ShouldProcess($actionPath, 'Remove simulation run directory')) {
                        if (Test-Path -LiteralPath $actionPath) { Remove-Item -LiteralPath $actionPath -Recurse -Force }
                    }
                }
                default { throw "Cleanup manifest contains unsupported action type '$($action.type)'." }
            }
        }
    }
    catch {
        if (Test-Path -LiteralPath $runDirectory) {
            $manifest.status = 'cleanup_failed'
            Save-SentinelForgeManifest $manifest
        }
        throw
    }

    if ($WhatIfPreference) {
        $preview = [pscustomobject]@{
            scenario_id = [string]$manifest.scenario_id
            run_id = [string]$manifest.run_id
            cleanup_verified = $false
            what_if = $true
        }
        if ($PassThru) { $preview }
        return
    }

    $verified = -not (Test-Path -LiteralPath $runDirectory)
    if (-not $verified) { throw 'Cleanup verification failed: the run directory still exists.' }
    $result = [pscustomobject]@{
        scenario_id = [string]$manifest.scenario_id
        run_id = [string]$manifest.run_id
        cleanup_verified = $true
        cleaned_at = [DateTimeOffset]::UtcNow.ToString('o')
    }
    if ($PassThru) { $result }
}

function Invoke-SentinelForgeScenario {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $ScenarioId,
        [string] $RunId = ([Guid]::NewGuid().ToString('D')),
        [string] $SandboxRoot = (Get-SentinelForgeDefaultSandboxRoot),
        [switch] $DryRun,
        [switch] $CleanupAfterRun
    )
    Assert-SentinelForgeLabMode
    Assert-SentinelForgeRunId $RunId
    $scenario = Get-SentinelForgeScenario -Id $ScenarioId
    $resolvedRoot = Resolve-SentinelForgeSandboxRoot $SandboxRoot
    if ($DryRun) {
        return [pscustomobject]@{
            schema_version = '1.0'
            scenario_id = $scenario.id
            run_id = $RunId
            dry_run = $true
            lab_mode_verified = $true
            sandbox_root = $resolvedRoot
            would_create = Join-Path (Join-Path $resolvedRoot 'runs') $RunId
            cleanup_required = $false
            description = $scenario.description
            attack_techniques = @($scenario.attack_techniques)
        }
    }
    Assert-SentinelForgeWindowsScenario $scenario
    $context = New-SentinelForgeRunContext -Scenario $scenario -RunId $RunId -SandboxRoot $resolvedRoot
    try {
        $evidencePath = switch -CaseSensitive ($scenario.id) {
            'registry-run-key' { Invoke-RegistryRunKeyScenario $context }
            'scheduled-task' { Invoke-ScheduledTaskScenario $context }
            'benign-process-chain' { Invoke-BenignProcessChainScenario $context }
            'encoded-powershell' { Invoke-EncodedPowerShellScenario $context }
            'user-writable-execution' { Invoke-UserWritableExecutionScenario $context }
            'dns-localhost' { Invoke-DnsLocalhostScenario $context }
            'ransomware-emulator' { Invoke-RansomwareSyntheticScenario $context }
            'security-control-events' { Invoke-SecurityControlSyntheticScenario $context }
            default { throw "Scenario '$($scenario.id)' has metadata but no implementation." }
        }
        $context.Manifest.status = 'completed'
        Save-SentinelForgeManifest $context.Manifest
        $syntheticEvent = if ($scenario.id -ceq 'security-control-events') {
            Get-Content -LiteralPath (Join-Path $context.RunDirectory 'synthetic-security-control-event.json') -Raw | ConvertFrom-Json -Depth 20
        } else { $null }
    }
    catch {
        $originalError = $_
        $context.Manifest.status = 'failed'
        $context.Manifest | Add-Member -NotePropertyName error_summary -NotePropertyValue $originalError.Exception.GetType().Name -Force
        Save-SentinelForgeManifest $context.Manifest
        $cleanupVerified = $false
        try {
            $cleanup = Undo-SentinelForgeScenario -ManifestPath (Join-Path $context.RunDirectory $script:ManifestName) -PassThru
            $cleanupVerified = $cleanup.cleanup_verified
        }
        catch {
            $cleanupVerified = $false
        }
        throw "Scenario '$ScenarioId' failed; cleanup_verified=$cleanupVerified. $($originalError.Exception.Message)"
    }

    $cleanupVerified = $false
    if ($CleanupAfterRun) {
        $cleanup = Undo-SentinelForgeScenario -ManifestPath (Join-Path $context.RunDirectory $script:ManifestName) -PassThru
        $cleanupVerified = $cleanup.cleanup_verified
    }
    [pscustomobject]@{
        schema_version = '1.0'
        scenario_id = $scenario.id
        run_id = $RunId
        dry_run = $false
        status = 'completed'
        run_directory = $context.RunDirectory
        manifest_path = Join-Path $context.RunDirectory $script:ManifestName
        evidence_path = $evidencePath
        synthetic_event = $syntheticEvent
        cleanup_verified = $cleanupVerified
    }
}

Export-ModuleMember -Function @(
    'Get-SentinelForgeScenario',
    'Invoke-SentinelForgeScenario',
    'Undo-SentinelForgeScenario',
    'Test-SentinelForgeContainedPath'
)
