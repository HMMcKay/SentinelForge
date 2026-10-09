[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $ScenarioId,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')][string] $RunId = ([Guid]::NewGuid().ToString('D')),
    [string] $SandboxRoot = ([IO.Path]::Combine([IO.Path]::GetTempPath(), 'SentinelForgeLab')),
    [switch] $DryRun,
    [switch] $CleanupAfterRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'SentinelForge.Simulations.psd1') -Force
Invoke-SentinelForgeScenario @PSBoundParameters
