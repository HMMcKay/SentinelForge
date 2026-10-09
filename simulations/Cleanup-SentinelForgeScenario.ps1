[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $ManifestPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'SentinelForge.Simulations.psd1') -Force
Undo-SentinelForgeScenario -ManifestPath $ManifestPath -PassThru -WhatIf:$WhatIfPreference
