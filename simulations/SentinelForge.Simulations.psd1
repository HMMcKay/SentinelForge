@{
    RootModule = 'SentinelForge.Simulations.psm1'
    ModuleVersion = '1.0.0'
    GUID = 'a51f1d35-df29-4742-a14f-e172595ad740'
    Author = 'SentinelForge contributors'
    Description = 'Lab-gated, reversible SentinelForge behavior simulations.'
    PowerShellVersion = '7.2'
    FunctionsToExport = @(
        'Get-SentinelForgeScenario',
        'Invoke-SentinelForgeScenario',
        'Undo-SentinelForgeScenario',
        'Test-SentinelForgeContainedPath'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
}
