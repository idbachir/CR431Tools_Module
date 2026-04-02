@{
    RootModule        = 'CR431Tools.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b8c9c1d0-3f4b-4c2a-9e3d-123456789abc'
    Author            = 'Malika Saidani, Idir Ait-Bachir'
    CompanyName       = 'N/A'
    Description       = 'Outils d’analyse des logs firewall et Pi-hole.'
    PowerShellVersion = '5.1'
    # CreatedOn       = '2026-03-25'

    FunctionsToExport = @(
    'Convert-FwLogToTable',
    'Get-FwDataCols',
    'Find-FwIpFqdn',
    'Invoke-FwFullProcess',
	'Show-ModuleParameters'
    )

    CmdletsToExport   = @()
    VariablesToExport = @()
}
