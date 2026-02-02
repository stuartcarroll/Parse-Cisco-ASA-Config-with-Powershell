@{
    # Module manifest for CiscoASAParser

    # Script module file associated with this manifest
    RootModule = 'CiscoASAParser.psm1'

    # Version number of this module
    ModuleVersion = '1.0.0'

    # ID used to uniquely identify this module
    GUID = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'

    # Author of this module
    Author = 'Stuart Carroll'

    # Company or vendor of this module
    CompanyName = 'Coffee Cup Solutions'

    # Copyright statement for this module
    Copyright = '(c) 2025 Coffee Cup Solutions. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'PowerShell module for parsing Cisco ASA firewall configurations. Extracts network objects, service objects, access lists, NAT rules, VPN configurations, and more into structured PowerShell objects.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Functions to export from this module
    FunctionsToExport = @(
        'Get-ASANetworkObject',
        'Get-ASAServiceObject',
        'Get-ASANetworkGroup',
        'Get-ASAServiceGroup',
        'Get-ASAIcmpGroup',
        'Get-ASAAccessList',
        'Get-ASANatRule',
        'Get-ASAIkePolicy',
        'Get-ASATransformSet',
        'Get-ASATunnelGroup',
        'Get-ASACryptoMap',
        'Get-ASAVpnConfig',
        'Get-ASAPhase2Selector',
        'Resolve-ASAObject'
    )

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @()

    # Private data to pass to the module specified in RootModule
    PrivateData = @{
        PSData = @{
            # Tags applied to this module for online gallery discovery
            Tags = @('Cisco', 'ASA', 'Firewall', 'Config', 'Parser', 'Network', 'Security')

            # URL to the license for this module
            LicenseUri = ''

            # URL to the project site for this module
            ProjectUri = ''

            # Release notes for this module
            ReleaseNotes = 'Initial release - Parse Cisco ASA running configurations'
        }
    }
}
