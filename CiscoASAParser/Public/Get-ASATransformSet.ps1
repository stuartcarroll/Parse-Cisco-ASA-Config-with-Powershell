function Get-ASATransformSet {
    <#
    .SYNOPSIS
        Parses IPsec transform sets (Phase 2 proposals) from a Cisco ASA configuration.

    .DESCRIPTION
        Extracts all 'crypto ipsec ikev1 transform-set' definitions from an ASA
        running configuration and returns them as PowerShell objects.

    .PARAMETER ConfigPath
        Path to the ASA configuration file.

    .PARAMETER Config
        Raw ASA configuration content as a string.

    .PARAMETER Name
        Filter results by transform set name. Supports wildcards (*).

    .EXAMPLE
        Get-ASATransformSet -ConfigPath "config.txt"

    .EXAMPLE
        Get-ASATransformSet -ConfigPath "config.txt" -Name "ESP-*"

    .OUTPUTS
        PSCustomObject with properties: Name, Transforms, Mode
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$ConfigPath,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [string]$Config,

        [Parameter(Mandatory = $false)]
        [string]$Name
    )

    process {
        $configContent = Get-ASAConfigContent -ConfigPath $ConfigPath -Config $Config

        $transformSetLines = $configContent -split '\r?\n' | Where-Object { $_ -match '^crypto ipsec ikev1 transform-set' }

        $transformSets = @()

        foreach ($line in $transformSetLines) {
            if ($line -match '^crypto ipsec ikev1 transform-set (\S+) (.+)$') {
                $tsName = $matches[1]
                $remainder = $matches[2]

                $mode = 'tunnel'
                if ($remainder -match 'mode transport') {
                    $mode = 'transport'
                    $remainder = $remainder -replace '\s*mode transport\s*', ' '
                }

                $transforms = $remainder.Trim() -split '\s+'

                $transformSets += [PSCustomObject]@{
                    Name       = $tsName
                    Transforms = $transforms -join ', '
                    Mode       = $mode
                }
            }
        }

        # Apply filters
        if ($Name) {
            $transformSets = $transformSets | Where-Object { $_.Name -like $Name }
        }

        $transformSets
    }
}
