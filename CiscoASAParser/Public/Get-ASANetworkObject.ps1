function Get-ASANetworkObject {
    <#
    .SYNOPSIS
        Parses network objects from a Cisco ASA configuration.

    .DESCRIPTION
        Extracts all 'object network' definitions from an ASA running configuration
        and returns them as PowerShell objects with properties for name, type, value,
        NAT settings, and the raw definition.

    .PARAMETER ConfigPath
        Path to the ASA configuration file (e.g., "show running-config.txt").

    .PARAMETER Config
        Raw ASA configuration content as a string. Can be piped from Get-Content -Raw.

    .PARAMETER Name
        Filter results by object name. Supports wildcards (*).

    .PARAMETER Type
        Filter results by object type: host, subnet, range, fqdn, or nat.

    .EXAMPLE
        Get-ASANetworkObject -ConfigPath "C:\configs\asa-config.txt"

        Returns all network objects from the configuration file.

    .EXAMPLE
        Get-ASANetworkObject -ConfigPath "config.txt" -Type "host"

        Returns only host-type network objects.

    .EXAMPLE
        Get-ASANetworkObject -ConfigPath "config.txt" -Name "Web*"

        Returns network objects with names starting with "Web".

    .EXAMPLE
        Get-Content "config.txt" -Raw | Get-ASANetworkObject

        Pipes configuration content directly to the function.

    .OUTPUTS
        PSCustomObject with properties:
        - Name: Object name
        - Type: host, subnet, range, fqdn, or unknown
        - Value: Real/original IP address, subnet, or FQDN
        - TranslatedIP: Mapped/NAT IP address (if object has NAT)
        - HasNAT: Boolean indicating if object has inline NAT
        - SourceZone: NAT source zone (if applicable)
        - DestZone: NAT destination zone (if applicable)
        - NatType: static or dynamic (if applicable)
        - ServiceProto: Service protocol (if NAT includes PAT)
        - OriginalPort: Original port (if NAT includes PAT)
        - TranslatedPort: Translated port (if NAT includes PAT)
        - Definition: Raw definition lines
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$ConfigPath,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [string]$Config,

        [Parameter(Mandatory = $false)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [ValidateSet('host', 'subnet', 'range', 'fqdn', 'unknown')]
        [string]$Type
    )

    process {
        # Get configuration content
        $configContent = Get-ASAConfigContent -ConfigPath $ConfigPath -Config $Config

        # Regex pattern for network objects
        $networkPattern = '(?m)^object network (\S+)\r?\n(?: .+\r?\n?)+'

        # Get all matches
        $networkMatches = [regex]::Matches($configContent, $networkPattern)

        # Use hashtable to merge duplicate object definitions
        $objectHash = @{}

        foreach ($match in $networkMatches) {
            $block = $match.Value

            # Extract the object name
            $objName = ($block -split '\r?\n')[0] -replace '^object network ', ''

            # Extract the definition lines
            $blockDefinition = ($block -split '\r?\n' | Select-Object -Skip 1) -join "`n" | ForEach-Object { $_.Trim() }

            # Initialize or get existing object data
            if (-not $objectHash.ContainsKey($objName)) {
                $objectHash[$objName] = @{
                    Type           = 'unknown'
                    Value          = $null
                    TranslatedIP   = $null
                    HasNAT         = $false
                    SourceZone     = $null
                    DestZone       = $null
                    NatType        = $null
                    ServiceProto   = $null
                    OriginalPort   = $null
                    TranslatedPort = $null
                    Definition     = @()
                }
            }

            $objData = $objectHash[$objName]
            $objData.Definition += $blockDefinition

            # Parse each line independently to capture both address and NAT info
            $lines = ($block -split '\r?\n' | Select-Object -Skip 1) | ForEach-Object { $_.Trim() }

            foreach ($line in $lines) {
                # Base address types
                if ($line -match '^host (\S+)') {
                    $objData.Type = 'host'
                    $objData.Value = $matches[1]
                }
                elseif ($line -match '^subnet (\S+) (\S+)') {
                    $objData.Type = 'subnet'
                    $objData.Value = "$($matches[1])/$($matches[2])"
                }
                elseif ($line -match '^range (\S+) (\S+)') {
                    $objData.Type = 'range'
                    $objData.Value = "$($matches[1])-$($matches[2])"
                }
                elseif ($line -match '^fqdn v4 (\S+)') {
                    $objData.Type = 'fqdn'
                    $objData.Value = $matches[1]
                }
                elseif ($line -match '^fqdn (\S+)') {
                    $objData.Type = 'fqdn'
                    $objData.Value = $matches[1]
                }

                # NAT info (not elseif - can coexist with host/subnet)
                if ($line -match '^nat \((\S+),(\S+)\) (static|dynamic) (\S+)') {
                    $objData.SourceZone = $matches[1]
                    $objData.DestZone = $matches[2]
                    $objData.NatType = $matches[3]
                    $objData.TranslatedIP = $matches[4]
                    $objData.HasNAT = $true
                }

                # PAT service info
                if ($line -match 'service (\S+) (\S+) (\S+)$') {
                    $objData.ServiceProto = $matches[1]
                    $objData.OriginalPort = $matches[2]
                    $objData.TranslatedPort = $matches[3]
                }
            }
        }

        # Convert hashtable to array of objects
        $networkObjects = @()
        foreach ($objName in $objectHash.Keys) {
            $data = $objectHash[$objName]
            $networkObjects += [PSCustomObject]@{
                Name           = $objName
                Type           = $data.Type
                Value          = $data.Value
                TranslatedIP   = $data.TranslatedIP
                HasNAT         = $data.HasNAT
                SourceZone     = $data.SourceZone
                DestZone       = $data.DestZone
                NatType        = $data.NatType
                ServiceProto   = $data.ServiceProto
                OriginalPort   = $data.OriginalPort
                TranslatedPort = $data.TranslatedPort
                Definition     = $data.Definition -join "`n"
            }
        }

        # Apply filters
        if ($Name) {
            $networkObjects = $networkObjects | Where-Object { $_.Name -like $Name }
        }

        if ($Type) {
            $networkObjects = $networkObjects | Where-Object { $_.Type -eq $Type }
        }

        # Return results
        $networkObjects
    }
}
