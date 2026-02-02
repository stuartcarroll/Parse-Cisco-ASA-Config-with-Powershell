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
        - Type: host, subnet, range, fqdn, nat, or unknown
        - SourceZone: NAT source zone (if applicable)
        - DestZone: NAT destination zone (if applicable)
        - NatType: static or dynamic (if applicable)
        - Value: IP address, subnet, or FQDN value
        - ServiceProto: Service protocol (if NAT includes service)
        - OriginalPort: Original port (if NAT includes service)
        - TranslatedPort: Translated port (if NAT includes service)
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
        [ValidateSet('host', 'subnet', 'range', 'fqdn', 'nat', 'unknown')]
        [string]$Type
    )

    process {
        # Get configuration content
        $configContent = Get-ASAConfigContent -ConfigPath $ConfigPath -Config $Config

        # Regex pattern for network objects
        $networkPattern = '(?m)^object network (\S+)\r?\n(?: .+\r?\n?)+'

        # Get all matches
        $networkMatches = [regex]::Matches($configContent, $networkPattern)

        $networkObjects = @()

        foreach ($match in $networkMatches) {
            $block = $match.Value

            # Extract the object name
            $objName = ($block -split '\r?\n')[0] -replace '^object network ', ''

            # Extract the definition lines
            $definition = ($block -split '\r?\n' | Select-Object -Skip 1) -join "`n" | ForEach-Object { $_.Trim() }

            # Determine the type of network object
            $objType = switch -Regex ($definition) {
                '^host'   { 'host' }
                '^subnet' { 'subnet' }
                '^range'  { 'range' }
                '^fqdn'   { 'fqdn' }
                '^nat'    { 'nat' }
                default   { 'unknown' }
            }

            # Extract the value based on the type
            $value = switch -Regex ($definition) {
                'host (\S+)'       { $matches[1] }
                'subnet (\S+)'     { $matches[1] }
                'range (\S+)'      { $matches[1] }
                'fqdn v4 (\S+)'    { $matches[1] }
                'fqdn (\S+)'       { $matches[1] }
                'static (\S+)'     { $matches[1] }
                'dynamic interface' { 'interface' }
                default            { $null }
            }

            # Extract subnet mask if present
            if ($definition -match 'subnet (\S+) (\S+)') {
                $value = "$($matches[1])/$($matches[2])"
            }

            # Extract range end if present
            if ($definition -match 'range (\S+) (\S+)') {
                $value = "$($matches[1])-$($matches[2])"
            }

            # For NAT objects, extract source and destination zones if available
            $sourceZone = $null
            $destZone = $null
            $natType = $null

            if ($definition -match 'nat \((\S+),(\S+)\) (static|dynamic)') {
                $sourceZone = $matches[1]
                $destZone = $matches[2]
                $natType = $matches[3]
            }

            # For service objects, extract protocol and ports if available
            $serviceProto = $null
            $serviceOrigPort = $null
            $serviceTransPort = $null

            if ($definition -match 'service (\S+) (\S+) (\S+)$') {
                $serviceProto = $matches[1]
                $serviceOrigPort = $matches[2]
                $serviceTransPort = $matches[3]
            }

            # Create the output object
            $obj = [PSCustomObject]@{
                Name           = $objName
                Type           = $objType
                SourceZone     = $sourceZone
                DestZone       = $destZone
                NatType        = $natType
                Value          = $value
                ServiceProto   = $serviceProto
                OriginalPort   = $serviceOrigPort
                TranslatedPort = $serviceTransPort
                Definition     = $definition
            }

            $networkObjects += $obj
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
