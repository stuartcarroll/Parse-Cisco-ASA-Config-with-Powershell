function Get-ASAServiceObject {
    <#
    .SYNOPSIS
        Parses service objects from a Cisco ASA configuration.

    .DESCRIPTION
        Extracts all 'object service' definitions from an ASA running configuration
        and returns them as PowerShell objects.

    .PARAMETER ConfigPath
        Path to the ASA configuration file.

    .PARAMETER Config
        Raw ASA configuration content as a string.

    .PARAMETER Name
        Filter results by object name. Supports wildcards (*).

    .PARAMETER Protocol
        Filter results by protocol (tcp, udp, etc.).

    .EXAMPLE
        Get-ASAServiceObject -ConfigPath "config.txt"

    .EXAMPLE
        Get-ASAServiceObject -ConfigPath "config.txt" -Protocol "tcp"

    .OUTPUTS
        PSCustomObject with properties: Name, Protocol, SourcePort, DestPort, Description
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
        [string]$Protocol
    )

    process {
        $configContent = Get-ASAConfigContent -ConfigPath $ConfigPath -Config $Config

        $servicePattern = '(?m)^object service (\S+)\r?\n(?: .+\r?\n?)+'
        $serviceMatches = [regex]::Matches($configContent, $servicePattern)

        $serviceObjects = @()

        foreach ($match in $serviceMatches) {
            $block = $match.Value
            $objName = ($block -split '\r?\n')[0] -replace '^object service ', ''

            $lines = ($block -split '\r?\n' | Select-Object -Skip 1) | ForEach-Object { $_.Trim() }

            $proto = $null
            $srcPort = $null
            $dstPort = $null
            $description = $null

            foreach ($line in $lines) {
                # service tcp destination eq https
                if ($line -match '^service (\S+) destination eq (\S+)') {
                    $proto = $matches[1]
                    $dstPort = $matches[2]
                }
                # service tcp source eq 1234 destination eq 5678
                elseif ($line -match '^service (\S+) source eq (\S+) destination eq (\S+)') {
                    $proto = $matches[1]
                    $srcPort = $matches[2]
                    $dstPort = $matches[3]
                }
                # service tcp destination range 8000 8100
                elseif ($line -match '^service (\S+) destination range (\S+) (\S+)') {
                    $proto = $matches[1]
                    $dstPort = "$($matches[2])-$($matches[3])"
                }
                # service tcp
                elseif ($line -match '^service (\S+)$') {
                    $proto = $matches[1]
                }
                # description
                if ($line -match '^description (.+)$') {
                    $description = $matches[1]
                }
            }

            $serviceObjects += [PSCustomObject]@{
                Name        = $objName
                Protocol    = $proto
                SourcePort  = $srcPort
                DestPort    = $dstPort
                Description = $description
            }
        }

        # Apply filters
        if ($Name) {
            $serviceObjects = $serviceObjects | Where-Object { $_.Name -like $Name }
        }

        if ($Protocol) {
            $serviceObjects = $serviceObjects | Where-Object { $_.Protocol -eq $Protocol }
        }

        $serviceObjects
    }
}
