function Get-ASANatRule {
    <#
    .SYNOPSIS
        Parses NAT rules from a Cisco ASA configuration.

    .DESCRIPTION
        Extracts all 'nat' statements (twice NAT format) from an ASA running configuration
        and returns them as PowerShell objects with zone, source/destination mappings,
        and NAT category classification.

    .PARAMETER ConfigPath
        Path to the ASA configuration file.

    .PARAMETER Config
        Raw ASA configuration content as a string.

    .PARAMETER Category
        Filter results by NAT category: Identity/NoNAT, SourceNAT, DestNAT, or TwiceNAT.

    .PARAMETER SourceZone
        Filter results by source zone/interface.

    .PARAMETER DestZone
        Filter results by destination zone/interface.

    .EXAMPLE
        Get-ASANatRule -ConfigPath "config.txt"

    .EXAMPLE
        Get-ASANatRule -ConfigPath "config.txt" -Category "SourceNAT"

    .EXAMPLE
        Get-ASANatRule -ConfigPath "config.txt" -SourceZone "inside"

    .OUTPUTS
        PSCustomObject with properties: SourceZone, DestZone, SourceType, RealSource,
        MappedSource, DestType, RealDest, MappedDest, Category, NoProxyArp, RouteLookup
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$ConfigPath,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [string]$Config,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Identity/NoNAT', 'SourceNAT', 'DestNAT', 'TwiceNAT')]
        [string]$Category,

        [Parameter(Mandatory = $false)]
        [string]$SourceZone,

        [Parameter(Mandatory = $false)]
        [string]$DestZone
    )

    process {
        $configContent = Get-ASAConfigContent -ConfigPath $ConfigPath -Config $Config

        $natPattern = '(?m)^nat \((\S+),(\S+)\) source (static|dynamic) (\S+) (\S+) destination (static|dynamic) (\S+) (\S+)(.*)$'
        $natMatches = [regex]::Matches($configContent, $natPattern)

        $natRules = @()

        foreach ($match in $natMatches) {
            $srcZone = $match.Groups[1].Value
            $dstZone = $match.Groups[2].Value
            $sourceType = $match.Groups[3].Value
            $realSource = $match.Groups[4].Value
            $mappedSource = $match.Groups[5].Value
            $destType = $match.Groups[6].Value
            $realDest = $match.Groups[7].Value
            $mappedDest = $match.Groups[8].Value
            $options = $match.Groups[9].Value.Trim()

            # Check for no-proxy-arp
            $noProxyArp = $options -match 'no-proxy-arp'

            # Check for route-lookup
            $routeLookup = $options -match 'route-lookup'

            # Determine NAT category
            $natCategory = if ($realSource -eq $mappedSource -and $realDest -eq $mappedDest) {
                'Identity/NoNAT'
            }
            elseif ($realSource -ne $mappedSource -and $realDest -eq $mappedDest) {
                'SourceNAT'
            }
            elseif ($realSource -eq $mappedSource -and $realDest -ne $mappedDest) {
                'DestNAT'
            }
            else {
                'TwiceNAT'
            }

            $natRules += [PSCustomObject]@{
                SourceZone   = $srcZone
                DestZone     = $dstZone
                SourceType   = $sourceType
                RealSource   = $realSource
                MappedSource = $mappedSource
                DestType     = $destType
                RealDest     = $realDest
                MappedDest   = $mappedDest
                Category     = $natCategory
                NoProxyArp   = $noProxyArp
                RouteLookup  = $routeLookup
            }
        }

        # Apply filters
        if ($Category) {
            $natRules = $natRules | Where-Object { $_.Category -eq $Category }
        }

        if ($SourceZone) {
            $natRules = $natRules | Where-Object { $_.SourceZone -like $SourceZone }
        }

        if ($DestZone) {
            $natRules = $natRules | Where-Object { $_.DestZone -like $DestZone }
        }

        $natRules
    }
}
