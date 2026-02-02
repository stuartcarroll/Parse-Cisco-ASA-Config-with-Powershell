function Get-ASANatRule {
    <#
    .SYNOPSIS
        Parses NAT rules from a Cisco ASA configuration.

    .DESCRIPTION
        Extracts NAT rules from an ASA running configuration including:
        - Twice NAT (standalone nat statements)
        - Object NAT (nat defined inside object network blocks)
        Returns them as PowerShell objects with zone, source/destination mappings,
        and NAT category classification.

    .PARAMETER ConfigPath
        Path to the ASA configuration file.

    .PARAMETER Config
        Raw ASA configuration content as a string.

    .PARAMETER Category
        Filter results by NAT category: Identity/NoNAT, SourceNAT, DestNAT, TwiceNAT, or ObjectNAT.

    .PARAMETER NatStyle
        Filter by NAT style: ObjectNAT (inline in objects), TwiceNAT (standalone), or All.

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

    .EXAMPLE
        Get-ASANatRule -ConfigPath "config.txt" -NatStyle "ObjectNAT"

        Returns only Object NAT rules (NAT defined inside network objects).

    .OUTPUTS
        PSCustomObject with properties: SourceZone, DestZone, SourceType, RealSource,
        MappedSource, DestType, RealDest, MappedDest, Category, ObjectName, NoProxyArp, RouteLookup
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$ConfigPath,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [string]$Config,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Identity/NoNAT', 'SourceNAT', 'DestNAT', 'TwiceNAT', 'ObjectNAT')]
        [string]$Category,

        [Parameter(Mandatory = $false)]
        [ValidateSet('ObjectNAT', 'TwiceNAT', 'All')]
        [string]$NatStyle = 'All',

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
                ObjectName   = $null
                NatStyle     = 'TwiceNAT'
                NoProxyArp   = $noProxyArp
                RouteLookup  = $routeLookup
            }
        }

        # Parse Object NAT (NAT defined inside object network blocks)
        # First collect all blocks by object name to handle split definitions
        $objectNatPattern = '(?m)^object network (\S+)\r?\n(?: .+\r?\n?)+'
        $objectNatMatches = [regex]::Matches($configContent, $objectNatPattern)

        $objectBlocks = @{}
        foreach ($match in $objectNatMatches) {
            $block = $match.Value
            $objName = ($block -split '\r?\n')[0] -replace '^object network ', ''

            if (-not $objectBlocks.ContainsKey($objName)) {
                $objectBlocks[$objName] = @{
                    RealIP       = $null
                    TranslatedIP = $null
                    SourceZone   = $null
                    DestZone     = $null
                    NatType      = $null
                    HasNAT       = $false
                }
            }

            $data = $objectBlocks[$objName]

            # Parse each line
            $lines = ($block -split '\r?\n' | Select-Object -Skip 1) | ForEach-Object { $_.Trim() }
            foreach ($line in $lines) {
                if ($line -match '^host (\S+)') {
                    $data.RealIP = $matches[1]
                }
                elseif ($line -match '^subnet (\S+) (\S+)') {
                    $data.RealIP = "$($matches[1])/$($matches[2])"
                }
                elseif ($line -match '^range (\S+) (\S+)') {
                    $data.RealIP = "$($matches[1])-$($matches[2])"
                }

                if ($line -match '^nat \((\S+),(\S+)\) (static|dynamic) (\S+)') {
                    $data.SourceZone = $matches[1]
                    $data.DestZone = $matches[2]
                    $data.NatType = $matches[3]
                    $data.TranslatedIP = $matches[4]
                    $data.HasNAT = $true
                }
            }
        }

        # Create NAT rules from merged object data
        foreach ($objName in $objectBlocks.Keys) {
            $data = $objectBlocks[$objName]
            if ($data.HasNAT) {
                $natRules += [PSCustomObject]@{
                    SourceZone   = $data.SourceZone
                    DestZone     = $data.DestZone
                    SourceType   = $data.NatType
                    RealSource   = $data.RealIP
                    MappedSource = $data.TranslatedIP
                    DestType     = $null
                    RealDest     = $null
                    MappedDest   = $null
                    Category     = 'ObjectNAT'
                    ObjectName   = $objName
                    NatStyle     = 'ObjectNAT'
                    NoProxyArp   = $false
                    RouteLookup  = $false
                }
            }
        }

        # Apply filters
        if ($NatStyle -ne 'All') {
            $natRules = $natRules | Where-Object { $_.NatStyle -eq $NatStyle }
        }

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
