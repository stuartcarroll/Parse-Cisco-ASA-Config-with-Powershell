function Get-ASACryptoMap {
    <#
    .SYNOPSIS
        Parses crypto map entries from a Cisco ASA configuration.

    .DESCRIPTION
        Extracts all 'crypto map' entries from an ASA running configuration
        and returns them as PowerShell objects with peer, ACL, transform sets,
        PFS, and SA lifetime settings.

    .PARAMETER ConfigPath
        Path to the ASA configuration file.

    .PARAMETER Config
        Raw ASA configuration content as a string.

    .PARAMETER MapName
        Filter results by crypto map name. Supports wildcards (*).

    .PARAMETER Peer
        Filter results by peer IP address. Supports wildcards (*).

    .EXAMPLE
        Get-ASACryptoMap -ConfigPath "config.txt"

    .EXAMPLE
        Get-ASACryptoMap -ConfigPath "config.txt" -MapName "outside_map"

    .OUTPUTS
        PSCustomObject with properties: MapName, Sequence, Peer, ACL, TransformSets,
        PFS, SALifetime, SALifetimeKB, NATTDisable
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$ConfigPath,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [string]$Config,

        [Parameter(Mandatory = $false)]
        [string]$MapName,

        [Parameter(Mandatory = $false)]
        [string]$Peer
    )

    process {
        $configContent = Get-ASAConfigContent -ConfigPath $ConfigPath -Config $Config

        $cryptoMapLines = $configContent -split '\r?\n' | Where-Object { $_ -match '^crypto map \S+ \d+' }

        $cryptoMapEntries = @{}

        foreach ($line in $cryptoMapLines) {
            if ($line -match '^crypto map (\S+) (\d+) (.+)$') {
                $mapNameValue = $matches[1]
                $sequence = $matches[2]
                $setting = $matches[3]

                $key = "$mapNameValue-$sequence"

                if (-not $cryptoMapEntries.ContainsKey($key)) {
                    $cryptoMapEntries[$key] = [PSCustomObject]@{
                        MapName       = $mapNameValue
                        Sequence      = [int]$sequence
                        Peer          = $null
                        ACL           = $null
                        TransformSets = $null
                        PFS           = $null
                        SALifetime    = $null
                        SALifetimeKB  = $null
                        NATTDisable   = $false
                    }
                }

                $entry = $cryptoMapEntries[$key]

                if ($setting -match '^match address (\S+)') { $entry.ACL = $matches[1] }
                if ($setting -match '^set peer (\S+)') { $entry.Peer = $matches[1] }
                if ($setting -match '^set ikev1 transform-set (.+)$') { $entry.TransformSets = $matches[1] }
                if ($setting -match '^set ikev2 ipsec-proposal (.+)$') { $entry.TransformSets = $matches[1] }
                if ($setting -match '^set pfs (\S+)') { $entry.PFS = $matches[1] }
                if ($setting -match '^set security-association lifetime seconds (\d+)') { $entry.SALifetime = [int]$matches[1] }
                if ($setting -match '^set security-association lifetime kilobytes (\d+)') { $entry.SALifetimeKB = [int]$matches[1] }
                if ($setting -match '^set nat-t-disable') { $entry.NATTDisable = $true }
            }
        }

        $cryptoMaps = $cryptoMapEntries.Values | Sort-Object MapName, Sequence

        # Apply filters
        if ($MapName) {
            $cryptoMaps = $cryptoMaps | Where-Object { $_.MapName -like $MapName }
        }

        if ($Peer) {
            $cryptoMaps = $cryptoMaps | Where-Object { $_.Peer -like $Peer }
        }

        $cryptoMaps
    }
}
