function Get-ASAPhase2Selector {
    <#
    .SYNOPSIS
        Returns VPN Phase 2 selectors (traffic selectors/interesting traffic) from a Cisco ASA.

    .DESCRIPTION
        Resolves VPN ACLs to determine the local and remote networks that define
        Phase 2 traffic selectors for each VPN peer. Automatically resolves object
        and group references to actual subnet values.

    .PARAMETER ConfigPath
        Path to the ASA configuration file.

    .PARAMETER Config
        Raw ASA configuration content as a string.

    .PARAMETER Peer
        Filter results by peer IP address. Supports wildcards (*).

    .EXAMPLE
        Get-ASAPhase2Selector -ConfigPath "config.txt"

    .EXAMPLE
        Get-ASAPhase2Selector -ConfigPath "config.txt" -Peer "203.0.113.1"

    .OUTPUTS
        PSCustomObject with properties: Peer, VPNName, LocalNetRaw, LocalNet, RemoteNetRaw, RemoteNet
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$ConfigPath,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [string]$Config,

        [Parameter(Mandatory = $false)]
        [string]$Peer
    )

    process {
        $configContent = Get-ASAConfigContent -ConfigPath $ConfigPath -Config $Config

        # Get required data - use Get-ASACryptoMap directly to avoid circular dependency with Get-ASAVpnConfig
        $cryptoMaps = Get-ASACryptoMap -Config $configContent
        $tunnelGroups = Get-ASATunnelGroup -Config $configContent -S2SOnly
        $accessLists = Get-ASAAccessList -Config $configContent
        $networkObjects = Get-ASANetworkObject -Config $configContent
        $networkGroups = Get-ASANetworkGroup -Config $configContent

        # Helper function to resolve object/group to subnet(s) recursively
        function Resolve-ToSubnet {
            param($reference)

            $results = @()

            # Handle object:name format
            if ($reference -match '^object:(.+)$') {
                $objectName = $matches[1]
                # Case-insensitive lookup
                $obj = $networkObjects | Where-Object { $_.Name -ieq $objectName }
                if ($obj) {
                    $def = $obj.Definition
                    if ($def -match 'host (\S+)') { return "$($matches[1])/32" }
                    if ($def -match 'subnet (\S+) (\S+)') { return "$($matches[1]) $($matches[2])" }
                    if ($def -match 'range (\S+) (\S+)') { return "$($matches[1])-$($matches[2])" }
                    # Check Value property as fallback
                    if ($obj.Value) { return $obj.Value }
                    return $def
                }
                return $reference
            }

            # Handle group:name format
            if ($reference -match '^group:(.+)$') {
                $groupName = $matches[1]
                # Case-insensitive lookup
                $grp = $networkGroups | Where-Object { $_.Name -ieq $groupName }
                if ($grp -and $grp.Members) {
                    foreach ($member in $grp.Members) {
                        $resolved = Resolve-ToSubnet $member
                        if ($resolved -is [array]) {
                            $results += $resolved
                        } else {
                            $results += $resolved
                        }
                    }
                    return $results
                }
                return $reference
            }

            # Handle direct object name (no prefix)
            $obj = $networkObjects | Where-Object { $_.Name -ieq $reference }
            if ($obj) {
                $def = $obj.Definition
                if ($def -match 'host (\S+)') { return "$($matches[1])/32" }
                if ($def -match 'subnet (\S+) (\S+)') { return "$($matches[1]) $($matches[2])" }
                if ($def -match 'range (\S+) (\S+)') { return "$($matches[1])-$($matches[2])" }
                if ($obj.Value) { return $obj.Value }
                return $def
            }

            $grp = $networkGroups | Where-Object { $_.Name -ieq $reference }
            if ($grp -and $grp.Members) {
                foreach ($member in $grp.Members) {
                    $resolved = Resolve-ToSubnet $member
                    if ($resolved -is [array]) {
                        $results += $resolved
                    } else {
                        $results += $resolved
                    }
                }
                return $results
            }

            # Handle subnet:value and host:value formats
            if ($reference -match '^subnet:(.+)$') { return $matches[1] }
            if ($reference -match '^host:(.+)$') { return "$($matches[1])/32" }

            return $reference
        }

        $phase2Selectors = @()

        foreach ($cryptoMap in $cryptoMaps) {
            $peerIP = $cryptoMap.Peer

            # Only include if it's a S2S tunnel
            $tunnelGroup = $tunnelGroups | Where-Object { $_.PeerIP -eq $peerIP }
            if (-not $tunnelGroup -or $tunnelGroup.Type -ne 'ipsec-l2l') { continue }

            $aclName = $cryptoMap.ACL
            $aclEntries = $accessLists | Where-Object { $_.ACLName -eq $aclName }

            foreach ($entry in $aclEntries) {
                $localNetRaw = $entry.Source
                $remoteNetRaw = $entry.Destination

                # Resolve source (local network) - pass full reference for resolution
                $localNet = Resolve-ToSubnet $entry.Source

                # Resolve destination (remote network) - pass full reference for resolution
                $remoteNet = Resolve-ToSubnet $entry.Destination

                $phase2Selectors += [PSCustomObject]@{
                    Peer         = $peerIP
                    VPNName      = "VPN-$peerIP"
                    LocalNetRaw  = $localNetRaw
                    LocalNet     = $localNet
                    RemoteNetRaw = $remoteNetRaw
                    RemoteNet    = $remoteNet
                }
            }
        }

        # Apply filters
        if ($Peer) {
            $phase2Selectors = $phase2Selectors | Where-Object { $_.Peer -like $Peer }
        }

        $phase2Selectors
    }
}
