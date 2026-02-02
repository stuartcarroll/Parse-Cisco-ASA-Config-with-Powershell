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
        PSCustomObject with properties: Peer, VPNName, LocalNet, RemoteNet
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

        # Helper function to resolve object to subnet
        function Resolve-ToSubnet {
            param($objectName)

            $obj = $networkObjects | Where-Object { $_.Name -eq $objectName }
            if ($obj) {
                $def = $obj.Definition
                if ($def -match 'host (\S+)') { return "$($matches[1])/32" }
                if ($def -match 'subnet (\S+) (\S+)') { return "$($matches[1]) $($matches[2])" }
                return $def
            }

            $grp = $networkGroups | Where-Object { $_.Name -eq $objectName }
            if ($grp) { return $grp.Members }

            return $objectName
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
                $localNet = $null
                $remoteNet = $null

                # Resolve source (local network)
                if ($entry.Source -match '^object:(.+)$') {
                    $localNet = Resolve-ToSubnet $matches[1]
                }
                elseif ($entry.Source -match '^group:(.+)$') {
                    $localNet = Resolve-ToSubnet $matches[1]
                }
                elseif ($entry.Source -match '^subnet:(.+)$') {
                    $localNet = $matches[1]
                }
                elseif ($entry.Source -match '^host:(.+)$') {
                    $localNet = "$($matches[1])/32"
                }
                else {
                    $localNet = $entry.Source
                }

                # Resolve destination (remote network)
                if ($entry.Destination -match '^object:(.+)$') {
                    $remoteNet = Resolve-ToSubnet $matches[1]
                }
                elseif ($entry.Destination -match '^group:(.+)$') {
                    $remoteNet = Resolve-ToSubnet $matches[1]
                }
                elseif ($entry.Destination -match '^subnet:(.+)$') {
                    $remoteNet = $matches[1]
                }
                elseif ($entry.Destination -match '^host:(.+)$') {
                    $remoteNet = "$($matches[1])/32"
                }
                else {
                    $remoteNet = $entry.Destination
                }

                $phase2Selectors += [PSCustomObject]@{
                    Peer      = $peerIP
                    VPNName   = "VPN-$peerIP"
                    LocalNet  = $localNet
                    RemoteNet = $remoteNet
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
