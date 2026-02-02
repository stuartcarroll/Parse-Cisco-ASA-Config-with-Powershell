function Get-ASAVpnConfig {
    <#
    .SYNOPSIS
        Returns a unified view of site-to-site VPN configurations from a Cisco ASA.

    .DESCRIPTION
        Combines information from crypto maps and tunnel groups to provide a
        consolidated view of S2S VPN configurations including peer, IKE version,
        ACL, transform sets, PFS, and SA lifetime.

    .PARAMETER ConfigPath
        Path to the ASA configuration file.

    .PARAMETER Config
        Raw ASA configuration content as a string.

    .PARAMETER Peer
        Filter results by peer IP address. Supports wildcards (*).

    .EXAMPLE
        Get-ASAVpnConfig -ConfigPath "config.txt"

    .EXAMPLE
        Get-ASAVpnConfig -ConfigPath "config.txt" -Peer "203.0.113.1"

    .OUTPUTS
        PSCustomObject with properties: Name, Peer, IKEVersion, ACL, TransformSets,
        PFS, SALifetime, SALifetimeKB, NATTDisable, MapName, Sequence, Interface,
        LocalSubnets, RemoteSubnets
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

        # Get crypto maps, tunnel groups, and phase 2 selectors
        $cryptoMaps = Get-ASACryptoMap -Config $configContent
        $tunnelGroups = Get-ASATunnelGroup -Config $configContent -S2SOnly
        $phase2Selectors = Get-ASAPhase2Selector -Config $configContent

        # Parse interface bindings: "crypto map outside_map interface outside"
        $interfaceBindings = @{}
        $configContent -split '\r?\n' | ForEach-Object {
            if ($_ -match '^crypto map (\S+) interface (\S+)$') {
                $interfaceBindings[$matches[1]] = $matches[2]
            }
        }

        $vpnConfigs = @()

        foreach ($cryptoMap in $cryptoMaps) {
            $peerIP = $cryptoMap.Peer
            $tunnelGroup = $tunnelGroups | Where-Object { $_.PeerIP -eq $peerIP }

            # Only include if it's a S2S tunnel
            if (-not $tunnelGroup -or $tunnelGroup.Type -ne 'ipsec-l2l') { continue }

            # Get unique local and remote subnets for this peer
            $peerSelectors = $phase2Selectors | Where-Object { $_.Peer -eq $peerIP }
            $localSubnets = @($peerSelectors | ForEach-Object { $_.LocalNet } | Where-Object { $_ } | Select-Object -Unique)
            $remoteSubnets = @($peerSelectors | ForEach-Object { $_.RemoteNet } | Where-Object { $_ } | Select-Object -Unique)

            $vpnConfigs += [PSCustomObject]@{
                Name          = "VPN-$peerIP"
                Peer          = $peerIP
                IKEVersion    = $tunnelGroup.IKEVersion
                ACL           = $cryptoMap.ACL
                TransformSets = $cryptoMap.TransformSets
                PFS           = $cryptoMap.PFS
                SALifetime    = $cryptoMap.SALifetime
                SALifetimeKB  = $cryptoMap.SALifetimeKB
                NATTDisable   = $cryptoMap.NATTDisable
                MapName       = $cryptoMap.MapName
                Sequence      = $cryptoMap.Sequence
                Interface     = $interfaceBindings[$cryptoMap.MapName]
                LocalSubnets  = $localSubnets
                RemoteSubnets = $remoteSubnets
            }
        }

        # Apply filters
        if ($Peer) {
            $vpnConfigs = $vpnConfigs | Where-Object { $_.Peer -like $Peer }
        }

        $vpnConfigs
    }
}
