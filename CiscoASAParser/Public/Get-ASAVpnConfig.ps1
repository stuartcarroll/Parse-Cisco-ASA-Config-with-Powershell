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
        PFS, SALifetime, NATTDisable
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

        # Get crypto maps and tunnel groups using internal calls
        $cryptoMaps = Get-ASACryptoMap -Config $configContent
        $tunnelGroups = Get-ASATunnelGroup -Config $configContent -S2SOnly

        $vpnConfigs = @()

        foreach ($cryptoMap in $cryptoMaps) {
            $peerIP = $cryptoMap.Peer
            $tunnelGroup = $tunnelGroups | Where-Object { $_.PeerIP -eq $peerIP }

            # Only include if it's a S2S tunnel
            if (-not $tunnelGroup -or $tunnelGroup.Type -ne 'ipsec-l2l') { continue }

            $vpnConfigs += [PSCustomObject]@{
                Name          = "VPN-$peerIP"
                Peer          = $peerIP
                IKEVersion    = $tunnelGroup.IKEVersion
                ACL           = $cryptoMap.ACL
                TransformSets = $cryptoMap.TransformSets
                PFS           = $cryptoMap.PFS
                SALifetime    = $cryptoMap.SALifetime
                NATTDisable   = $cryptoMap.NATTDisable
            }
        }

        # Apply filters
        if ($Peer) {
            $vpnConfigs = $vpnConfigs | Where-Object { $_.Peer -like $Peer }
        }

        $vpnConfigs
    }
}
