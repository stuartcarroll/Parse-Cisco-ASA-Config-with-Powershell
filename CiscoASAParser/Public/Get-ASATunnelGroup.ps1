function Get-ASATunnelGroup {
    <#
    .SYNOPSIS
        Parses tunnel groups from a Cisco ASA configuration.

    .DESCRIPTION
        Extracts all 'tunnel-group' definitions from an ASA running configuration
        and returns them as PowerShell objects with type, IKE version, and PSK info.

    .PARAMETER ConfigPath
        Path to the ASA configuration file.

    .PARAMETER Config
        Raw ASA configuration content as a string.

    .PARAMETER PeerIP
        Filter results by peer IP address. Supports wildcards (*).

    .PARAMETER Type
        Filter results by tunnel group type (e.g., ipsec-l2l, remote-access).

    .PARAMETER S2SOnly
        If specified, returns only site-to-site (ipsec-l2l) tunnel groups.

    .EXAMPLE
        Get-ASATunnelGroup -ConfigPath "config.txt"

    .EXAMPLE
        Get-ASATunnelGroup -ConfigPath "config.txt" -S2SOnly

    .EXAMPLE
        Get-ASATunnelGroup -ConfigPath "config.txt" -PeerIP "203.0.113.*"

    .OUTPUTS
        PSCustomObject with properties: PeerIP, Type, IKEVersion, PSK
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$ConfigPath,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [string]$Config,

        [Parameter(Mandatory = $false)]
        [string]$PeerIP,

        [Parameter(Mandatory = $false)]
        [string]$Type,

        [Parameter(Mandatory = $false)]
        [switch]$S2SOnly
    )

    process {
        $configContent = Get-ASAConfigContent -ConfigPath $ConfigPath -Config $Config

        $tunnelGroupTypes = $configContent -split '\r?\n' | Where-Object { $_ -match '^tunnel-group \S+ type' }

        $tunnelGroups = @()

        foreach ($line in $tunnelGroupTypes) {
            if ($line -match '^tunnel-group (\S+) type (\S+)$') {
                $peer = $matches[1]
                $tgType = $matches[2]

                $ipsecAttrPattern = "(?m)^tunnel-group $([regex]::Escape($peer)) ipsec-attributes\r?\n(?: .+\r?\n?)+"
                $ipsecAttrMatch = [regex]::Match($configContent, $ipsecAttrPattern)

                $ikeVersion = $null
                $psk = $false

                if ($ipsecAttrMatch.Success) {
                    $attrBlock = $ipsecAttrMatch.Value
                    if ($attrBlock -match 'ikev2') { $ikeVersion = 'ikev2' }
                    elseif ($attrBlock -match 'ikev1') { $ikeVersion = 'ikev1' }
                    if ($attrBlock -match 'pre-shared-key') { $psk = $true }
                }

                $tunnelGroups += [PSCustomObject]@{
                    PeerIP     = $peer
                    Type       = $tgType
                    IKEVersion = $ikeVersion
                    PSK        = $psk
                }
            }
        }

        # Apply filters
        if ($PeerIP) {
            $tunnelGroups = $tunnelGroups | Where-Object { $_.PeerIP -like $PeerIP }
        }

        if ($Type) {
            $tunnelGroups = $tunnelGroups | Where-Object { $_.Type -eq $Type }
        }

        if ($S2SOnly) {
            $tunnelGroups = $tunnelGroups | Where-Object { $_.Type -eq 'ipsec-l2l' }
        }

        $tunnelGroups
    }
}
