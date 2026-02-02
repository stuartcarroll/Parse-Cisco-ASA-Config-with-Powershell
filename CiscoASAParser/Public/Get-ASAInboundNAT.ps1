function Get-ASAInboundNAT {
    <#
    .SYNOPSIS
        Finds inbound NAT rules that have corresponding ACL permits.

    .DESCRIPTION
        Correlates static NAT rules with ACL permit entries to show which internal
        hosts are actually accessible from the internet. A host needs BOTH a static
        NAT (to translate the public IP to internal) AND an ACL permit (to allow
        the traffic through) to be reachable.

    .PARAMETER ConfigPath
        Path to the ASA configuration file.

    .PARAMETER Config
        Raw ASA configuration content as a string.

    .PARAMETER ACLName
        Name of the ACL to check for permits. Defaults to "outside_access_in".

    .PARAMETER InternalIP
        Filter results by internal IP address. Supports wildcards (*).

    .PARAMETER PublicIP
        Filter results by public/mapped IP address. Supports wildcards (*).

    .EXAMPLE
        Get-ASAInboundNAT -ConfigPath "config.txt"

        Returns all inbound NAT rules that have ACL permits.

    .EXAMPLE
        Get-ASAInboundNAT -ConfigPath "config.txt" -InternalIP "10.200.20.*"

        Returns inbound NAT rules for hosts in the 10.200.20.x subnet.

    .EXAMPLE
        Get-ASAInboundNAT -ConfigPath "config.txt" -ACLName "dmz_access_in"

        Uses a different ACL name instead of the default outside_access_in.

    .OUTPUTS
        PSCustomObject with properties:
        - ObjectName: NAT object name (or null for Twice NAT)
        - InternalIP: Real/internal IP address
        - PublicIP: Mapped/public IP address
        - ACLName: ACL that permits the traffic
        - Protocol: Permitted protocol (tcp, udp, etc.)
        - Service: Permitted port/service
        - SourceFilter: Who can connect (any, specific IP, etc.)
        - MatchType: How ACL references NAT (object-reference, direct-ip, group-member)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$ConfigPath,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [string]$Config,

        [Parameter(Mandatory = $false)]
        [string]$ACLName = "outside_access_in",

        [Parameter(Mandatory = $false)]
        [string]$InternalIP,

        [Parameter(Mandatory = $false)]
        [string]$PublicIP
    )

    process {
        $configContent = Get-ASAConfigContent -ConfigPath $ConfigPath -Config $Config

        # Get all static NAT rules
        $staticNats = Get-ASANatRule -Config $configContent |
            Where-Object { $_.SourceType -eq 'static' }

        # Get permit ACLs for the specified ACL name
        $permitAcls = Get-ASAAccessList -Config $configContent |
            Where-Object { $_.ACLName -eq $ACLName -and $_.Action -eq 'permit' }

        # Get network groups for group-member matching
        $networkGroups = Get-ASANetworkGroup -Config $configContent

        $results = @()

        foreach ($nat in $staticNats) {
            $natObjectName = $nat.ObjectName
            $natPublicIP = $nat.MappedSource
            $natInternalIP = $nat.RealSource

            foreach ($acl in $permitAcls) {
                $matchType = $null
                $isMatch = $false

                # Match Type A: Object Reference
                # ACL destination = "object:SSSMPR-FEP1" matches NAT ObjectName
                if ($acl.Destination -match '^object:(.+)$') {
                    $aclObjectName = $matches[1]
                    if ($natObjectName -and $aclObjectName -eq $natObjectName) {
                        $isMatch = $true
                        $matchType = 'object-reference'
                    }
                }

                # Match Type B: Direct IP
                # ACL destination = "host:81.144.153.67" matches NAT MappedSource
                if (-not $isMatch -and $acl.Destination -match '^host:(.+)$') {
                    $aclHostIP = $matches[1]
                    if ($natPublicIP -and $aclHostIP -eq $natPublicIP) {
                        $isMatch = $true
                        $matchType = 'direct-ip'
                    }
                }

                # Match Type C: Group Member
                # ACL destination = "group:ServerGroup" - check if NAT object is a member
                if (-not $isMatch -and $acl.Destination -match '^group:(.+)$') {
                    $groupName = $matches[1]
                    $group = $networkGroups | Where-Object { $_.Name -eq $groupName }

                    if ($group -and $group.Members) {
                        foreach ($member in $group.Members) {
                            # Check if NAT object is directly in the group
                            if ($member -match '^object:(.+)$' -and $matches[1] -eq $natObjectName) {
                                $isMatch = $true
                                $matchType = 'group-member'
                                break
                            }
                            # Check if NAT public IP matches a host in the group
                            if ($member -match '^host:(.+)$' -and $matches[1] -eq $natPublicIP) {
                                $isMatch = $true
                                $matchType = 'group-member'
                                break
                            }
                        }
                    }
                }

                if ($isMatch) {
                    $results += [PSCustomObject]@{
                        ObjectName   = $natObjectName
                        InternalIP   = $natInternalIP
                        PublicIP     = $natPublicIP
                        ACLName      = $acl.ACLName
                        Protocol     = $acl.Protocol
                        Service      = $acl.Service
                        SourceFilter = $acl.Source
                        MatchType    = $matchType
                    }
                }
            }
        }

        # Apply filters
        if ($InternalIP) {
            $results = $results | Where-Object { $_.InternalIP -like $InternalIP }
        }

        if ($PublicIP) {
            $results = $results | Where-Object { $_.PublicIP -like $PublicIP }
        }

        $results
    }
}
