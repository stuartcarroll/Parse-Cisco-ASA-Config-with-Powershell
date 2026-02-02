function Resolve-ASAObject {
    <#
    .SYNOPSIS
        Resolves an ASA object or group name to its IP address, subnet, or members.

    .DESCRIPTION
        Looks up a network object, network group, service object, or service group
        by name and returns its resolved value. For network objects, returns the
        IP/subnet. For groups, returns the members (optionally expanded recursively).

    .PARAMETER ConfigPath
        Path to the ASA configuration file.

    .PARAMETER Config
        Raw ASA configuration content as a string.

    .PARAMETER Name
        The object or group name to resolve. Accepts pipeline input.
        Supports wildcards (*) for searching multiple objects.

    .PARAMETER Recurse
        If specified, recursively resolves nested group references to their
        final IP addresses/subnets.

    .PARAMETER ObjectType
        Limit search to specific object types: Network, Service, or All (default).

    .EXAMPLE
        Resolve-ASAObject -ConfigPath "config.txt" -Name "Web-Server-01"

        Resolves a single object by name.

    .EXAMPLE
        Resolve-ASAObject -ConfigPath "config.txt" -Name "DMZ*"

        Finds all objects/groups matching the pattern.

    .EXAMPLE
        "Web-Server", "DB-Server" | Resolve-ASAObject -ConfigPath "config.txt"

        Resolves multiple objects via pipeline.

    .EXAMPLE
        Resolve-ASAObject -ConfigPath "config.txt" -Name "Internal-Servers" -Recurse

        Recursively resolves a group to all its member IPs/subnets.

    .EXAMPLE
        Get-ASAAccessList -ConfigPath "config.txt" |
            Where-Object { $_.Source -match '^object:(.+)$' } |
            ForEach-Object { Resolve-ASAObject -ConfigPath "config.txt" -Name ($_.Source -replace '^object:','') }

        Resolves all object references from ACLs.

    .OUTPUTS
        PSCustomObject with properties:
        - Name: Object/group name
        - Type: network-object, network-group, service-object, service-group
        - Value: Resolved IP address, subnet, or FQDN (for objects)
        - Members: Array of members (for groups)
        - ResolvedMembers: Recursively resolved values (if -Recurse specified)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 1)]
        [string]$ConfigPath,

        [Parameter(Mandatory = $false)]
        [string]$Config,

        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [switch]$Recurse,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Network', 'Service', 'All')]
        [string]$ObjectType = 'All'
    )

    begin {
        # Cache the parsed objects for pipeline efficiency
        if ($ConfigPath) {
            $script:configContent = Get-ASAConfigContent -ConfigPath $ConfigPath
        }
        elseif ($Config) {
            $script:configContent = $Config
        }

        if ($ObjectType -eq 'All' -or $ObjectType -eq 'Network') {
            $script:networkObjects = Get-ASANetworkObject -Config $script:configContent
            $script:networkGroups = Get-ASANetworkGroup -Config $script:configContent -ExpandMembers
        }

        if ($ObjectType -eq 'All' -or $ObjectType -eq 'Service') {
            $script:serviceObjects = Get-ASAServiceObject -Config $script:configContent
            $script:serviceGroups = Get-ASAServiceGroup -Config $script:configContent -ExpandMembers
        }
    }

    process {
        $results = @()

        # Search network objects
        if ($ObjectType -eq 'All' -or $ObjectType -eq 'Network') {
            $matchedNetObjs = $script:networkObjects | Where-Object { $_.Name -like $Name }
            foreach ($obj in $matchedNetObjs) {
                $results += [PSCustomObject]@{
                    Name            = $obj.Name
                    Type            = 'network-object'
                    Value           = $obj.Value
                    Members         = $null
                    ResolvedMembers = $null
                    Definition      = $obj.Definition
                }
            }

            # Search network groups
            $matchedNetGroups = $script:networkGroups | Where-Object { $_.Name -like $Name }
            foreach ($grp in $matchedNetGroups) {
                $resolvedMembers = $null

                if ($Recurse -and $grp.Members) {
                    $resolvedMembers = @()
                    foreach ($member in $grp.Members) {
                        if ($member -match '^object:(.+)$') {
                            $resolved = Resolve-ASAObject -Config $script:configContent -Name $matches[1] -ObjectType Network
                            if ($resolved) {
                                $resolvedMembers += $resolved.Value
                            }
                        }
                        elseif ($member -match '^group:(.+)$') {
                            $resolved = Resolve-ASAObject -Config $script:configContent -Name $matches[1] -ObjectType Network -Recurse
                            if ($resolved -and $resolved.ResolvedMembers) {
                                $resolvedMembers += $resolved.ResolvedMembers
                            }
                            elseif ($resolved -and $resolved.Members) {
                                $resolvedMembers += $resolved.Members
                            }
                        }
                        elseif ($member -match '^(host|subnet):(.+)$') {
                            $resolvedMembers += $matches[2]
                        }
                        else {
                            $resolvedMembers += $member
                        }
                    }
                }

                $results += [PSCustomObject]@{
                    Name            = $grp.Name
                    Type            = 'network-group'
                    Value           = $null
                    Members         = $grp.Members
                    ResolvedMembers = $resolvedMembers
                    Definition      = $null
                }
            }
        }

        # Search service objects
        if ($ObjectType -eq 'All' -or $ObjectType -eq 'Service') {
            $matchedSvcObjs = $script:serviceObjects | Where-Object { $_.Name -like $Name }
            foreach ($obj in $matchedSvcObjs) {
                $value = if ($obj.Protocol -and $obj.DestPort) {
                    "$($obj.Protocol)/$($obj.DestPort)"
                }
                elseif ($obj.Protocol) {
                    $obj.Protocol
                }
                else {
                    $null
                }

                $results += [PSCustomObject]@{
                    Name            = $obj.Name
                    Type            = 'service-object'
                    Value           = $value
                    Members         = $null
                    ResolvedMembers = $null
                    Definition      = $obj.Description
                }
            }

            # Search service groups
            $matchedSvcGroups = $script:serviceGroups | Where-Object { $_.Name -like $Name }
            foreach ($grp in $matchedSvcGroups) {
                $results += [PSCustomObject]@{
                    Name            = $grp.Name
                    Type            = 'service-group'
                    Value           = $null
                    Members         = $grp.Members
                    ResolvedMembers = $null
                    Definition      = $null
                }
            }
        }

        # Output results
        if ($results.Count -eq 0) {
            Write-Warning "Object '$Name' not found."
        }
        else {
            $results
        }
    }
}
