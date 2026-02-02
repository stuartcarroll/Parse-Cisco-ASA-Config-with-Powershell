function Get-ASAAccessList {
    <#
    .SYNOPSIS
        Parses access-list entries from a Cisco ASA configuration.

    .DESCRIPTION
        Extracts all 'access-list extended' entries from an ASA running configuration
        and returns them as PowerShell objects with parsed source, destination,
        protocol, and service information.

    .PARAMETER ConfigPath
        Path to the ASA configuration file.

    .PARAMETER Config
        Raw ASA configuration content as a string.

    .PARAMETER ACLName
        Filter results by access-list name. Supports wildcards (*).

    .PARAMETER Action
        Filter results by action (permit or deny).

    .PARAMETER ActiveOnly
        If specified, excludes inactive rules.

    .EXAMPLE
        Get-ASAAccessList -ConfigPath "config.txt"

    .EXAMPLE
        Get-ASAAccessList -ConfigPath "config.txt" -ACLName "outside_access_in"

    .EXAMPLE
        Get-ASAAccessList -ConfigPath "config.txt" -Action "permit" -ActiveOnly

    .OUTPUTS
        PSCustomObject with properties: ACLName, Action, Protocol, Source, Destination,
        ServiceGroup, Service, User, LogEnabled, Inactive
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$ConfigPath,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [string]$Config,

        [Parameter(Mandatory = $false)]
        [string]$ACLName,

        [Parameter(Mandatory = $false)]
        [ValidateSet('permit', 'deny')]
        [string]$Action,

        [Parameter(Mandatory = $false)]
        [switch]$ActiveOnly
    )

    process {
        $configContent = Get-ASAConfigContent -ConfigPath $ConfigPath -Config $Config

        $aclPattern = '(?m)^access-list (\S+) extended (permit|deny) (\S+) (.+)$'
        $aclMatches = [regex]::Matches($configContent, $aclPattern)

        $accessLists = @()

        foreach ($match in $aclMatches) {
            $aclNameValue = $match.Groups[1].Value
            $actionValue = $match.Groups[2].Value
            $protocol = $match.Groups[3].Value
            $remainder = $match.Groups[4].Value

            $source = $null
            $destination = $null
            $service = $null
            $serviceGroup = $null
            $user = $null
            $logEnabled = $false
            $inactive = $false

            # Check for log flag
            if ($remainder -match '\blog\b') {
                $logEnabled = $true
                $remainder = $remainder -replace '\s*log\s*(disable|default|debugging|notifications|informational|warnings|errors|critical|alerts|emergencies)?\s*', ' '
            }

            # Check for inactive flag
            if ($remainder -match '\binactive\b') {
                $inactive = $true
                $remainder = $remainder -replace '\s*inactive\s*', ' '
            }

            $remainder = $remainder.Trim()

            # Check if protocol is actually object-group (service group used as protocol)
            if ($protocol -eq 'object-group') {
                if ($remainder -match '^(\S+) (.+)$') {
                    $serviceGroup = $matches[1]
                    $protocol = 'object-group'
                    $remainder = $matches[2]
                }
            }

            # Check for user identity at the start
            if ($remainder -match '^user (\S+) (.+)$') {
                $user = $matches[1]
                $remainder = $matches[2]
            }

            # Parse source
            if ($remainder -match '^object-group (\S+) (.+)$') {
                $source = "group:$($matches[1])"
                $remainder = $matches[2]
            }
            elseif ($remainder -match '^object (\S+) (.+)$') {
                $source = "object:$($matches[1])"
                $remainder = $matches[2]
            }
            elseif ($remainder -match '^host (\S+) (.+)$') {
                $source = "host:$($matches[1])"
                $remainder = $matches[2]
            }
            elseif ($remainder -match '^(\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+) (.+)$') {
                $source = "subnet:$($matches[1])/$($matches[2])"
                $remainder = $matches[3]
            }
            elseif ($remainder -match '^any4 (.+)$') {
                $source = 'any4'
                $remainder = $matches[1]
            }
            elseif ($remainder -match '^any (.+)$') {
                $source = 'any'
                $remainder = $matches[1]
            }

            # Parse destination
            if ($remainder -match '^object-group (\S+)(.*)$') {
                $destination = "group:$($matches[1])"
                $remainder = $matches[2].Trim()
            }
            elseif ($remainder -match '^object (\S+)(.*)$') {
                $destination = "object:$($matches[1])"
                $remainder = $matches[2].Trim()
            }
            elseif ($remainder -match '^host (\S+)(.*)$') {
                $destination = "host:$($matches[1])"
                $remainder = $matches[2].Trim()
            }
            elseif ($remainder -match '^(\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)(.*)$') {
                $destination = "subnet:$($matches[1])/$($matches[2])"
                $remainder = $matches[3].Trim()
            }
            elseif ($remainder -match '^any4(.*)$') {
                $destination = 'any4'
                $remainder = $matches[1].Trim()
            }
            elseif ($remainder -match '^any(.*)$') {
                $destination = 'any'
                $remainder = $matches[1].Trim()
            }

            # Check for service object-group in remainder
            if ($remainder -match '^object-group (\S+)(.*)$') {
                $serviceGroup = $matches[1]
                $remainder = $matches[2].Trim()
            }

            # Whatever's left is the service/port
            $service = if ($remainder) { $remainder } else { $null }

            $accessLists += [PSCustomObject]@{
                ACLName      = $aclNameValue
                Action       = $actionValue
                Protocol     = $protocol
                Source       = $source
                Destination  = $destination
                ServiceGroup = $serviceGroup
                Service      = $service
                User         = $user
                LogEnabled   = $logEnabled
                Inactive     = $inactive
            }
        }

        # Apply filters
        if ($ACLName) {
            $accessLists = $accessLists | Where-Object { $_.ACLName -like $ACLName }
        }

        if ($Action) {
            $accessLists = $accessLists | Where-Object { $_.Action -eq $Action }
        }

        if ($ActiveOnly) {
            $accessLists = $accessLists | Where-Object { -not $_.Inactive }
        }

        $accessLists
    }
}
