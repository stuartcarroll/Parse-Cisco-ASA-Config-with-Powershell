function Get-ASANetworkGroup {
    <#
    .SYNOPSIS
        Parses network object-groups from a Cisco ASA configuration.

    .DESCRIPTION
        Extracts all 'object-group network' definitions from an ASA running configuration
        and returns them as PowerShell objects with their members.

    .PARAMETER ConfigPath
        Path to the ASA configuration file.

    .PARAMETER Config
        Raw ASA configuration content as a string.

    .PARAMETER Name
        Filter results by group name. Supports wildcards (*).

    .PARAMETER ExpandMembers
        If specified, returns members as an array instead of comma-separated string.

    .EXAMPLE
        Get-ASANetworkGroup -ConfigPath "config.txt"

    .EXAMPLE
        Get-ASANetworkGroup -ConfigPath "config.txt" -Name "DMZ*"

    .OUTPUTS
        PSCustomObject with properties: Name, Members, MemberCount
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$ConfigPath,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [string]$Config,

        [Parameter(Mandatory = $false)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [switch]$ExpandMembers
    )

    process {
        $configContent = Get-ASAConfigContent -ConfigPath $ConfigPath -Config $Config

        $networkGroupPattern = '(?m)^object-group network (\S+)\r?\n(?: .+\r?\n?)+'
        $networkGroupMatches = [regex]::Matches($configContent, $networkGroupPattern)

        $networkGroups = @()

        foreach ($match in $networkGroupMatches) {
            $block = $match.Value
            $groupName = ($block -split '\r?\n')[0] -replace '^object-group network ', ''

            $members = @()
            $lines = ($block -split '\r?\n' | Select-Object -Skip 1) | ForEach-Object { $_.Trim() }

            foreach ($line in $lines) {
                if ($line -match '^network-object object (\S+)') {
                    $members += "object:$($matches[1])"
                }
                elseif ($line -match '^network-object host (\S+)') {
                    $members += "host:$($matches[1])"
                }
                elseif ($line -match '^network-object (\S+) (\S+)') {
                    $members += "subnet:$($matches[1])/$($matches[2])"
                }
                elseif ($line -match '^group-object (\S+)') {
                    $members += "group:$($matches[1])"
                }
            }

            $networkGroups += [PSCustomObject]@{
                Name        = $groupName
                Members     = if ($ExpandMembers) { $members } else { $members -join ', ' }
                MemberCount = $members.Count
            }
        }

        # Apply filters
        if ($Name) {
            $networkGroups = $networkGroups | Where-Object { $_.Name -like $Name }
        }

        $networkGroups
    }
}
