function Get-ASAIcmpGroup {
    <#
    .SYNOPSIS
        Parses ICMP type object-groups from a Cisco ASA configuration.

    .DESCRIPTION
        Extracts all 'object-group icmp-type' definitions from an ASA running configuration
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
        Get-ASAIcmpGroup -ConfigPath "config.txt"

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

        $icmpGroupPattern = '(?m)^object-group icmp-type (\S+)\r?\n(?: .+\r?\n?)+'
        $icmpGroupMatches = [regex]::Matches($configContent, $icmpGroupPattern)

        $icmpGroups = @()

        foreach ($match in $icmpGroupMatches) {
            $block = $match.Value
            $groupName = ($block -split '\r?\n')[0] -replace '^object-group icmp-type ', ''

            $members = @()
            $lines = ($block -split '\r?\n' | Select-Object -Skip 1) | ForEach-Object { $_.Trim() }

            foreach ($line in $lines) {
                if ($line -match '^icmp-object (\S+)') {
                    $members += $matches[1]
                }
            }

            $icmpGroups += [PSCustomObject]@{
                Name        = $groupName
                Members     = if ($ExpandMembers) { $members } else { $members -join ', ' }
                MemberCount = $members.Count
            }
        }

        # Apply filters
        if ($Name) {
            $icmpGroups = $icmpGroups | Where-Object { $_.Name -like $Name }
        }

        $icmpGroups
    }
}
