function Get-ASAServiceGroup {
    <#
    .SYNOPSIS
        Parses service object-groups from a Cisco ASA configuration.

    .DESCRIPTION
        Extracts all 'object-group service' definitions from an ASA running configuration
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
        Get-ASAServiceGroup -ConfigPath "config.txt"

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

        $serviceGroupPattern = '(?m)^object-group service (\S+)\r?\n(?: .+\r?\n?)+'
        $serviceGroupMatches = [regex]::Matches($configContent, $serviceGroupPattern)

        $serviceGroups = @()

        foreach ($match in $serviceGroupMatches) {
            $block = $match.Value
            $groupName = ($block -split '\r?\n')[0] -replace '^object-group service ', ''

            $members = @()
            $lines = ($block -split '\r?\n' | Select-Object -Skip 1) | ForEach-Object { $_.Trim() }

            foreach ($line in $lines) {
                # service-object tcp destination eq https
                if ($line -match '^service-object (\S+) destination eq (\S+)') {
                    $members += "$($matches[1])/$($matches[2])"
                }
                # service-object tcp destination range 8000 8100
                elseif ($line -match '^service-object (\S+) destination range (\S+) (\S+)') {
                    $members += "$($matches[1])/$($matches[2])-$($matches[3])"
                }
                # service-object object ServiceName
                elseif ($line -match '^service-object object (\S+)') {
                    $members += "object:$($matches[1])"
                }
                # port-object eq https
                elseif ($line -match '^port-object eq (\S+)') {
                    $members += "port:$($matches[1])"
                }
                # port-object range 8000 8100
                elseif ($line -match '^port-object range (\S+) (\S+)') {
                    $members += "port:$($matches[1])-$($matches[2])"
                }
                # group-object GroupName
                elseif ($line -match '^group-object (\S+)') {
                    $members += "group:$($matches[1])"
                }
            }

            $serviceGroups += [PSCustomObject]@{
                Name        = $groupName
                Members     = if ($ExpandMembers) { $members } else { $members -join ', ' }
                MemberCount = $members.Count
            }
        }

        # Apply filters
        if ($Name) {
            $serviceGroups = $serviceGroups | Where-Object { $_.Name -like $Name }
        }

        $serviceGroups
    }
}
