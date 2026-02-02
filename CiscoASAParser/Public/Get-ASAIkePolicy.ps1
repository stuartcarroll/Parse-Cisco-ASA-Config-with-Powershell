function Get-ASAIkePolicy {
    <#
    .SYNOPSIS
        Parses IKEv2 policies (Phase 1) from a Cisco ASA configuration.

    .DESCRIPTION
        Extracts all 'crypto ikev2 policy' definitions from an ASA running configuration
        and returns them as PowerShell objects with encryption, integrity, DH group,
        PRF, and lifetime settings.

    .PARAMETER ConfigPath
        Path to the ASA configuration file.

    .PARAMETER Config
        Raw ASA configuration content as a string.

    .PARAMETER Priority
        Filter results by policy priority number.

    .EXAMPLE
        Get-ASAIkePolicy -ConfigPath "config.txt"

    .EXAMPLE
        Get-ASAIkePolicy -ConfigPath "config.txt" -Priority 10

    .OUTPUTS
        PSCustomObject with properties: Priority, Encryption, Integrity, DHGroup, PRF, Lifetime
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$ConfigPath,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [string]$Config,

        [Parameter(Mandatory = $false)]
        [int]$Priority
    )

    process {
        $configContent = Get-ASAConfigContent -ConfigPath $ConfigPath -Config $Config

        $ikePolicyPattern = '(?m)^crypto ikev2 policy (\d+)\r?\n(?: .+\r?\n?)+'
        $ikePolicyMatches = [regex]::Matches($configContent, $ikePolicyPattern)

        $ikePolicies = @()

        foreach ($match in $ikePolicyMatches) {
            $block = $match.Value
            $priorityValue = ($block -split '\r?\n')[0] -replace '^crypto ikev2 policy ', ''

            $encryption = $null
            $integrity = $null
            $group = $null
            $prf = $null
            $lifetime = $null

            $lines = ($block -split '\r?\n' | Select-Object -Skip 1) | ForEach-Object { $_.Trim() }

            foreach ($line in $lines) {
                if ($line -match '^encryption (.+)$') { $encryption = $matches[1] }
                if ($line -match '^integrity (.+)$') { $integrity = $matches[1] }
                if ($line -match '^group (.+)$') { $group = $matches[1] }
                if ($line -match '^prf (.+)$') { $prf = $matches[1] }
                if ($line -match '^lifetime seconds (\d+)$') { $lifetime = [int]$matches[1] }
            }

            $ikePolicies += [PSCustomObject]@{
                Priority   = [int]$priorityValue
                Encryption = $encryption
                Integrity  = $integrity
                DHGroup    = $group
                PRF        = $prf
                Lifetime   = $lifetime
            }
        }

        # Apply filters
        if ($Priority) {
            $ikePolicies = $ikePolicies | Where-Object { $_.Priority -eq $Priority }
        }

        $ikePolicies | Sort-Object Priority
    }
}
