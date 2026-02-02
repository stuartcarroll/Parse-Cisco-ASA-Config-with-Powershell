function Get-ASAConfigContent {
    <#
    .SYNOPSIS
        Internal helper function to load ASA configuration content.

    .DESCRIPTION
        Normalizes config loading from either a file path or raw string content.
        This is a private function used by all public cmdlets.

    .PARAMETER ConfigPath
        Path to the ASA configuration file.

    .PARAMETER Config
        Raw ASA configuration content as a string.

    .OUTPUTS
        System.String - The raw configuration content.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ConfigPath,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [string]$Config
    )

    process {
        # If Config is provided via pipeline or parameter, use it
        if ($Config) {
            return $Config
        }

        # If ConfigPath is provided, read the file
        if ($ConfigPath) {
            if (-not (Test-Path -Path $ConfigPath)) {
                throw "Configuration file not found: $ConfigPath"
            }

            try {
                $content = Get-Content -Path $ConfigPath -Raw -ErrorAction Stop
                return $content
            }
            catch {
                throw "Failed to read configuration file: $_"
            }
        }

        throw "Either -ConfigPath or -Config parameter must be provided."
    }
}
