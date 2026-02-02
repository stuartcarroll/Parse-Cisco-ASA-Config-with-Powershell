#Requires -Version 5.1

<#
.SYNOPSIS
    CiscoASAParser - PowerShell module for parsing Cisco ASA firewall configurations.

.DESCRIPTION
    This module provides cmdlets for extracting and parsing various configuration
    elements from Cisco ASA firewall "show running-config" output including:
    - Network Objects (hosts, subnets, ranges, FQDNs)
    - Service Objects
    - Object Groups (network, service, ICMP)
    - Access Lists
    - NAT Rules
    - VPN Configurations (IKE policies, transform sets, tunnel groups, crypto maps)

.NOTES
    Author: Stuart Carroll
    Company: Coffee Cup Solutions
    Version: 1.0.0
#>

# Get the module's root directory
$ModuleRoot = $PSScriptRoot

# Import private functions
$PrivatePath = Join-Path $ModuleRoot "Private"
$PrivateFunctions = @(Get-ChildItem -LiteralPath $PrivatePath -Filter "*.ps1" -ErrorAction SilentlyContinue)
foreach ($Function in $PrivateFunctions) {
    try {
        . $Function.FullName
    }
    catch {
        Write-Error "Failed to import private function $($Function.FullName): $_"
    }
}

# Import public functions
$PublicPath = Join-Path $ModuleRoot "Public"
$PublicFunctions = @(Get-ChildItem -LiteralPath $PublicPath -Filter "*.ps1" -ErrorAction SilentlyContinue)
foreach ($Function in $PublicFunctions) {
    try {
        . $Function.FullName
    }
    catch {
        Write-Error "Failed to import public function $($Function.FullName): $_"
    }
}

# Export public functions
Export-ModuleMember -Function $PublicFunctions.BaseName
