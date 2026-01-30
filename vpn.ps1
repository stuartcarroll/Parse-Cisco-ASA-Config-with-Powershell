$ikePolicyPattern = '(?m)^crypto ikev2 policy (\d+)\r?\n(?: .+\r?\n?)+'
$ikePolicyMatches = [regex]::Matches($config, $ikePolicyPattern)

$ikePolicies = @()

foreach ($match in $ikePolicyMatches) {
    $block = $match.Value
    $priority = ($block -split '\r?\n')[0] -replace '^crypto ikev2 policy ', ''
    
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
        if ($line -match '^lifetime seconds (\d+)$') { $lifetime = $matches[1] }
    }
    
    $ikePolicies += [PSCustomObject]@{
        Priority   = $priority
        Encryption = $encryption
        Integrity  = $integrity
        DHGroup    = $group
        PRF        = $prf
        Lifetime   = $lifetime
    }
}

$transformSetLines = $config -split '\r?\n' | Where-Object { $_ -match '^crypto ipsec ikev1 transform-set' }

$transformSets = @()

foreach ($line in $transformSetLines) {
    if ($line -match '^crypto ipsec ikev1 transform-set (\S+) (.+)$') {
        $name = $matches[1]
        $remainder = $matches[2]
        
        $mode = 'tunnel'
        if ($remainder -match 'mode transport') {
            $mode = 'transport'
            $remainder = $remainder -replace '\s*mode transport\s*', ' '
        }
        
        $transforms = $remainder.Trim() -split '\s+'
        
        $transformSets += [PSCustomObject]@{
            Name       = $name
            Transforms = $transforms -join ', '
            Mode       = $mode
        }
    }
}

$tunnelGroupTypes = $config -split '\r?\n' | Where-Object { $_ -match '^tunnel-group \S+ type' }

$tunnelGroups = @()

foreach ($line in $tunnelGroupTypes) {
    if ($line -match '^tunnel-group (\S+) type (\S+)$') {
        $peerIP = $matches[1]
        $type = $matches[2]
        
        # Get ipsec-attributes block for this peer
        $ipsecAttrPattern = "(?m)^tunnel-group $([regex]::Escape($peerIP)) ipsec-attributes\r?\n(?: .+\r?\n?)+"
        $ipsecAttrMatch = [regex]::Match($config, $ipsecAttrPattern)
        
        $ikeVersion = $null
        $psk = $false
        
        if ($ipsecAttrMatch.Success) {
            $attrBlock = $ipsecAttrMatch.Value
            if ($attrBlock -match 'ikev2') { $ikeVersion = 'ikev2' }
            elseif ($attrBlock -match 'ikev1') { $ikeVersion = 'ikev1' }
            if ($attrBlock -match 'pre-shared-key') { $psk = $true }
        }
        
        $tunnelGroups += [PSCustomObject]@{
            PeerIP     = $peerIP
            Type       = $type
            IKEVersion = $ikeVersion
            PSK        = $psk
        }
    }
}

$cryptoMapLines = $config -split '\r?\n' | Where-Object { $_ -match '^crypto map \S+ \d+' }

$cryptoMapEntries = @{}

foreach ($line in $cryptoMapLines) {
    if ($line -match '^crypto map (\S+) (\d+) (.+)$') {
        $mapName = $matches[1]
        $sequence = $matches[2]
        $setting = $matches[3]
        
        $key = "$mapName-$sequence"
        
        if (-not $cryptoMapEntries.ContainsKey($key)) {
            $cryptoMapEntries[$key] = [PSCustomObject]@{
                MapName       = $mapName
                Sequence      = $sequence
                Peer          = $null
                ACL           = $null
                TransformSets = $null
                PFS           = $null
                SALifetime    = $null
                SALifetimeKB  = $null
                NATTDisable   = $false
            }
        }
        
        $entry = $cryptoMapEntries[$key]
        
        if ($setting -match '^match address (\S+)') { $entry.ACL = $matches[1] }
        if ($setting -match '^set peer (\S+)') { $entry.Peer = $matches[1] }
        if ($setting -match '^set ikev1 transform-set (.+)$') { $entry.TransformSets = $matches[1] }
        if ($setting -match '^set ikev2 ipsec-proposal (.+)$') { $entry.TransformSets = $matches[1] }
        if ($setting -match '^set pfs (\S+)') { $entry.PFS = $matches[1] }
        if ($setting -match '^set security-association lifetime seconds (\d+)') { $entry.SALifetime = $matches[1] }
        if ($setting -match '^set security-association lifetime kilobytes (\d+)') { $entry.SALifetimeKB = $matches[1] }
        if ($setting -match '^set nat-t-disable') { $entry.NATTDisable = $true }
    }
}

$cryptoMaps = $cryptoMapEntries.Values | Sort-Object MapName, { [int]$_.Sequence }

Write-Host "IKE Policies:" -ForegroundColor Green
$ikePolicies | Format-Table -AutoSize

Write-Host "Transform Sets:" -ForegroundColor Green
$transformSets | Format-Table -AutoSize

Write-Host "Tunnel Groups:" -ForegroundColor Green
$tunnelGroups | Format-Table -AutoSize

Write-Host "Crypto Maps:" -ForegroundColor Green
$cryptoMaps | Format-Table -AutoSize


# Filter to S2S only (exclude remote-access)
$s2sTunnels = $tunnelGroups | Where-Object { $_.Type -eq 'ipsec-l2l' }

# Combine everything per peer
$vpnConfigs = @()

foreach ($cryptoMap in $cryptoMaps) {
    $peer = $cryptoMap.Peer
    $tunnelGroup = $tunnelGroups | Where-Object { $_.PeerIP -eq $peer }
    
    $vpnConfigs += [PSCustomObject]@{
        Name          = "VPN-$peer"
        Peer          = $peer
        IKEVersion    = $tunnelGroup.IKEVersion
        ACL           = $cryptoMap.ACL
        TransformSets = $cryptoMap.TransformSets
        PFS           = $cryptoMap.PFS
        SALifetime    = $cryptoMap.SALifetime
        NATTDisable   = $cryptoMap.NATTDisable
    }
}

# ============================================
# OUTPUT
# ============================================



# Filter to S2S only (exclude remote-access)
$s2sTunnels = $tunnelGroups | Where-Object { $_.Type -eq 'ipsec-l2l' }

# Combine everything per peer
$vpnConfigs = @()

foreach ($cryptoMap in $cryptoMaps) {
    $peer = $cryptoMap.Peer
    $tunnelGroup = $tunnelGroups | Where-Object { $_.PeerIP -eq $peer }
    
    $vpnConfigs += [PSCustomObject]@{
        Name          = "VPN-$peer"
        Peer          = $peer
        IKEVersion    = $tunnelGroup.IKEVersion
        ACL           = $cryptoMap.ACL
        TransformSets = $cryptoMap.TransformSets
        PFS           = $cryptoMap.PFS
        SALifetime    = $cryptoMap.SALifetime
        NATTDisable   = $cryptoMap.NATTDisable
    }
}

# ============================================
# OUTPUT
# ============================================

Write-Host "IKE Policies:" -ForegroundColor Green
$ikePolicies | Format-Table -AutoSize

Write-Host "Transform Sets:" -ForegroundColor Green
$transformSets | Format-Table -AutoSize

Write-Host "Tunnel Groups (S2S only):" -ForegroundColor Green
$s2sTunnels | Format-Table -AutoSize

Write-Host "Crypto Maps:" -ForegroundColor Green
$cryptoMaps | Format-Table -AutoSize

Write-Host "Unified VPN Configs:" -ForegroundColor Green
$vpnConfigs | Format-Table -AutoSize