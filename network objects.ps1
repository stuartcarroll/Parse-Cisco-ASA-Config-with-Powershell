# Load the running configuration from a text file
$config = Get-Content -Path "show running-config.txt" -Raw


# Regex guide: 
#   (?m) - Multiline Mode Flag
#   ^object network  - Literal Match at Line Start
#   (\S+) - Capture the Object Name
#   \r?\n - Match Newline (CRLF or LF)
#   (?: .+\r?\n?)+ - Non-Capturing Group for Indented Lines (one or more)

# Define the regex patterns
$networkpattern = '(?m)^object network (\S+)\r?\n(?: .+\r?\n?)+' 
$servicePattern = '(?m)^object service (\S+)\r?\n(?: .+\r?\n?)+'
$networkGroupPattern = '(?m)^object-group network (\S+)\r?\n(?: .+\r?\n?)+'
$serviceGroupPattern = '(?m)^object-group service (\S+)\r?\n(?: .+\r?\n?)+'
$icmpGroupPattern = '(?m)^object-group icmp-type (\S+)\r?\n(?: .+\r?\n?)+'
$aclPattern = '(?m)^access-list (\S+) extended (permit|deny) (\S+) (.+)$'
$natPattern = '(?m)^nat \((\S+),(\S+)\) source (static|dynamic) (\S+) (\S+) destination (static|dynamic) (\S+) (\S+)(.*)$'
$ikePolicyPattern = '(?m)^crypto ikev2 policy (\d+)\r?\n(?: .+\r?\n?)+'

# Get matches 
$serviceMatches = [regex]::Matches($config, $servicePattern)
$networkMatches = [regex]::Matches($config, $networkpattern)
$networkGroupMatches = [regex]::Matches($config, $networkGroupPattern)
$serviceGroupMatches = [regex]::Matches($config, $serviceGroupPattern)
$icmpGroupMatches = [regex]::Matches($config, $icmpGroupPattern)
$aclMatches = [regex]::Matches($config, $aclPattern)
$natMatches = [regex]::Matches($config, $natPattern)
$ikePolicyMatches = [regex]::Matches($config, $ikePolicyPattern)

# Parse network objects
$networkObjects = @()
foreach ($match in $networkMatches) {
    $block = $match.Value

    # extract the object name
    $name = ($block -split '\r?\n')[0] -replace '^object network ', ''
    # extract the definition lines
    $definition = ($block -split '\r?\n' | Select-Object -Skip 1) -join "`n" | ForEach-Object { $_.Trim() }

    # Determine the type of network object
    $type = switch -Regex ($definition) {
        '^host'   { 'host' }
        '^subnet' { 'subnet' }
        '^range'  { 'range' }
        '^fqdn'   { 'fqdn' }
        '^nat'    { 'nat' }
        default   { 'unknown' }
    }

    # Extract the value based on the type
    $value = switch -Regex ($definition) {
        'host (\S+)'                    { $matches[1] }
        'subnet (\S+)'                  { $matches[1] }
        'static (\S+)'                  { $matches[1] }
        'dynamic interface'             { 'interface' }
        default                         { $null }
    }

    # For NAT objects, extract source and destination zones if available
    if ($definition -match 'nat \((\S+),(\S+)\) (static|dynamic)') {
        $sourceZone = $matches[1]
        $destZone = $matches[2]
        $natType = $matches[3]
    } else {
        $sourceZone = $null
        $destZone = $null
        $natType = $null
    }

    # For service objects, extract protocol and ports if available
    if ($definition -match 'service (\S+) (\S+) (\S+)$') {
        $serviceProto = $matches[1]
        $serviceOrigPort = $matches[2]
        $serviceTransPort = $matches[3]
    } else {
        $serviceProto = $null
        $serviceOrigPort = $null
        $serviceTransPort = $null
    }

    # Create a custom object to store the parsed data
    $networkObjects += [PSCustomObject]@{
        Name            = $name
        Type            = $type
        SourceZone      = $sourceZone
        DestZone        = $destZone
        NatType         = $natType
        Value           = $value
        ServiceProto    = $serviceProto
        OriginalPort    = $serviceOrigPort
        TranslatedPort  = $serviceTransPort
        Definition      = $definition
    }
}

# Parse service objects
$serviceObjects = @()

foreach ($match in $serviceMatches) {
    $block = $match.Value
    $name = ($block -split '\r?\n')[0] -replace '^object service ', ''
    
    $lines = ($block -split '\r?\n' | Select-Object -Skip 1) | ForEach-Object { $_.Trim() }
    
    # Extract protocol and ports
    $proto = $null
    $srcPort = $null
    $dstPort = $null
    $description = $null
    
    foreach ($line in $lines) {
        if ($line -match '^service (\S+) source eq (\S+) destination eq (\S+)') {
            $proto = $matches[1]
            $srcPort = $matches[2]
            $dstPort = $matches[3]
        }
        if ($line -match '^description (.+)$') {
            $description = $matches[1]
        }
    }
    
    $serviceObjects += [PSCustomObject]@{
        Name        = $name
        Protocol    = $proto
        SourcePort  = $srcPort
        DestPort    = $dstPort
        Description = $description
    }
}

# Parse network groups
$networkGroups = @()

foreach ($match in $networkGroupMatches) {
    $block = $match.Value
    $name = ($block -split '\r?\n')[0] -replace '^object-group network ', ''
    
    $members = @()
    $lines = ($block -split '\r?\n' | Select-Object -Skip 1) | ForEach-Object { $_.Trim() }
    
    foreach ($line in $lines) {
        if ($line -match '^network-object object (\S+)') {
            $members += $matches[1]
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
        Name    = $name
        Members = $members -join ', '
    }
}

# Parse service groups
$serviceGroups = @()

foreach ($match in $serviceGroupMatches) {
    $block = $match.Value
    $name = ($block -split '\r?\n')[0] -replace '^object-group service ', ''
    
    $members = @()
    $lines = ($block -split '\r?\n' | Select-Object -Skip 1) | ForEach-Object { $_.Trim() }
    
    foreach ($line in $lines) {
        if ($line -match '^service-object (\S+) destination eq (\S+)') {
            $members += "$($matches[1])/$($matches[2])"
        }
    }
    
    $serviceGroups += [PSCustomObject]@{
        Name    = $name
        Members = $members -join ', '
    }
}

# Parse ICMP type groups
$icmpGroups = @()

foreach ($match in $icmpGroupMatches) {
    $block = $match.Value
    $name = ($block -split '\r?\n')[0] -replace '^object-group icmp-type ', ''
    
    $members = @()
    $lines = ($block -split '\r?\n' | Select-Object -Skip 1) | ForEach-Object { $_.Trim() }
    
    foreach ($line in $lines) {
        if ($line -match '^icmp-object (\S+)') {
            $members += $matches[1]
        }
    }
    
    $icmpGroups += [PSCustomObject]@{
        Name    = $name
        Members = $members -join ', '
    }
}

# Parse access-lists
$accessLists = @()

foreach ($match in $aclMatches) {
    $aclName = $match.Groups[1].Value
    $action = $match.Groups[2].Value
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
        ACLName      = $aclName
        Action       = $action
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

$natRules = @()

foreach ($match in $natMatches) {
    $sourceZone = $match.Groups[1].Value
    $destZone = $match.Groups[2].Value
    $sourceType = $match.Groups[3].Value
    $realSource = $match.Groups[4].Value
    $mappedSource = $match.Groups[5].Value
    $destType = $match.Groups[6].Value
    $realDest = $match.Groups[7].Value
    $mappedDest = $match.Groups[8].Value
    $options = $match.Groups[9].Value.Trim()
    
    # Check for no-proxy-arp
    $noProxyArp = $options -match 'no-proxy-arp'
    
    # Check for route-lookup
    $routeLookup = $options -match 'route-lookup'
    
    # Determine NAT category
    if ($realSource -eq $mappedSource -and $realDest -eq $mappedDest) {
        $natCategory = 'Identity/NoNAT'
    }
    elseif ($realSource -ne $mappedSource -and $realDest -eq $mappedDest) {
        $natCategory = 'SourceNAT'
    }
    elseif ($realSource -eq $mappedSource -and $realDest -ne $mappedDest) {
        $natCategory = 'DestNAT'
    }
    else {
        $natCategory = 'TwiceNAT'
    }
    
    $natRules += [PSCustomObject]@{
        SourceZone   = $sourceZone
        DestZone     = $destZone
        SourceType   = $sourceType
        RealSource   = $realSource
        MappedSource = $mappedSource
        DestType     = $destType
        RealDest     = $realDest
        MappedDest   = $mappedDest
        Category     = $natCategory
        NoProxyArp   = $noProxyArp
        RouteLookup  = $routeLookup
    }
}

# ============================================
# PARSE IKE POLICIES (Phase 1)
# ============================================

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

# ============================================
# PARSE TRANSFORM SETS (Phase 2 Proposals)
# ============================================


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


# ============================================
# PARSE TUNNEL GROUPS
# ============================================

$tunnelGroupTypes = $config -split '\r?\n' | Where-Object { $_ -match '^tunnel-group \S+ type' }

$tunnelGroups = @()

foreach ($line in $tunnelGroupTypes) {
    if ($line -match '^tunnel-group (\S+) type (\S+)$') {
        $peerIP = $matches[1]
        $type = $matches[2]
        
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

# ============================================
# PARSE CRYPTO MAPS
# ============================================

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

# ============================================
# UNIFIED VPN VIEW (S2S only)
# ============================================

$vpnConfigs = @()

foreach ($cryptoMap in $cryptoMaps) {
    $peer = $cryptoMap.Peer
    $tunnelGroup = $tunnelGroups | Where-Object { $_.PeerIP -eq $peer }
    
    if ($tunnelGroup.Type -ne 'ipsec-l2l') { continue }
    
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
# RESOLVE PHASE 2 SELECTORS
# ============================================

function Resolve-ObjectToSubnet {
    param($objectName)
    
    $obj = $networkObjects | Where-Object { $_.Name -eq $objectName }
    if ($obj) {
        $def = $obj.Definition
        if ($def -match 'host (\S+)') { return "$($matches[1])/32" }
        if ($def -match 'subnet (\S+) (\S+)') { return "$($matches[1]) $($matches[2])" }
        return $def
    }
    
    $grp = $networkGroups | Where-Object { $_.Name -eq $objectName }
    if ($grp) { return $grp.Members }
    
    return $objectName
}

$phase2Selectors = @()

foreach ($vpn in $vpnConfigs) {
    $aclName = $vpn.ACL
    $aclEntries = $accessLists | Where-Object { $_.ACLName -eq $aclName }
    
    foreach ($entry in $aclEntries) {
        $localNet = $null
        $remoteNet = $null
        
        if ($entry.Source -match '^object:(.+)$') {
            $localNet = Resolve-ObjectToSubnet $matches[1]
        }
        elseif ($entry.Source -match '^group:(.+)$') {
            $localNet = Resolve-ObjectToSubnet $matches[1]
        }
        elseif ($entry.Source -match '^subnet:(.+)$') {
            $localNet = $matches[1]
        }
        
        if ($entry.Destination -match '^object:(.+)$') {
            $remoteNet = Resolve-ObjectToSubnet $matches[1]
        }
        elseif ($entry.Destination -match '^group:(.+)$') {
            $remoteNet = Resolve-ObjectToSubnet $matches[1]
        }
        elseif ($entry.Destination -match '^subnet:(.+)$') {
            $remoteNet = $matches[1]
        }
        
        $phase2Selectors += [PSCustomObject]@{
            Peer      = $vpn.Peer
            VPNName   = $vpn.Name
            LocalNet  = $localNet
            RemoteNet = $remoteNet
        }
    }
}



#Count objects parsed
Write-Host "Parsed $($networkObjects.Count) network objects."
Write-Host "Parsed $($serviceObjects.Count) service objects."
Write-Host "Parsed $($networkGroups.Count) network groups."
Write-Host "Parsed $($serviceGroups.Count) service groups."
Write-Host "Parsed $($icmpGroups.Count) ICMP type groups."
Write-Host "Parsed $($accessLists.Count) access-list entries."
Write-Host "Parsed $($natRules.Count) NAT rules."
Write-Host "Parsed $($ikePolicies.Count) IKE policies."
Write-Host "Parsed $($transformSets.Count) transform sets."
Write-Host "Parsed $($tunnelGroups.Count) tunnel groups."
Write-Host "Parsed $($cryptoMaps.Count) crypto map entries."



# Output the parsed objects
write-Host "`Network Objects:"  -ForegroundColor Green
$networkObjects | Format-Table -AutoSize
write-Host "`Service Objects:"  -ForegroundColor Green
$serviceObjects | Format-Table -AutoSize
write-Host "`Network Groups:"  -ForegroundColor Green
$networkGroups | Format-Table -AutoSize
write-Host "`Service Groups:"  -ForegroundColor Green
$serviceGroups | Format-Table -AutoSize
write-Host "`ICMP Type Groups:"  -ForegroundColor Green
$icmpGroups | Format-Table -AutoSize
write-Host "`Access-Lists:"  -ForegroundColor Green
$accessLists | Format-Table -AutoSize
write-Host "`NAT Rules:"  -ForegroundColor Green
$natRules | Format-Table -AutoSize
Write-Host "`nIKE Policies (Phase 1):" -ForegroundColor Green
$ikePolicies | Format-Table -AutoSize
Write-Host "`nTransform Sets (Phase 2):" -ForegroundColor Green
$transformSets | Format-Table -AutoSize
Write-Host "`nTunnel Groups (S2S):" -ForegroundColor Green
$tunnelGroups | Where-Object { $_.Type -eq 'ipsec-l2l' } | Format-Table -AutoSize
Write-Host "`nCrypto Maps:" -ForegroundColor Green
$cryptoMaps | Format-Table -AutoSize
Write-Host "`nUnified VPN Configs:" -ForegroundColor Green
$vpnConfigs | Format-Table -AutoSize
Write-Host "`nPhase 2 Selectors:" -ForegroundColor Green
$phase2Selectors | Format-Table -AutoSize

