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


# Get matches 
$serviceMatches = [regex]::Matches($config, $servicePattern)
$networkMatches = [regex]::Matches($config, $networkpattern)
$networkGroupMatches = [regex]::Matches($config, $networkGroupPattern)
$serviceGroupMatches = [regex]::Matches($config, $serviceGroupPattern)
$icmpGroupMatches = [regex]::Matches($config, $icmpGroupPattern)
$aclMatches = [regex]::Matches($config, $aclPattern)
$natMatches = [regex]::Matches($config, $natPattern)

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

#Count objects parsed
Write-Host "Parsed $($networkObjects.Count) network objects."
Write-Host "Parsed $($serviceObjects.Count) service objects."
Write-Host "Parsed $($networkGroups.Count) network groups."
Write-Host "Parsed $($serviceGroups.Count) service groups."
Write-Host "Parsed $($icmpGroups.Count) ICMP type groups."
Write-Host "Parsed $($accessLists.Count) access-list entries."
Write-Host "Parsed $($natRules.Count) NAT rules."

# Output the parsed objects
write-Host "`Network Objects:"
write-Host "----------------"
$networkObjects | Format-Table -AutoSize
write-Host "`Service Objects:"
write-Host "----------------"
$serviceObjects | Format-Table -AutoSize
write-Host "`Network Groups:"
write-Host "----------------"
$networkGroups | Format-Table -AutoSize
write-Host "`Service Groups:"
write-Host "----------------"  
$serviceGroups | Format-Table -AutoSize
write-Host "`ICMP Type Groups:"
write-Host "----------------"
$icmpGroups | Format-Table -AutoSize
write-Host "`Access-Lists:"
write-Host "----------------"
$accessLists | Format-Table -AutoSize
write-Host "`NAT Rules:"
write-Host "----------------"
$natRules | Format-Table -AutoSize
#>