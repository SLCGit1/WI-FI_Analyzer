# 💻 WiFi Analyzer Code - Technical Breakdown

## What This Code Does

This PowerShell script creates a comprehensive WiFi analyzer application that helps users diagnose wireless network issues and optimize performance. The application scans for all nearby WiFi networks, analyzes their signal strength, security settings, and channel usage, and provides detailed recommendations to improve connectivity.

Key functionality includes:
- **Network Discovery**: The code utilizes Windows' `netsh` command to detect and parse information about all accessible WiFi networks in the vicinity.
- **Signal Analysis**: It categorizes signal strength into clear quality levels (Strong, Medium, Weak) with visual color-coding for instant assessment.
- **Security Assessment**: The code identifies security protocols (WPA3, WPA2, WPA, Open) and highlights potential security vulnerabilities with color-coded warnings.
- **Channel Congestion Analysis**: A sophisticated algorithm models how WiFi signals overlap and interfere with each other, calculating congestion scores for each channel.
- **Performance Testing**: The code performs network speed tests, measuring both download throughput and latency Line 302 has an option for failed over DNS, for Org that block public DNS.
- **Report Generation**: Compiles all findings into a comprehensive report that can be saved and shared.
- **Location Tracking**: Enhanced with Building and Room Number fields to help IT support locate and address WiFi issues more efficiently.

The application presents this information through a user-friendly graphical interface using Windows Forms technology, with color coding and clear visual indicators to help users understand their WiFi environment at a glance.

## 📑 Table of Contents

- [🖥️ GUI Components](#-gui-components)
- [📡 Network Scanning](#-network-scanning)
- [🔍 System Information](#-system-information)
- [📊 Channel Analysis](#-channel-analysis)
- [⚡ Speed Testing](#-speed-testing)
- [🎨 Visual Formatting](#-visual-formatting)
- [📄 Report Generation](#-report-generation)
- [🔄 Event Handlers](#-event-handlers)
- [⚙️ Advanced Implementation Details](#-advanced-implementation-details)
- [🏢 Location Tracking Enhancement](#-location-tracking-enhancement)

## 🖥️ GUI Components

### Main Form Setup

```powershell
# Import required .NET assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Create the main application window
$form = New-Object System.Windows.Forms.Form
$form.Text = "Wi-Fi Analyzer"
$form.Size = New-Object System.Drawing.Size(850, 600)
$form.StartPosition = "CenterScreen"
$form.Padding = New-Object System.Windows.Forms.Padding(15)
```

The GUI is built using .NET Windows Forms. This approach provides:
- Native Windows look and feel
- Rich text formatting capabilities
- Event-driven programming model

### Control Creation

```powershell
# Create buttons with enhanced visual properties
$scanButton = New-Object System.Windows.Forms.Button
$scanButton.Text = "Scan Wi-Fi"
$scanButton.Size = New-Object System.Drawing.Size(120, 35)
$scanButton.Location = New-Object System.Drawing.Point -ArgumentList 20, 20
$scanButton.Font = New-Object System.Drawing.Font("Segoe UI", 10)

# Create a RichTextBox for formatted output display
$outputBox = New-Object System.Windows.Forms.RichTextBox
$outputBox.Multiline = $true
$outputBox.ScrollBars = "Vertical"
$outputBox.Location = New-Object System.Drawing.Point -ArgumentList 20, 70
$outputBox.Size = New-Object System.Drawing.Size(790, 470)
$outputBox.Font = New-Object System.Drawing.Font("Consolas", 10)
$outputBox.BackColor = [System.Drawing.Color]::White
```

Key UI design decisions:
- **RichTextBox**: Chosen over standard TextBox to enable color-coding
- **Consolas font**: Selected for its monospaced properties for table alignment
- **Segoe UI**: Used for buttons and headers for enhanced readability

## 📡 Network Scanning

### Get-WiFiScan Function

```powershell
function Get-WiFiScan {
    # Initialize variables
    $networks = @()
    $ssid = ""
    $security = ""
    
    # Execute netsh command to get WiFi information
    $output = netsh wlan show networks mode=bssid | Out-String
    $lines = $output -split "`r`n"

    # Process command output with regular expressions
    for ($i = 0; $i -lt $lines.Length; $i++) {
        $line = $lines[$i].Trim()

        # Extract SSID (network name)
        if ($line -match "^SSID\s+\d+\s*:\s*(.+)$") {
            $ssid = $matches[1].Trim()
            $security = "Unknown"
        }
        
        # Extract security type
        if ($line -match "Authentication\s*:\s*(.+)$") {
            $security = $matches[1].Trim()
        }

        # Extract BSSID and related properties
        if ($line -match "^BSSID\s+\d+\s*:\s*(.+)$") {
            $bssid = $matches[1].Trim()
            $signal = $null
            $channel = $null
            $width = $null

            # Look ahead in output for additional properties
            for ($j = 1; $j -le 8; $j++) {
                if ($i + $j -ge $lines.Length) { break }
                $nextLine = $lines[$i + $j].Trim()

                # Extract signal strength
                if ($nextLine -match "^Signal\s*:\s*(\d+)%") {
                    $signal = [int]$matches[1]
                }
                # Extract channel number
                elseif ($nextLine -match "^Channel\s*:\s*(\d+)$") {
                    $channel = [int]$matches[1]
                }
                # Extract channel width
                elseif ($nextLine -match "^Channel width\s*:\s*(.+)$") {
                    $width = $matches[1].Trim()
                }
            }

            # Create network object with all properties
            if ($ssid -and $bssid -and $signal -ne $null -and $channel -ne $null) {
                $networks += [PSCustomObject]@{
                    SSID      = if ($ssid) { $ssid } else { "[Hidden Network]" }
                    BSSID     = $bssid
                    Signal    = $signal
                    Channel   = $channel
                    Security  = $security
                    Width     = if ($width) { $width } else { "Standard" }
                    Band      = if ($channel -gt 14) { "5 GHz" } else { "2.4 GHz" }
                }
            }
        }
    }

    return $networks
}
```

#### Implementation Details

1. **Command Execution**:
   - Uses `netsh wlan show networks mode=bssid` to retrieve detailed network information
   - The `mode=bssid` parameter is crucial for getting signal strength and channel data

2. **Parsing Strategy**:
   - Applies regex pattern matching to extract structured data
   - Uses a state machine approach to associate properties with the correct network
   - Looks ahead in the output to find properties that appear after each BSSID

3. **Data Enrichment**:
   - Automatically determines frequency band based on channel number
   - Provides default values for missing information
   - Handles hidden networks with a descriptive placeholder

4. **Error Handling**:
   - Only creates network objects when all required properties are present
   - Uses null-value checking to ensure data integrity

## 🔍 System Information

### Get-MACAddress Function

```powershell
function Get-MACAddress {
    # Get WiFi interface information
    $output = netsh wlan show interfaces | Out-String
    $lines = $output -split "`r`n"

    # Extract MAC address with regex
    foreach ($line in $lines) {
        if ($line -match "^\s*Physical address\s*:\s*([0-9a-fA-F:-]+)") {
            return $matches[1].Trim()
        }
    }
    return "Unavailable"
}
```

This function:
- Uses a different `netsh` command to get interface details
- Focuses only on extracting the MAC address
- Has a fallback return value for error cases

### Get-ComputerInfoExtras Function

```powershell
function Get-ComputerInfoExtras {
    # Get computer hostname
    $hostname = $env:COMPUTERNAME

    # Find active WiFi adapter
    $wifiAdapter = Get-NetAdapter -Physical | Where-Object {
        $_.Status -eq "Up" -and ($_.InterfaceDescription -match "Wireless" -or $_.Name -match "Wi-Fi")
    }

    $ip = $null

    # Get adapter's IPv4 address
    if ($wifiAdapter) {
        $ipEntry = Get-NetIPAddress -InterfaceIndex $wifiAdapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -notlike "169.*" }

        if ($ipEntry) {
            $ip = $ipEntry.IPAddress
        }
    }

    return @{
        ComputerName = $hostname
        IPAddress    = if ($ip) { $ip } else { "Unavailable" }
    }
}
```

This function:
- Uses PowerShell's `Get-NetAdapter` cmdlet instead of `netsh`
- Filters for active wireless adapters
- Excludes link-local addresses (169.x.x.x)
- Returns multiple values in a hashtable

## 📊 Channel Analysis

### Analyze-ChannelCongestion Function

```powershell
function Analyze-ChannelCongestion($networks) {
    # Initialize channel analysis hashtable
    $channelAnalysis = @{}
    
    # Separate networks by frequency band
    $networks24GHz = $networks | Where-Object { [int]$_.Channel -le 14 }
    $networks5GHz = $networks | Where-Object { [int]$_.Channel -gt 14 }
    
    # Process 2.4 GHz networks with channel overlap
    foreach ($network in $networks24GHz) {
        $channel = [int]$network.Channel
        $signal = [int]$network.Signal
        
        # Calculate affected channel range (+/- 4 channels)
        $startChannel = [Math]::Max(1, $channel - 4)
        $endChannel = [Math]::Min(14, $channel + 4)
        
        # Calculate impact on each affected channel
        for ($i = $startChannel; $i -le $endChannel; $i++) {
            $distance = [Math]::Abs($i - $channel)
            $impact = $signal * (1 - ($distance / 5))
            
            # Update channel congestion score
            if ($channelAnalysis.ContainsKey($i)) {
                $channelAnalysis[$i] += $impact
            } else {
                $channelAnalysis[$i] = $impact
            }
        }
    }
    
    # Process 5 GHz networks (simpler - less overlap)
    foreach ($network in $networks5GHz) {
        $channel = [int]$network.Channel
        $signal = [int]$network.Signal
        
        if ($channelAnalysis.ContainsKey($channel)) {
            $channelAnalysis[$channel] += $signal
        } else {
            $channelAnalysis[$channel] = $signal
        }
    }
    
    return $channelAnalysis
}
```

#### Channel Congestion Algorithm

The algorithm models real-world WiFi interference patterns by accounting for:

1. **Channel Overlap**: 
   - 2.4 GHz channels overlap significantly (+/- 4 channels)
   - Channel 6 affects channels 2-10, with diminishing impact

2. **Impact Formula**:
   ```
   Impact = Signal × (1 - (Distance ÷ 5))
   ```
   Where:
   - Signal = Network signal strength (0-100%)
   - Distance = Absolute difference from center channel
   - Division by 5 creates a linear diminishing effect

3. **Cumulative Scoring**:
   - Each channel's congestion score is the sum of all impacts
   - Higher scores indicate more congestion/interference

### Recommend-BestChannel Function

```powershell
function Recommend-BestChannel($networks) {
    # Handle empty networks case
    if ($networks.Count -eq 0) {
        return @{
            "2.4GHz" = "N/A"
            "5GHz" = "N/A"
            "CongestionData" = @{}
        }
    }
    
    # Get congestion data
    $congestion = Analyze-ChannelCongestion $networks
    
    # Separate and sort channels by band
    $channels24GHz = $congestion.GetEnumerator() | Where-Object { $_.Name -le 14 } | Sort-Object Name
    $channels5GHz = $congestion.GetEnumerator() | Where-Object { $_.Name -gt 14 } | Sort-Object Name
    
    # Find least congested channel in each band
    $best24GHz = if ($channels24GHz.Count -gt 0) { 
        $channels24GHz | Sort-Object Value | Select-Object -First 1 
    } else { 
        $null 
    }
    
    $best5GHz = if ($channels5GHz.Count -gt 0) { 
        $channels5GHz | Sort-Object Value | Select-Object -First 1 
    } else { 
        $null 
    }
    
    # Return recommendations for both bands
    return @{
        "2.4GHz" = if ($best24GHz) { $best24GHz.Name } else { "N/A" }
        "5GHz" = if ($best5GHz) { $best5GHz.Name } else { "N/A" }
        "CongestionData" = $congestion
    }
}
```

This function:
- Builds on the congestion analysis to recommend channels
- Separates channels by frequency band
- Sorts channels by congestion score
- Selects the least congested channel in each band
- Returns recommendations for both bands plus full congestion data

## ⚡ Speed Testing

### Test-NetworkSpeed Function

```powershell
function Test-NetworkSpeed {
    # Initialize result data structure
    $testResults = @{
        DownloadSpeed = 0
        Latency = 0
        Status = "Failed"
        Details = ""
    }
    
    try {
        # Latency test with multiple fallback servers
        $pingServers = @("8.8.8.8", "167.206.19.3", "216.244.115.147")
        $pingSuccess = $false
        
        foreach ($server in $pingServers) {
            try {
                $ping = Test-Connection -ComputerName $server -Count 2 -ErrorAction Stop
                $avgLatency = ($ping | Measure-Object -Property ResponseTime -Average).Average
                $testResults.Latency = [math]::Round($avgLatency, 0)
                $pingSuccess = $true
                $testResults.Details += "Ping successful to $server. "
                break
            }
            catch {
                $testResults.Details += "Failed to ping $server. "
                continue
            }
        }
        
        if (-not $pingSuccess) {
            $testResults.Status = "Failed: All ping tests failed. Network connectivity may be limited."
            return $testResults
        }
        
        # Download speed test with multiple fallback URLs
        $downloadUrls = @(
            "http://speedtest.ftp.otenet.gr/files/test1Mb.db",
            "http://ipv4.download.thinkbroadband.com/1MB.zip",
            "https://proof.ovh.net/files/1Mb.dat"
        )
        
        $downloadSuccess = $false
        foreach ($url in $downloadUrls) {
            try {
                # Download test file and measure time
                $startTime = Get-Date
                $wc = New-Object System.Net.WebClient
                $wc.DownloadFile($url, "$env:TEMP\speedtest.tmp")
                $endTime = Get-Date
                
                # Calculate speed
                $fileSize = (Get-Item "$env:TEMP\speedtest.tmp").Length / 1MB
                $timeTaken = ($endTime - $startTime).TotalSeconds
                
                if ($timeTaken -gt 0) {
                    $downloadSpeed = $fileSize / $timeTaken # MB/s
                    Remove-Item "$env:TEMP\speedtest.tmp" -Force -ErrorAction SilentlyContinue
                    
                    # Update results
                    $testResults.DownloadSpeed = [math]::Round($downloadSpeed * 8, 2) # Convert to Mbps
                    $testResults.Status = "Success"
                    $testResults.Details += "Download test successful using $url. "
                    $downloadSuccess = $true
                    break
                }
            }
            catch {
                $testResults.Details += "Failed to download from $url. "
                continue
            }
        }
        
        if (-not $downloadSuccess) {
            $testResults.Status = "Partial: Latency test successful, but all download tests failed."
        }
        
        return $testResults
    }
    catch {
        $testResults.Status = "Failed: Unexpected error - $($_.Exception.Message)"
        return $testResults
    }
}
```

#### Speed Test Implementation

The function employs multiple techniques to ensure reliable testing:

1. **Latency Testing**:
   - Uses `Test-Connection` cmdlet (PowerShell's ping wrapper)
   - Tries multiple DNS servers with fallback logic
   - Calculates average response time

2. **Download Testing**:
   - Uses `System.Net.WebClient` for file downloads
   - Measures exact start and end times with millisecond precision
   - Calculates throughput based on file size and download time
   - Converts from MB/s to Mbps (× 8) for standard reporting

3. **Fallback Strategy**:
   - Multiple servers for latency testing
   - Multiple URLs for download testing
   - Continues even if latency test succeeds but download fails

4. **Error Handling**:
   - Comprehensive try/catch blocks
   - Detailed status reporting
   - Returns partial results when possible

## 🎨 Visual Formatting

### Get-SignalColor Function

```powershell
function Get-SignalColor($signal) {
    if ($signal -ge 70) {
        return "Strong", "Green"
    } elseif ($signal -ge 40) {
        return "Medium", "Orange"
    } else {
        return "Weak", "Red"
    }
}
```

This function:
- Takes a signal strength percentage as input
- Returns both a text label and a color
- Uses thresholds to categorize signal quality

### Get-SecurityColor Function

```powershell
function Get-SecurityColor($security) {
    if ($security -match "WPA3") {
        return "WPA3", "Green"
    } elseif ($security -match "WPA2") {
        return "WPA2", "Blue"
    } elseif ($security -match "WPA") {
        return "WPA", "Orange"
    } elseif ($security -match "Open") {
        return "Open", "Red"
    } else {
        return $security, "Black"
    }
}
```

This function:
- Takes a security type string as input
- Returns a standardized label and appropriate color
- Uses pattern matching to handle variations in security naming

## 🏢 Location Tracking Enhancement

### Enhanced User Information Form

```powershell
function Show-ExportInfoForm {
    # Create form dialog
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Export Info"
    $form.Size = New-Object System.Drawing.Size(400, 360) # Increased height for new fields
    $form.StartPosition = "CenterScreen"

    # Define form fields - UPDATED to include Building and Room Number
    $labels = @("Your Name:", "ID Number:", "Email Address:", "Telephone Number:", "Building:", "Room Number:")
    $textboxes = @()

    # Create controls dynamically
    for ($i = 0; $i -lt $labels.Count; $i++) {
        # Label
        $label = New-Object System.Windows.Forms.Label
        $label.Text = $labels[$i]
        $label.Location = New-Object System.Drawing.Point -ArgumentList 20, (30 + ($i * 40))
        $label.Size = New-Object System.Drawing.Size(120, 20)
        $form.Controls.Add($label)

        # Textbox
        $textbox = New-Object System.Windows.Forms.TextBox
        $textbox.Location = New-Object System.Drawing.Point -ArgumentList 150, (30 + ($i * 40))
        $textbox.Size = New-Object System.Drawing.Size(220, 20)
        $form.Controls.Add($textbox)
        $textboxes += $textbox
    }

    # OK button - UPDATED position to accommodate new fields
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Text = "OK"
    $okButton.Location = New-Object System.Drawing.Point -ArgumentList 150, 270
    $okButton.Size = New-Object System.Drawing.Size(100, 30)
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $okButton
    $form.Controls.Add($okButton)

    # Show dialog and process result
    if ($form.ShowDialog() -eq "OK") {
        # Return data structure UPDATED to include Building and Room Number
        return @{
            Name = $textboxes[0].Text
            ID = $textboxes[1].Text
            Email = $textboxes[2].Text
            Phone = $textboxes[3].Text
            Building = $textboxes[4].Text
            RoomNumber = $textboxes[5].Text
        }
    } else {
        return $null
    }
}
```

### Enhanced Report Generation

```powershell
function Export-Report($networks, $mac, $recommendedChannels, $computerName, $ipAddress, $userInfo, $connectedSSID, $connectedBSSID, $speedTest, $congestionData) {
    # Determine report file path
    $desktop = [Environment]::GetFolderPath("Desktop")
    $filePath = Join-Path $desktop "WiFi_Analysis_Report.txt"
    $report = @()

    # Build the report content in sections
    $report += "Wi-Fi Analysis Report"
    $report += ("=" * 25)
    
    # User information section - UPDATED to include Building and Room Number
    $report += "Submitted By:"
    $report += "Name         : $($userInfo.Name)"
    $report += "ID Number    : $($userInfo.ID)"
    $report += "Email        : $($userInfo.Email)"
    $report += "Telephone    : $($userInfo.Phone)"
    $report += "Building     : $($userInfo.Building)"
    $report += "Room Number  : $($userInfo.RoomNumber)"
    $report += ""
    
    # Rest of the report function remains the same
    # ...
}
```

### Implementation Benefits

The enhanced location tracking provides several important benefits:

1. **Precise Location Information**:
   - Building and room number data helps IT staff locate issues accurately
   - Enables faster response times for on-site troubleshooting
   - Facilitates better tracking of problem areas

2. **Pattern Recognition**:
   - Allows correlation of WiFi issues with specific buildings or locations
   - Helps identify potential infrastructure problems (e.g., interference sources, dead zones)
   - Enables data-driven decisions about access point placement and upgrades

3. **User Experience**:
   - Streamlined support process for users reporting WiFi issues
   - Eliminates need for follow-up questions about location
   - Provides consistent format for location reporting

4. **Report Enhancement**:
   - More complete documentation for IT knowledge base
   - Better historical tracking of WiFi issues by location
   - Improved metrics for measuring WiFi performance across campus

## 📄 Report Generation

### Export-Report Function (Continuing from above)

```powershell
function Export-Report($networks, $mac, $recommendedChannels, $computerName, $ipAddress, $userInfo, $connectedSSID, $connectedBSSID, $speedTest, $congestionData) {
    # Determine report file path
    $desktop = [Environment]::GetFolderPath("Desktop")
    $filePath = Join-Path $desktop "WiFi_Analysis_Report.txt"
    $report = @()

    # Build the report content in sections
    $report += "Wi-Fi Analysis Report"
    $report += ("=" * 25)
    
    # User information section - UPDATED to include Building and Room Number
    $report += "Submitted By:"
    $report += "Name         : $($userInfo.Name)"
    $report += "ID Number    : $($userInfo.ID)"
    $report += "Email        : $($userInfo.Email)"
    $report += "Telephone    : $($userInfo.Phone)"
    $report += "Building     : $($userInfo.Building)"
    $report += "Room Number  : $($userInfo.RoomNumber)"
    $report += ""
    
    # System information section
    $report += "System Info:"
    $report += "Computer Name      : $computerName"
    $report += "Computer IP        : $ipAddress"
    $report += "Wi-Fi MAC Address  : $mac"
    $report += "Connected SSID     : $connectedSSID ($connectedBSSID)"
    $report += ""
    
    # Speed test results
    $report += "Network Performance:"
    if ($speedTest.Status -eq "Success") {
        $report += "Download Speed    : $($speedTest.DownloadSpeed) Mbps"
        $report += "Latency           : $($speedTest.Latency) ms"
    } else {
        $report += "Speed Test        : $($speedTest.Status)"
    }
    $report += ""
    
    # Network list section
    $report += "Nearby Networks:"
    $report += ""
    $report += ("{0,-35} {1,-10} {2,-10} {3,-15} {4,-10} {5,-10} {6,-15}" -f "SSID", "Signal(%)", "Channel", "Security", "Quality", "Band", "Width")
    $report += ("-" * 105)
    
    # Add each network to the report
    foreach ($net in $networks) {
        $ssidLabel = if ($net.SSID -eq $connectedSSID -and $net.BSSID -eq $connectedBSSID) { 
            "[*] $($net.SSID)" 
        } else { 
            $net.SSID 
        }
        
        $signalQuality, $_ = Get-SignalColor $net.Signal
        
        $report += ("{0,-35} {1,-10} {2,-10} {3,-15} {4,-10} {5,-10} {6,-15}" -f $ssidLabel, $net.Signal, $net.Channel, $net.Security, $signalQuality, $net.Band, $net.Width)
    }
    
    # Channel congestion analysis section
    $report += ""
    $report += "Channel Congestion Analysis:"
    
    # 2.4 GHz channels
    $report += "2.4 GHz Band:"
    $congestion24 = $congestionData.GetEnumerator() | Where-Object { $_.Name -le 14 } | Sort-Object Name
    foreach ($channel in $congestion24) {
        $congestionLevel = if ($channel.Value -gt 150) { "High" } elseif ($channel.Value -gt 75) { "Medium" } else { "Low" }
        $report += "  Channel $($channel.Name): $congestionLevel congestion (Score: $([math]::Round($channel.Value, 1)))"
    }
    
    # 5 GHz channels
    $report += ""
    $report += "5 GHz Band:"
    $congestion5 = $congestionData.GetEnumerator() | Where-Object { $_.Name -gt 14 } | Sort-Object Name
    foreach ($channel in $congestion5) {
        $congestionLevel = if ($channel.Value -gt 150) { "High" } elseif ($channel.Value -gt 75) { "Medium" } else { "Low" }
        $report += "  Channel $($channel.Name): $congestionLevel congestion (Score: $([math]::Round($channel.Value, 1)))"
    }
    
    # Recommendations and legends
    $report += ""
    $report += "Recommended Channels:"
    $report += "2.4 GHz Band: Channel $($recommendedChannels['2.4GHz'])"
    $report += "5 GHz Band  : Channel $($recommendedChannels['5GHz'])"
    $report += ""
    $report += "Signal Strength Legend:"
    $report += "Strong: 70-100% | Medium: 40-69% | Weak: 0-39%"
    $report += ""
    $report += "Security Type Legend:"
    $report += "WPA3: Most Secure | WPA2: Secure | WPA: Less Secure | Open: Not Secure"
    
    # Write to file and notify user
    $report | Set-Content -Path $filePath -Encoding UTF8
    [System.Windows.Forms.MessageBox]::Show("Report exported to Desktop", "Done")
}
```

This function:
- Builds a structured report from all collected data
- Uses formatted string tables for data presentation
- Includes congestion analysis with easy-to-understand labels
- Adds legends for interpreting signal and security data
- Saves the report to the user's desktop
- Notifies the user upon successful export

## 🔄 Event Handlers

### Scan Button Click Handler

```powershell
$scanButton.Add_Click({
    # Show initial scanning message
    $outputBox.Text = "Scanning WiFi networks and analyzing environment..."
    
    # Collect all required information
    $extras = Get-ComputerInfoExtras
    $script:computerName = $extras.ComputerName
    $script:ipAddress = $extras.IPAddress
    $script:networks = Get-WiFiScan
    $script:mac = Get-MACAddress
    $ssidInfo = Get-ConnectedSSID
    $script:connectedSSID = $ssidInfo.SSID
    $script:connectedBSSID = $ssidInfo.BSSID
    
    # Analyze channel congestion
    $recommendationData = Recommend-BestChannel $script:networks
    $script:recommended = @{
        "2.4GHz" = $recommendationData["2.4GHz"]
        "5GHz" = $recommendationData["5GHz"]
    }
    $script:congestionData = $recommendationData["CongestionData"]
    
    # Clear and begin formatting output
    $outputBox.Clear()
    
    # Display system information with rich formatting
    # ...formatted output code...
    
    # Run speed test and display results
    $outputBox.AppendText("Running network speed test... Please wait...`r`n")
    $script:speedTest = Test-NetworkSpeed
    
    # Format speed test results based on status
    if ($script:speedTest.Status -eq "Success") {
        # Display successful speed test results
    } 
    elseif ($script:speedTest.Status -match "Partial") {
        # Display partial results with warning color
    }
    else {
        # Display failed test with error color
    }
    
    # Display network table with color-coded information
    # ...formatted output code...
    
    # Display congestion analysis with color-coded levels
    # ...formatted output code...
    
    # Display channel recommendations
    # ...formatted output code...
    
    # Add legends for signal strength and security
    # ...formatted output code...
    
    # Enable export button now that data is available
    $exportButton.Enabled = $script:networks.Count -gt 0
})
