# WiFi Analyzer Script
# Created by Jesus Ayala - Sarah Lawrence College
# This script gathers system information, Wi-Fi networks, and adapter info.
# It is designed to be used as a diagnostic tool, especially for assisting students with Wi-Fi issues.

# Import required .NET assemblies for GUI components
Add-Type -AssemblyName System.Windows.Forms  # Provides access to Windows Forms controls (buttons, text boxes, etc.)
Add-Type -AssemblyName System.Drawing         # Provides access to drawing capabilities (fonts, colors, etc.)

# Function to scan and retrieve nearby WiFi networks with enhanced information
function Get-WiFiScan {
    # Initialize empty array to store network information
    $networks = @()
    $ssid = ""
    $security = ""
    
    # Execute netsh command to get raw WiFi network information including BSSIDs
    # The 'mode=bssid' parameter ensures we get detailed info including signal strength and channel
    $output = netsh wlan show networks mode=bssid | Out-String
    
    # Split the output into individual lines for processing
    $lines = $output -split "`r`n"

    # Process each line in the output
    for ($i = 0; $i -lt $lines.Length; $i++) {
        $line = $lines[$i].Trim()

        # Extract SSID (network name) using regex pattern matching
        if ($line -match "^SSID\s+\d+\s*:\s*(.+)$") {
            $ssid = $matches[1].Trim()
            $security = "Unknown" # Reset security for new network
        }
        
        # Extract security type
        if ($line -match "Authentication\s*:\s*(.+)$") {
            $security = $matches[1].Trim()
        }

        # Extract BSSID (MAC address of access point)
        if ($line -match "^BSSID\s+\d+\s*:\s*(.+)$") {
            $bssid = $matches[1].Trim()
            $signal = $null
            $channel = $null
            $width = $null

            # Look ahead in next few lines for signal strength and channel information
            # This works because the netsh output groups these details after each BSSID
            for ($j = 1; $j -le 8; $j++) {
                if ($i + $j -ge $lines.Length) { break }
                $nextLine = $lines[$i + $j].Trim()

                # Extract signal strength percentage
                if ($nextLine -match "^Signal\s*:\s*(\d+)%") {
                    $signal = [int]$matches[1]  # Convert to integer
                }
                # Extract channel number
                elseif ($nextLine -match "^Channel\s*:\s*(\d+)$") {
                    $channel = [int]$matches[1]  # Convert to integer
                }
                # Extract channel width if available
                elseif ($nextLine -match "^Channel width\s*:\s*(.+)$") {
                    $width = $matches[1].Trim()
                }
            }

            # If we have all required information, create a custom object and add to networks array
            if ($ssid -and $bssid -and $signal -ne $null -and $channel -ne $null) {
                $networks += [PSCustomObject]@{
                    SSID      = if ($ssid) { $ssid } else { "[Hidden Network]" }  # Better handling of empty SSIDs
                    BSSID     = $bssid    # Access point MAC address
                    Signal    = $signal   # Signal strength percentage
                    Channel   = $channel  # WiFi channel number
                    Security  = $security # Security type (WPA2, WPA3, Open, etc.)
                    Width     = if ($width) { $width } else { "Standard" } # Better default for missing width
                    Band      = if ($channel -gt 14) { "5 GHz" } else { "2.4 GHz" } # WiFi band
                }
            }
        }
    }

    # Return the collection of network objects
    return $networks
}

# Function to get the MAC address of the local WiFi adapter
function Get-MACAddress {
    # Execute netsh command to get interface information
    $output = netsh wlan show interfaces | Out-String
    $lines = $output -split "`r`n"

    # Look for the physical address (MAC) in the output
    foreach ($line in $lines) {
        if ($line -match "^\s*Physical address\s*:\s*([0-9a-fA-F:-]+)") {
            return $matches[1].Trim()  # Return the MAC address if found
        }
    }
    return "Unavailable"  # Return this if no MAC address is found
}

# Function to get information about the currently connected WiFi network
function Get-ConnectedSSID {
    # Execute netsh command to get interface information
    $output = netsh wlan show interfaces | Out-String
    $ssid = ""
    $bssid = ""
    
    # Process each line to find SSID and BSSID of connected network
    foreach ($line in $output -split "`r`n") {
        # Extract SSID (network name)
        if ($line -match "^\s*SSID\s*:\s*(.+)$") {
            $val = $matches[1].Trim()
            # Only set if value exists and is not N/A
            if ($val -and $val -ne "N/A") {
                $ssid = $val
            }
        }
        # Extract BSSID (MAC address of connected access point)
        elseif ($line -match "^\s*BSSID\s*:\s*(.+)$") {
            $bssid = $matches[1].Trim()
        }
    }
    
    # Return both values as a hashtable
    return @{
        SSID = $ssid
        BSSID = $bssid
    }
}

# Function to get additional computer information (hostname and IP address)
function Get-ComputerInfoExtras {
    # Get computer hostname from environment variable
    $hostname = $env:COMPUTERNAME

    # Find active WiFi network adapter
    $wifiAdapter = Get-NetAdapter -Physical | Where-Object {
        $_.Status -eq "Up" -and ($_.InterfaceDescription -match "Wireless" -or $_.Name -match "Wi-Fi")
    }

    $ip = $null

    # If WiFi adapter is found, get its IPv4 address
    if ($wifiAdapter) {
        # Get IPv4 address excluding link-local addresses (169.x.x.x)
        $ipEntry = Get-NetIPAddress -InterfaceIndex $wifiAdapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -notlike "169.*" }

        if ($ipEntry) {
            $ip = $ipEntry.IPAddress
        }
    }

    # Return computer name and IP as a hashtable
    return @{
        ComputerName = $hostname
        IPAddress    = if ($ip) { $ip } else { "Unavailable" }
    }
}

# Helper function to get color based on signal strength
function Get-SignalColor($signal) {
    # Three signal strength levels with corresponding colors
    # Strong signal (70-100%) = Green
    # Medium signal (40-69%) = Yellow
    # Weak signal (0-39%) = Red
    if ($signal -ge 70) {
        return "Strong", "Green"  # Strong signal - Green
    } elseif ($signal -ge 40) {
        return "Medium", "Orange" # Medium signal - Orange
    } else {
        return "Weak", "Red"      # Weak signal - Red
    }
}

# Helper function to get color based on security type
function Get-SecurityColor($security) {
    # Color-code security types:
    # WPA3 = Green (most secure)
    # WPA2 = Blue (secure)
    # WPA = Orange (less secure)
    # Open/None = Red (not secure)
    # Other/Unknown = Black (default)
    
    if ($security -match "WPA3") {
        return "WPA3", "Green"     # WPA3 - Green (most secure)
    } elseif ($security -match "WPA2") {
        return "WPA2", "Blue"      # WPA2 - Blue (secure)
    } elseif ($security -match "WPA") {
        return "WPA", "Orange"     # WPA - Orange (less secure)
    } elseif ($security -match "Open") {
        return "Open", "Red"       # Open - Red (not secure)
    } else {
        return $security, "Black"  # Other/Unknown - Black (default)
    }
}

# Function to analyze channel congestion
function Analyze-ChannelCongestion($networks) {
    # Initialize empty array for channel congestion analysis
    $channelAnalysis = @{}
    
    # Group networks by their frequency band
    $networks24GHz = $networks | Where-Object { [int]$_.Channel -le 14 }
    $networks5GHz = $networks | Where-Object { [int]$_.Channel -gt 14 }
    
    # 2.4 GHz channels (1-14, but typically 1, 6, 11 are primary non-overlapping channels)
    # Define channel overlaps for 2.4 GHz (standard 20 MHz channels)
    # Each channel overlaps with channels +/-4 from it
    foreach ($network in $networks24GHz) {
        $channel = [int]$network.Channel
        $signal = [int]$network.Signal
        
        # Affected channels (standard 20 MHz width overlaps with +/-4 channels)
        $startChannel = [Math]::Max(1, $channel - 4)
        $endChannel = [Math]::Min(14, $channel + 4)
        
        # Calculate impact on each affected channel (signal strength contributes to congestion)
        for ($i = $startChannel; $i -le $endChannel; $i++) {
            # Calculate signal impact based on distance from center channel
            $distance = [Math]::Abs($i - $channel)
            $impact = $signal * (1 - ($distance / 5))  # Diminishing impact with distance
            
            # Add to existing congestion value or initialize
            if ($channelAnalysis.ContainsKey($i)) {
                $channelAnalysis[$i] += $impact
            } else {
                $channelAnalysis[$i] = $impact
            }
        }
    }
    
    # 5 GHz channels have less overlap with standard 20 MHz width
    # For simplicity, we'll just count networks on each 5 GHz channel
    foreach ($network in $networks5GHz) {
        $channel = [int]$network.Channel
        $signal = [int]$network.Signal
        
        # Add to existing congestion value or initialize
        if ($channelAnalysis.ContainsKey($channel)) {
            $channelAnalysis[$channel] += $signal
        } else {
            $channelAnalysis[$channel] = $signal
        }
    }
    
    # Return the channel congestion analysis
    return $channelAnalysis
}

# Function to recommend the best channel based on congestion analysis
function Recommend-BestChannel($networks) {
    # If no networks found, return N/A
    if ($networks.Count -eq 0) {
        return @{
            "2.4GHz" = "N/A"
            "5GHz" = "N/A"
            "CongestionData" = @{}
        }
    }
    
    # Get channel congestion analysis
    $congestion = Analyze-ChannelCongestion $networks
    
    # Separate 2.4 GHz and 5 GHz channels
    $channels24GHz = $congestion.GetEnumerator() | Where-Object { $_.Name -le 14 } | Sort-Object Name
    $channels5GHz = $congestion.GetEnumerator() | Where-Object { $_.Name -gt 14 } | Sort-Object Name
    
    # Find least congested channels in each band
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
    
    # Return best channels for both bands
    return @{
        "2.4GHz" = if ($best24GHz) { $best24GHz.Name } else { "N/A" }
        "5GHz" = if ($best5GHz) { $best5GHz.Name } else { "N/A" }
        "CongestionData" = $congestion
    }
}

# Function to perform a simple network speed test with multiple fallbacks
function Test-NetworkSpeed {
    # Initialize variables
    $testResults = @{
        DownloadSpeed = 0
        Latency = 0
        Status = "Failed"
        Details = ""
    }
    
    try {
        # Try specified DNS servers for the ping test "167.206.19.3", "216.244.115.147"
        #failover ip's since we block external DNS which can be changed for a different Org.
        $pingServers = @("8.8.8.8", "167.206.19.3", "216.244.115.147")
        $pingSuccess = $false
        $successServer = ""
        $pingErrorCount = 0
        
        foreach ($server in $pingServers) {
            try {
                # Use -Count 2 for faster response
                $ping = Test-Connection -ComputerName $server -Count 2 -ErrorAction Stop
                $avgLatency = ($ping | Measure-Object -Property ResponseTime -Average).Average
                $testResults.Latency = [math]::Round($avgLatency, 0)
                $pingSuccess = $true
                $successServer = $server
                $testResults.Details += "Ping successful to $server. "
                break # Exit the loop if successful
            }
            catch {
                $pingErrorCount++
                $testResults.Details += "Failed to ping $server. "
                # Continue to the next server
                continue
            }
        }
        
        if (-not $pingSuccess) {
            # If all ping attempts failed
            $testResults.Status = "Failed: All ping tests failed. Network connectivity may be limited."
            return $testResults
        }
        
        # If we got here, at least one ping was successful, so we have latency
        $testResults.Status = "Partial: Latency test successful ($($testResults.Latency)ms), but download test skipped."
        
        # Try download URLs - these should be reliable public servers
        # Modified to use more reliable servers, especially ones that might work in restricted environments
        $downloadUrls = @(
            "http://speedtest.ftp.otenet.gr/files/test1Mb.db",  # Smaller file, more likely to succeed
            "http://ipv4.download.thinkbroadband.com/1MB.zip",  # Backup source
            "https://proof.ovh.net/files/1Mb.dat"              # Another source
        )
        
        $downloadSuccess = $false
        foreach ($url in $downloadUrls) {
            try {
                $startTime = Get-Date
                $wc = New-Object System.Net.WebClient
                $wc.DownloadFile($url, "$env:TEMP\speedtest.tmp")
                $endTime = Get-Date
                
                # Calculate download speed
                $fileSize = (Get-Item "$env:TEMP\speedtest.tmp").Length / 1MB # Size in MB
                $timeTaken = ($endTime - $startTime).TotalSeconds
                
                if ($timeTaken -gt 0) {
                    $downloadSpeed = $fileSize / $timeTaken # MB/s
                    
                    # Clean up the test file
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
                # Continue to the next URL
                continue
            }
        }
        
        if (-not $downloadSuccess) {
            # If all download attempts failed but ping succeeded
            $testResults.Status = "Partial: Latency test successful, but all download tests failed. Network may be restricted."
        }
        
        return $testResults
    }
    catch {
        # If test fails completely, return error information
        $testResults.Status = "Failed: Unexpected error - $($_.Exception.Message)"
        $testResults.Details = "Exception details: $($_.Exception)"
        return $testResults
    }
}

# Function to display a form for collecting user information before exporting report
function Show-ExportInfoForm {
    # Create a new form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Export Info"
    $form.Size = New-Object System.Drawing.Size(400, 280)  # Increased size
    $form.StartPosition = "CenterScreen"  # Center the form on screen

    # Labels for the form fields
    $labels = @("Your Name:", "ID Number:", "Email Address:", "Telephone Number:")
    $textboxes = @()  # Array to store textbox references

    # Create label and textbox for each field
    for ($i = 0; $i -lt $labels.Count; $i++) {
        # Create and position the label
        $label = New-Object System.Windows.Forms.Label
        $label.Text = $labels[$i]
        $label.Location = New-Object System.Drawing.Point -ArgumentList 20, (30 + ($i * 40))  # Increased spacing
        $label.Size = New-Object System.Drawing.Size(120, 20)
        $form.Controls.Add($label)

        # Create and position the textbox
        $textbox = New-Object System.Windows.Forms.TextBox
        $textbox.Location = New-Object System.Drawing.Point -ArgumentList 150, (30 + ($i * 40))  # Aligned with labels
        $textbox.Size = New-Object System.Drawing.Size(220, 20)  # Wider textboxes
        $form.Controls.Add($textbox)
        $textboxes += $textbox  # Add to collection
    }

    # Create OK button for form submission
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Text = "OK"
    $okButton.Location = New-Object System.Drawing.Point -ArgumentList 150, 190  # Positioned below fields
    $okButton.Size = New-Object System.Drawing.Size(100, 30)  # Larger button
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK  # Set dialog result when clicked
    $form.AcceptButton = $okButton  # Make this button the default (triggered by Enter key)
    $form.Controls.Add($okButton)

    # Show the form as a dialog (modal) and process the result
    if ($form.ShowDialog() -eq "OK") {
        # If OK was clicked, return collected information as hashtable
        return @{
            Name = $textboxes[0].Text
            ID = $textboxes[1].Text
            Email = $textboxes[2].Text
            Phone = $textboxes[3].Text
        }
    } else {
        # If dialog was canceled or closed, return null
        return $null
    }
}

# Function to export the WiFi analysis report to a text file
function Export-Report($networks, $mac, $recommendedChannels, $computerName, $ipAddress, $userInfo, $connectedSSID, $connectedBSSID, $speedTest, $congestionData) {
    # Get the path to the desktop folder
    $desktop = [Environment]::GetFolderPath("Desktop")
    $filePath = Join-Path $desktop "WiFi_Analysis_Report.txt"  # Full path to the report file
    $report = @()  # Initialize array to hold report lines

    # Build the report content
    $report += "Wi-Fi Analysis Report"
    $report += ("=" * 25)  # Separator line
    
    # User information section
    $report += "Submitted By:"
    $report += "Name       : $($userInfo.Name)"
    $report += "ID Number  : $($userInfo.ID)"
    $report += "Email      : $($userInfo.Email)"
    $report += "Telephone  : $($userInfo.Phone)"
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
        if ($speedTest.Details) {
            $report += "Test Details      : $($speedTest.Details)"
        }
    }
    $report += ""
    
    # Network list header
    $report += "Nearby Networks:"
    $report += ""
    $report += ("{0,-35} {1,-10} {2,-10} {3,-15} {4,-10} {5,-10} {6,-15}" -f "SSID", "Signal(%)", "Channel", "Security", "Quality", "Band", "Width")  # Column headers with added fields
    $report += ("-" * 105)  # Separator line
    
    # Add each network to the report
    foreach ($net in $networks) {
        # Mark the currently connected network with [*]
        $ssidLabel = if ($net.SSID -eq $connectedSSID -and $net.BSSID -eq $connectedBSSID) { 
            "[*] $($net.SSID)" 
        } else { 
            $net.SSID 
        }
        
        # Get signal quality label
        $signalQuality, $_ = Get-SignalColor $net.Signal
        
        # Format the line with fixed width columns including signal quality and security
        $report += ("{0,-35} {1,-10} {2,-10} {3,-15} {4,-10} {5,-10} {6,-15}" -f $ssidLabel, $net.Signal, $net.Channel, $net.Security, $signalQuality, $net.Band, $net.Width)
    }
    
    # Add channel congestion analysis
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
    
    # Add recommended channels to the report
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
    
    # Write all report lines to the file
    $report | Set-Content -Path $filePath -Encoding UTF8
    
    # Show a message box indicating successful export
    [System.Windows.Forms.MessageBox]::Show("Report exported to Desktop", "Done")
}

# GUI Setup - Main application window and controls
$form = New-Object System.Windows.Forms.Form
$form.Text = "Wi-Fi Analyzer"  # Window title
$form.Size = New-Object System.Drawing.Size(850, 600)  # Increased from 720,480
$form.StartPosition = "CenterScreen"  # Center the window on screen
$form.Padding = New-Object System.Windows.Forms.Padding(15)  # Add padding around edges

# Create Scan button
$scanButton = New-Object System.Windows.Forms.Button
$scanButton.Text = "Scan Wi-Fi"
$scanButton.Size = New-Object System.Drawing.Size(120, 35)  # Increased button size
$scanButton.Location = New-Object System.Drawing.Point -ArgumentList 20, 20
$scanButton.Font = New-Object System.Drawing.Font("Segoe UI", 10)  # Better font

# Create Export button (initially disabled until scan is performed)
$exportButton = New-Object System.Windows.Forms.Button
$exportButton.Text = "Export"
$exportButton.Size = New-Object System.Drawing.Size(120, 35)  # Increased button size
$exportButton.Location = New-Object System.Drawing.Point -ArgumentList 160, 20
$exportButton.Enabled = $false  # Disabled by default
$exportButton.Font = New-Object System.Drawing.Font("Segoe UI", 10)  # Better font

# Create text output box to display results
$outputBox = New-Object System.Windows.Forms.RichTextBox  # Changed to RichTextBox for color support
$outputBox.Multiline = $true  # Allow multiple lines
$outputBox.ScrollBars = "Vertical"  # Add vertical scrollbar
$outputBox.Location = New-Object System.Drawing.Point -ArgumentList 20, 70
$outputBox.Size = New-Object System.Drawing.Size(790, 470)  # Increased size
$outputBox.Font = New-Object System.Drawing.Font("Consolas", 10)  # Monospaced font for better alignment
$outputBox.BackColor = [System.Drawing.Color]::White  # White background for better contrast

# Add controls to the form
$form.Controls.Add($scanButton)
$form.Controls.Add($exportButton)
$form.Controls.Add($outputBox)

# Script-level shared variables to store scan results
$script:networks = @()  # Array of network objects
$script:mac = ""        # Local WiFi adapter MAC address
$script:recommended = @{} # Recommended channels
$script:computerName = "" # Computer hostname
$script:ipAddress = ""    # Computer IP address
$script:connectedSSID = "" # Connected network SSID
$script:connectedBSSID = "" # Connected network BSSID
$script:congestionData = @{} # Channel congestion data
$script:speedTest = @{    # Speed test results
    DownloadSpeed = 0
    Latency = 0
    Status = "Not Run"
    Details = ""
}

# Event handler for Scan button click
$scanButton.Add_Click({
    $outputBox.Text = "Scanning WiFi networks and analyzing environment..."  # Show scanning indicator
    
    # Get computer information
    $extras = Get-ComputerInfoExtras
    $script:computerName = $extras.ComputerName
    $script:ipAddress = $extras.IPAddress
    
    # Scan for networks
    $script:networks = Get-WiFiScan
    $script:mac = Get-MACAddress
    
    # Get currently connected network
    $ssidInfo = Get-ConnectedSSID
    $script:connectedSSID = $ssidInfo.SSID
    $script:connectedBSSID = $ssidInfo.BSSID
    
    # Get channel recommendation and congestion data
    $recommendationData = Recommend-BestChannel $script:networks
    $script:recommended = @{
        "2.4GHz" = $recommendationData["2.4GHz"]
        "5GHz" = $recommendationData["5GHz"]
    }
    $script:congestionData = $recommendationData["CongestionData"]
    
    # Clear previous output and display results
    $outputBox.Clear()
    
    # Display system information
    $outputBox.SelectionColor = "Black"
    $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $outputBox.AppendText("Computer Name     : ")
    $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10)
    $outputBox.AppendText("$script:computerName`r`n")
    
    $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $outputBox.AppendText("Computer IP       : ")
    $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10)
    $outputBox.AppendText("$script:ipAddress`r`n")
    
    $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $outputBox.AppendText("Wi-Fi MAC Address : ")
    $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10)
    $outputBox.AppendText("$script:mac`r`n")
    
    $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $outputBox.AppendText("Connected SSID    : ")
    $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10)
    $outputBox.AppendText("$script:connectedSSID ($script:connectedBSSID)`r`n`r`n")
    
    # Add speed test information
    $outputBox.AppendText("Running network speed test... Please wait...`r`n")
    $script:speedTest = Test-NetworkSpeed
    if ($script:speedTest.Status -eq "Success") {
        $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
        $outputBox.AppendText("Download Speed    : ")
        $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10)
        $outputBox.AppendText("$($script:speedTest.DownloadSpeed) Mbps`r`n")
        
        $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
        $outputBox.AppendText("Latency           : ")
        $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10)
        $outputBox.AppendText("$($script:speedTest.Latency) ms`r`n`r`n")
    } 
    elseif ($script:speedTest.Status -match "Partial") {
        # Show partial results when only latency was successful
        $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
        $outputBox.AppendText("Latency           : ")
        $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10)
        $outputBox.AppendText("$($script:speedTest.Latency) ms`r`n")
        
        $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
        $outputBox.AppendText("Speed Test Status : ")
        $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10)
        $outputBox.SelectionColor = "Orange"  # Warning color
        $outputBox.AppendText("Limited - Download test unavailable on this network`r`n`r`n")
        $outputBox.SelectionColor = "Black"
    }
    else {
        $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
        $outputBox.AppendText("Speed Test Failed : ")
        $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10)
        $outputBox.SelectionColor = "Red"
        $outputBox.AppendText("$($script:speedTest.Status)`r`n")
        $outputBox.SelectionColor = "Black"
        
        # Add a note about network restrictions for better user understanding
        $outputBox.AppendText("Note: Speed testing may be limited on networks with security restrictions.`r`n`r`n")
    }
    
    # Display networks table header
    $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $outputBox.AppendText("Nearby Networks:`r`n")
    $outputBox.SelectionFont = New-Object System.Drawing.Font("Consolas", 10, [System.Drawing.FontStyle]::Bold)
    $outputBox.AppendText(("{0,-35} {1,-10} {2,-10} {3,-15} {4,-10} {5,-10} {6,-15}`r`n" -f "SSID", "Signal(%)", "Channel", "Security", "Quality", "Band", "Width"))
    $outputBox.AppendText(("".PadRight(115, "-")) + "`r`n")  # Separator line
    $outputBox.SelectionFont = New-Object System.Drawing.Font("Consolas", 10)

    # Display each network
    foreach ($net in $script:networks) {
        # Mark the currently connected network with [*]
        $ssidLabel = if ($net.SSID -eq $script:connectedSSID -and $net.BSSID -eq $script:connectedBSSID) {
            "[*] $($net.SSID)"
        } else {
            $net.SSID
        }
        
        # Get signal quality and color based on signal strength
        $signalQuality, $signalColor = Get-SignalColor $net.Signal
        
        # Get security label and color
        $securityLabel, $securityColor = Get-SecurityColor $net.Security
        
        # Format each column with appropriate colors
        # SSID column
        $outputBox.SelectionStart = $outputBox.TextLength
        $outputBox.SelectionLength = 0
        $outputBox.SelectionColor = "Black"
        $outputBox.AppendText(("{0,-35} " -f $ssidLabel))
        
        # Signal column
        $outputBox.SelectionStart = $outputBox.TextLength
        $outputBox.SelectionLength = 0
        $outputBox.SelectionColor = $signalColor
        $outputBox.AppendText(("{0,-10} " -f $net.Signal))
        
        # Channel column
        $outputBox.SelectionStart = $outputBox.TextLength
        $outputBox.SelectionLength = 0
        $outputBox.SelectionColor = "Black"
        $outputBox.AppendText(("{0,-10} " -f $net.Channel))
        
        # Security column
        $outputBox.SelectionStart = $outputBox.TextLength
        $outputBox.SelectionLength = 0
        $outputBox.SelectionColor = $securityColor
        $outputBox.AppendText(("{0,-15} " -f $securityLabel))
        
        # Quality column
        $outputBox.SelectionStart = $outputBox.TextLength
        $outputBox.SelectionLength = 0
        $outputBox.SelectionColor = $signalColor
        $outputBox.AppendText(("{0,-10} " -f $signalQuality))
        
        # Band column
        $outputBox.SelectionStart = $outputBox.TextLength
        $outputBox.SelectionLength = 0
        $outputBox.SelectionColor = "Black"
        $outputBox.AppendText(("{0,-10} " -f $net.Band))
        
        # Width column
        $outputBox.SelectionStart = $outputBox.TextLength
        $outputBox.SelectionLength = 0
        $outputBox.SelectionColor = "Black"
        $outputBox.AppendText(("{0,-15}`r`n" -f $net.Width))
    }

    # Display channel congestion analysis
    $outputBox.SelectionStart = $outputBox.TextLength
    $outputBox.SelectionLength = 0
    $outputBox.SelectionColor = "Black"
    $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $outputBox.AppendText("`r`nChannel Congestion Analysis:`r`n")
    $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    
    # 2.4 GHz channels
    $outputBox.AppendText("2.4 GHz Band:`r`n")
    $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10)
    $congestion24 = $script:congestionData.GetEnumerator() | Where-Object { $_.Name -le 14 } | Sort-Object Name
    foreach ($channel in $congestion24) {
        $congestionColor = if ($channel.Value -gt 150) { "Red" } elseif ($channel.Value -gt 75) { "Orange" } else { "Green" }
        $congestionLevel = if ($channel.Value -gt 150) { "High" } elseif ($channel.Value -gt 75) { "Medium" } else { "Low" }
        
        $outputBox.SelectionStart = $outputBox.TextLength
        $outputBox.SelectionLength = 0
        $outputBox.SelectionColor = "Black"
        $outputBox.AppendText("  Channel $($channel.Name): ")
        
        $outputBox.SelectionStart = $outputBox.TextLength
        $outputBox.SelectionLength = 0
        $outputBox.SelectionColor = $congestionColor
        $outputBox.AppendText("$congestionLevel")
        
        $outputBox.SelectionStart = $outputBox.TextLength
        $outputBox.SelectionLength = 0
        $outputBox.SelectionColor = "Black"
        $outputBox.AppendText(" congestion (Score: $([math]::Round($channel.Value, 1)))`r`n")
    }
    
    # 5 GHz channels
    $outputBox.SelectionStart = $outputBox.TextLength
    $outputBox.SelectionLength = 0
    $outputBox.SelectionColor = "Black"
    $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $outputBox.AppendText("`r`n5 GHz Band:`r`n")
    $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10)
    $congestion5 = $script:congestionData.GetEnumerator() | Where-Object { $_.Name -gt 14 } | Sort-Object Name
    foreach ($channel in $congestion5) {
        $congestionColor = if ($channel.Value -gt 150) { "Red" } elseif ($channel.Value -gt 75) { "Orange" } else { "Green" }
        $congestionLevel = if ($channel.Value -gt 150) { "High" } elseif ($channel.Value -gt 75) { "Medium" } else { "Low" }
        
        $outputBox.SelectionStart = $outputBox.TextLength
        $outputBox.SelectionLength = 0
        $outputBox.SelectionColor = "Black"
        $outputBox.AppendText("  Channel $($channel.Name): ")
        
        $outputBox.SelectionStart = $outputBox.TextLength
        $outputBox.SelectionLength = 0
        $outputBox.SelectionColor = $congestionColor
        $outputBox.AppendText("$congestionLevel")
        
        $outputBox.SelectionStart = $outputBox.TextLength
        $outputBox.SelectionLength = 0
        $outputBox.SelectionColor = "Black"
        $outputBox.AppendText(" congestion (Score: $([math]::Round($channel.Value, 1)))`r`n")
    }
    
    # Display channel recommendation
    $outputBox.SelectionStart = $outputBox.TextLength
    $outputBox.SelectionLength = 0
    $outputBox.SelectionColor = "Black"
    $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $outputBox.AppendText("`r`nRecommended Channels:`r`n")
    $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10)
    $outputBox.AppendText("2.4 GHz Band: Channel $($script:recommended['2.4GHz'])`r`n")
    $outputBox.AppendText("5 GHz Band  : Channel $($script:recommended['5GHz'])`r`n`r`n")
    
    # Add legends
    $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $outputBox.AppendText("Signal Strength Legend:`r`n")
    $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10)
    
    # Strong signal legend
    $outputBox.SelectionStart = $outputBox.TextLength
    $outputBox.SelectionLength = 0
    $outputBox.SelectionColor = "Green"
    $outputBox.AppendText("Strong: 70-100% ")
    
    # Medium signal legend
    $outputBox.SelectionStart = $outputBox.TextLength
    $outputBox.SelectionLength = 0
    $outputBox.SelectionColor = "Black"
    $outputBox.AppendText("| ")
    
    $outputBox.SelectionStart = $outputBox.TextLength
    $outputBox.SelectionLength = 0
    $outputBox.SelectionColor = "Orange"
    $outputBox.AppendText("Medium: 40-69% ")
    
    # Weak signal legend
    $outputBox.SelectionStart = $outputBox.TextLength
    $outputBox.SelectionLength = 0
    $outputBox.SelectionColor = "Black"
    $outputBox.AppendText("| ")
    
    $outputBox.SelectionStart = $outputBox.TextLength
    $outputBox.SelectionLength = 0
    $outputBox.SelectionColor = "Red"
    $outputBox.AppendText("Weak: 0-39%")
    
    # Reset text color to default
    $outputBox.SelectionStart = $outputBox.TextLength
    $outputBox.SelectionLength = 0
    $outputBox.SelectionColor = "Black"
    $outputBox.AppendText("`r`n`r`n")
    
    # Security legend
    $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $outputBox.AppendText("Security Type Legend:`r`n")
    $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10)
    
    # WPA3 legend
    $outputBox.SelectionStart = $outputBox.TextLength
    $outputBox.SelectionLength = 0
    $outputBox.SelectionColor = "Green"
    $outputBox.AppendText("WPA3: Most Secure ")
    
    # WPA2 legend
    $outputBox.SelectionStart = $outputBox.TextLength
    $outputBox.SelectionLength = 0
    $outputBox.SelectionColor = "Black"
    $outputBox.AppendText("| ")
    
    $outputBox.SelectionStart = $outputBox.TextLength
    $outputBox.SelectionLength = 0
    $outputBox.SelectionColor = "Blue"
    $outputBox.AppendText("WPA2: Secure ")
    
    # WPA legend
    $outputBox.SelectionStart = $outputBox.TextLength
    $outputBox.SelectionLength = 0
    $outputBox.SelectionColor = "Black"
    $outputBox.AppendText("| ")
    
    $outputBox.SelectionStart = $outputBox.TextLength
    $outputBox.SelectionLength = 0
    $outputBox.SelectionColor = "Orange"
    $outputBox.AppendText("WPA: Less Secure ")
    
    # Open legend
    $outputBox.SelectionStart = $outputBox.TextLength
    $outputBox.SelectionLength = 0
    $outputBox.SelectionColor = "Black"
    $outputBox.AppendText("| ")
    
    $outputBox.SelectionStart = $outputBox.TextLength
    $outputBox.SelectionLength = 0
    $outputBox.SelectionColor = "Red"
    $outputBox.AppendText("Open: Not Secure")
    
    # Reset text color
    $outputBox.SelectionColor = "Black"
    
    # Enable export button if networks were found
    $exportButton.Enabled = $script:networks.Count -gt 0
})

# Event handler for Export button click
$exportButton.Add_Click({
    # Check if networks were scanned
    if ($script:networks.Count -gt 0) {
        # Show the user info form
        $userInfo = Show-ExportInfoForm
        
        # If user completed the form
        if ($userInfo) {
            # Export the report with all collected information
            Export-Report -networks $script:networks -mac $script:mac `
                -recommendedChannels $script:recommended `
                -computerName $script:computerName -ipAddress $script:ipAddress `
                -userInfo $userInfo -connectedSSID $script:connectedSSID -connectedBSSID $script:connectedBSSID `
                -speedTest $script:speedTest -congestionData $script:congestionData
        }
    } else {
        # Show error if no scan has been performed
        [System.Windows.Forms.MessageBox]::Show("Nothing to export. Please run a scan first.", "Export Error")
    }
})

# Display the form and start application
[void]$form.ShowDialog()
