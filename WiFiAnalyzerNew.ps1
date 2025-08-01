# WiFi Analyzer Script - Complete Fixed Version with Hybrid Startup
# Created by Jesus Ayala - Sarah Lawrence College
# Enhanced with guided setup, quick start, and robust error handling

param(
    [switch]$QuickStart,
    [switch]$SkipPreflightCheck,
    [switch]$Debug
)

# Import required .NET assemblies for GUI components
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ===== CORE WIFI ANALYSIS FUNCTIONS =====

# Function to scan and retrieve nearby WiFi networks with enhanced information
function Get-WiFiScan {
    $networks = @()
    $ssid = ""
    $security = ""
    
    $output = netsh wlan show networks mode=bssid | Out-String
    $lines = $output -split "`r`n"

    for ($i = 0; $i -lt $lines.Length; $i++) {
        $line = $lines[$i].Trim()

        if ($line -match "^SSID\s+\d+\s*:\s*(.+)$") {
            $ssid = $matches[1].Trim()
            $security = "Unknown"
        }
        
        if ($line -match "Authentication\s*:\s*(.+)$") {
            $security = $matches[1].Trim()
        }

        if ($line -match "^BSSID\s+\d+\s*:\s*(.+)$") {
            $bssid = $matches[1].Trim()
            $signal = $null
            $channel = $null
            $width = $null

            for ($j = 1; $j -le 8; $j++) {
                if ($i + $j -ge $lines.Length) { break }
                $nextLine = $lines[$i + $j].Trim()

                if ($nextLine -match "^Signal\s*:\s*(\d+)%") {
                    $signal = [int]$matches[1]
                }
                elseif ($nextLine -match "^Channel\s*:\s*(\d+)$") {
                    $channel = [int]$matches[1]
                }
                elseif ($nextLine -match "^Channel width\s*:\s*(.+)$") {
                    $width = $matches[1].Trim()
                }
            }

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

# Function to get the MAC address of the local WiFi adapter
function Get-MACAddress {
    $output = netsh wlan show interfaces | Out-String
    $lines = $output -split "`r`n"

    foreach ($line in $lines) {
        if ($line -match "^\s*Physical address\s*:\s*([0-9a-fA-F:-]+)") {
            return $matches[1].Trim()
        }
    }
    return "Unavailable"
}

# Function to get information about the currently connected WiFi network
function Get-ConnectedSSID {
    $output = netsh wlan show interfaces | Out-String
    $ssid = ""
    $bssid = ""
    
    foreach ($line in $output -split "`r`n") {
        if ($line -match "^\s*SSID\s*:\s*(.+)$") {
            $val = $matches[1].Trim()
            if ($val -and $val -ne "N/A") {
                $ssid = $val
            }
        }
        elseif ($line -match "^\s*BSSID\s*:\s*(.+)$") {
            $bssid = $matches[1].Trim()
        }
    }
    
    return @{
        SSID = $ssid
        BSSID = $bssid
    }
}

# Function to get additional computer information
function Get-ComputerInfoExtras {
    $hostname = $env:COMPUTERNAME

    $wifiAdapter = Get-NetAdapter -Physical | Where-Object {
        $_.Status -eq "Up" -and ($_.InterfaceDescription -match "Wireless" -or $_.Name -match "Wi-Fi")
    }

    $ip = $null

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

# Helper function to get color based on signal strength
function Get-SignalColor($signal) {
    if ($signal -ge 70) {
        return "Strong", "Green"
    } elseif ($signal -ge 40) {
        return "Medium", "Orange"
    } else {
        return "Weak", "Red"
    }
}

# Helper function to get color based on security type
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

# Function to analyze channel congestion
function Analyze-ChannelCongestion($networks) {
    $channelAnalysis = @{}
    
    $networks24GHz = $networks | Where-Object { [int]$_.Channel -le 14 }
    $networks5GHz = $networks | Where-Object { [int]$_.Channel -gt 14 }
    
    foreach ($network in $networks24GHz) {
        $channel = [int]$network.Channel
        $signal = [int]$network.Signal
        
        $startChannel = [Math]::Max(1, $channel - 4)
        $endChannel = [Math]::Min(14, $channel + 4)
        
        for ($i = $startChannel; $i -le $endChannel; $i++) {
            $distance = [Math]::Abs($i - $channel)
            $impact = $signal * (1 - ($distance / 5))
            
            if ($channelAnalysis.ContainsKey($i)) {
                $channelAnalysis[$i] += $impact
            } else {
                $channelAnalysis[$i] = $impact
            }
        }
    }
    
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

# Function to recommend the best channel based on congestion analysis
function Recommend-BestChannel($networks) {
    if ($networks.Count -eq 0) {
        return @{
            "2.4GHz" = "N/A"
            "5GHz" = "N/A"
            "CongestionData" = @{}
        }
    }
    
    $congestion = Analyze-ChannelCongestion $networks
    
    $channels24GHz = $congestion.GetEnumerator() | Where-Object { $_.Name -le 14 } | Sort-Object Name
    $channels5GHz = $congestion.GetEnumerator() | Where-Object { $_.Name -gt 14 } | Sort-Object Name
    
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
    
    return @{
        "2.4GHz" = if ($best24GHz) { $best24GHz.Name } else { "N/A" }
        "5GHz" = if ($best5GHz) { $best5GHz.Name } else { "N/A" }
        "CongestionData" = $congestion
    }
}

# Function to perform a simple network speed test (ORIGINAL WORKING VERSION)
function Test-NetworkSpeed {
    $testResults = @{
        DownloadSpeed = 0
        Latency = 0
        Status = "Failed"
        Details = ""
    }
    
    try {
        $pingServers = @("8.8.8.8", "167.206.19.3", "216.244.115.147")
        $pingSuccess = $false
        $successServer = ""
        $pingErrorCount = 0
        
        foreach ($server in $pingServers) {
            try {
                $ping = Test-Connection -ComputerName $server -Count 2 -ErrorAction Stop
                $avgLatency = ($ping | Measure-Object -Property ResponseTime -Average).Average
                $testResults.Latency = [math]::Round($avgLatency, 0)
                $pingSuccess = $true
                $successServer = $server
                $testResults.Details += "Ping successful to $server. "
                break
            }
            catch {
                $pingErrorCount++
                $testResults.Details += "Failed to ping $server. "
                continue
            }
        }
        
        if (-not $pingSuccess) {
            $testResults.Status = "Failed: All ping tests failed. Network connectivity may be limited."
            return $testResults
        }
        
        $testResults.Status = "Partial: Latency test successful ($($testResults.Latency)ms), but download test skipped."
        
        $downloadUrls = @(
            "http://speedtest.ftp.otenet.gr/files/test1Mb.db",
            "http://ipv4.download.thinkbroadband.com/1MB.zip",
            "https://proof.ovh.net/files/1Mb.dat"
        )
        
        $downloadSuccess = $false
        foreach ($url in $downloadUrls) {
            try {
                $startTime = Get-Date
                $wc = New-Object System.Net.WebClient
                $wc.DownloadFile($url, "$env:TEMP\speedtest.tmp")
                $endTime = Get-Date
                
                $fileSize = (Get-Item "$env:TEMP\speedtest.tmp").Length / 1MB
                $timeTaken = ($endTime - $startTime).TotalSeconds
                
                if ($timeTaken -gt 0) {
                    $downloadSpeed = $fileSize / $timeTaken
                    
                    Remove-Item "$env:TEMP\speedtest.tmp" -Force -ErrorAction SilentlyContinue
                    
                    $testResults.DownloadSpeed = [math]::Round($downloadSpeed * 8, 2)
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
            $testResults.Status = "Partial: Latency test successful, but all download tests failed. Network may be restricted."
        }
        
        return $testResults
    }
    catch {
        $testResults.Status = "Failed: Unexpected error - $($_.Exception.Message)"
        $testResults.Details = "Exception details: $($_.Exception)"
        return $testResults
    }
}

# ===== HYBRID STARTUP SYSTEM =====

# Function to check if location services are enabled
function Test-Prerequisites {
    $results = @{
        LocationServices = $false
        WiFiAdapter = $false
        AdminRights = $false
        OverallStatus = $false
        Issues = @()
        Warnings = @()
    }
    
    try {
        $wlanTest = netsh wlan show interfaces 2>&1
        if ($wlanTest -match "Network shell commands need location permission" -or $wlanTest -match "Access is denied") {
            $results.Issues += "Location services are not enabled for WiFi scanning"
        } else {
            $results.LocationServices = $true
        }
    }
    catch {
        $results.Issues += "Unable to test WiFi access: $($_.Exception.Message)"
    }
    
    try {
        $adapters = Get-NetAdapter | Where-Object { 
            $_.InterfaceDescription -match "Wireless" -or $_.Name -match "Wi-Fi" 
        }
        if ($adapters.Count -eq 0) {
            $results.Issues += "No WiFi adapter found"
        } elseif (($adapters | Where-Object Status -eq "Up").Count -eq 0) {
            $results.Issues += "WiFi adapter found but not active"
        } else {
            $results.WiFiAdapter = $true
        }
    }
    catch {
        $results.Warnings += "Could not fully verify WiFi adapter status"
    }
    
    try {
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        $results.AdminRights = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $results.AdminRights) {
            $results.Warnings += "Running without administrator privileges (some features may be limited)"
        }
    }
    catch {
        $results.Warnings += "Could not determine privilege level"
    }
    
    $results.OverallStatus = $results.LocationServices -and $results.WiFiAdapter
    return $results
}

# FIXED: Startup choice dialog with proper sizing and working buttons
function Show-StartupChoiceDialog {
    $choiceForm = New-Object System.Windows.Forms.Form
    $choiceForm.Text = "WiFi Analyzer - Startup Options"
    $choiceForm.Size = New-Object System.Drawing.Size(520, 420)
    $choiceForm.StartPosition = "CenterScreen"
    $choiceForm.FormBorderStyle = "FixedDialog"
    $choiceForm.MaximizeBox = $false
    $choiceForm.MinimizeBox = $false
    
    # Header
    $headerLabel = New-Object System.Windows.Forms.Label
    $headerLabel.Text = "WiFi Analyzer"
    $headerLabel.Location = New-Object System.Drawing.Point(20, 20)
    $headerLabel.Size = New-Object System.Drawing.Size(470, 30)
    $headerLabel.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
    $headerLabel.ForeColor = "DarkBlue"
    $headerLabel.TextAlign = "MiddleCenter"
    $choiceForm.Controls.Add($headerLabel)
    
    # Subtitle
    $subtitleLabel = New-Object System.Windows.Forms.Label
    $subtitleLabel.Text = "Choose your startup preference:"
    $subtitleLabel.Location = New-Object System.Drawing.Point(20, 60)
    $subtitleLabel.Size = New-Object System.Drawing.Size(470, 20)
    $subtitleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $subtitleLabel.TextAlign = "MiddleCenter"
    $choiceForm.Controls.Add($subtitleLabel)
    
    # Guided Setup Option - Made larger
    $guidedPanel = New-Object System.Windows.Forms.Panel
    $guidedPanel.Location = New-Object System.Drawing.Point(30, 100)
    $guidedPanel.Size = New-Object System.Drawing.Size(450, 90)
    $guidedPanel.BorderStyle = "FixedSingle"
    $guidedPanel.BackColor = "LightBlue"
    $choiceForm.Controls.Add($guidedPanel)
    
    $guidedButton = New-Object System.Windows.Forms.Button
    $guidedButton.Text = "[G] Guided Setup (Recommended)"
    $guidedButton.Location = New-Object System.Drawing.Point(10, 10)
    $guidedButton.Size = New-Object System.Drawing.Size(280, 35)
    $guidedButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $guidedButton.BackColor = "White"
    $guidedPanel.Controls.Add($guidedButton)
    
    $guidedDesc = New-Object System.Windows.Forms.Label
    $guidedDesc.Text = "Checks system requirements and guides you through setup.`r`nPerfect for first-time users or troubleshooting."
    $guidedDesc.Location = New-Object System.Drawing.Point(10, 50)
    $guidedDesc.Size = New-Object System.Drawing.Size(430, 35)
    $guidedDesc.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $guidedPanel.Controls.Add($guidedDesc)
    
    # Quick Start Option - Made larger
    $quickPanel = New-Object System.Windows.Forms.Panel
    $quickPanel.Location = New-Object System.Drawing.Point(30, 210)
    $quickPanel.Size = New-Object System.Drawing.Size(450, 90)
    $quickPanel.BorderStyle = "FixedSingle"
    $quickPanel.BackColor = "LightGreen"
    $choiceForm.Controls.Add($quickPanel)
    
    $quickButton = New-Object System.Windows.Forms.Button
    $quickButton.Text = "[Q] Quick Start"
    $quickButton.Location = New-Object System.Drawing.Point(10, 10)
    $quickButton.Size = New-Object System.Drawing.Size(150, 35)
    $quickButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $quickButton.BackColor = "White"
    $quickPanel.Controls.Add($quickButton)
    
    $quickDesc = New-Object System.Windows.Forms.Label
    $quickDesc.Text = "Skip setup checks and go straight to WiFi scanning.`r`nFor experienced users who have already configured their system."
    $quickDesc.Location = New-Object System.Drawing.Point(10, 50)
    $quickDesc.Size = New-Object System.Drawing.Size(430, 35)
    $quickDesc.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $quickPanel.Controls.Add($quickDesc)
    
    # Options at bottom
    $optionsLabel = New-Object System.Windows.Forms.Label
    $optionsLabel.Text = "Tip: You can skip this dialog next time using command line parameters"
    $optionsLabel.Location = New-Object System.Drawing.Point(30, 320)
    $optionsLabel.Size = New-Object System.Drawing.Size(450, 15)
    $optionsLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Italic)
    $optionsLabel.ForeColor = "Gray"
    $choiceForm.Controls.Add($optionsLabel)
    
    # Remember choice checkbox
    $rememberCheck = New-Object System.Windows.Forms.CheckBox
    $rememberCheck.Text = "Remember my choice"
    $rememberCheck.Location = New-Object System.Drawing.Point(30, 340)
    $rememberCheck.Size = New-Object System.Drawing.Size(200, 20)
    $rememberCheck.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $choiceForm.Controls.Add($rememberCheck)
    
    # FIXED: Use form-level variables instead of script scope
    $choiceForm.Tag = @{
        Choice = $null
        Remember = $false
    }
    
    # FIXED: Event handlers that properly set the choice
    $guidedButton.Add_Click({
        $choiceForm.Tag.Choice = "Guided"
        $choiceForm.Tag.Remember = $rememberCheck.Checked
        $choiceForm.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $choiceForm.Close()
    })
    
    $quickButton.Add_Click({
        $choiceForm.Tag.Choice = "Quick"
        $choiceForm.Tag.Remember = $rememberCheck.Checked
        $choiceForm.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $choiceForm.Close()
    })
    
    # Show form and return choice
    $result = $choiceForm.ShowDialog()
    
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $choice = $choiceForm.Tag.Choice
        $remember = $choiceForm.Tag.Remember
        
        if ($remember -and $choice) {
            Save-UserPreference $choice
        }
        return $choice
    } else {
        return "Cancel"
    }
}

# Preference management
function Get-UserPreference {
    try {
        $prefPath = "$env:APPDATA\WiFiAnalyzer_Preference.txt"
        if (Test-Path $prefPath) {
            return Get-Content $prefPath -Raw
        }
    }
    catch {
        # Ignore errors, just return null
    }
    return $null
}

function Save-UserPreference($preference) {
    try {
        $prefPath = "$env:APPDATA\WiFiAnalyzer_Preference.txt"
        $preference | Set-Content $prefPath
        if ($Debug) {
            Write-Host "Preference saved: $preference" -ForegroundColor Green
        }
    }
    catch {
        if ($Debug) {
            Write-Host "Could not save preference: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

# FIXED: Enhanced Guided Setup function with better feedback
function Start-GuidedSetup {
    if ($Debug) {
        Write-Host "Starting Guided Setup process..." -ForegroundColor Cyan
    }
    
    try {
        do {
            $prereqResults = Test-Prerequisites
            
            if ($prereqResults.OverallStatus) {
                [System.Windows.Forms.MessageBox]::Show(
                    "All system requirements are met!`n`nStarting WiFi Analyzer...",
                    "System Check Passed",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information
                )
                if ($Debug) { Write-Host "All prerequisites met" -ForegroundColor Green }
                return $true
            }
            
            # Show issues found
            $issueMsg = "System requirements check found issues:`n`n"
            foreach ($issue in $prereqResults.Issues) {
                $issueMsg += "X $issue`n"
            }
            foreach ($warning in $prereqResults.Warnings) {
                $issueMsg += "! $warning`n"
            }
            $issueMsg += "`nWould you like to fix these issues?"
            
            $result = [System.Windows.Forms.MessageBox]::Show(
                $issueMsg,
                "System Requirements Check",
                [System.Windows.Forms.MessageBoxButtons]::YesNoCancel,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            
            switch ($result) {
                "Yes" {
                    if ($Debug) { Write-Host "User chose to fix issues" -ForegroundColor Yellow }
                    try {
                        Start-Process "ms-settings:privacy-location"
                        [System.Windows.Forms.MessageBox]::Show(
                            "Please enable Location Services and click OK to recheck.",
                            "Fix Issues",
                            [System.Windows.Forms.MessageBoxButtons]::OK,
                            [System.Windows.Forms.MessageBoxIcon]::Information
                        )
                    }
                    catch {
                        [System.Windows.Forms.MessageBox]::Show(
                            "Please manually open Settings > Privacy & security > Location",
                            "Manual Setup Required"
                        )
                    }
                    continue
                }
                "No" {
                    if ($Debug) { Write-Host "User chose to continue with issues" -ForegroundColor Yellow }
                    $continueResult = [System.Windows.Forms.MessageBox]::Show(
                        "Continue anyway? The WiFi analyzer may not work properly.",
                        "Continue with Issues?",
                        [System.Windows.Forms.MessageBoxButtons]::YesNo,
                        [System.Windows.Forms.MessageBoxIcon]::Question
                    )
                    return ($continueResult -eq "Yes")
                }
                default {
                    if ($Debug) { Write-Host "User cancelled guided setup" -ForegroundColor Red }
                    return $false
                }
            }
        } while ($true)
        
    } catch {
        if ($Debug) {
            Write-Host "Error in Guided Setup: $($_.Exception.Message)" -ForegroundColor Red
        }
        [System.Windows.Forms.MessageBox]::Show(
            "An error occurred during guided setup: $($_.Exception.Message)",
            "Guided Setup Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        return $false
    }
}

# FIXED: Enhanced Quick Start function with better feedback
function Start-QuickStart {
    if ($Debug) {
        Write-Host "Quick Start Mode - Performing basic validation..." -ForegroundColor Cyan
    }
    
    try {
        $prereqResults = Test-Prerequisites
        
        if (-not $prereqResults.OverallStatus) {
            $quickMsg = "Quick validation found potential issues:`n`n"
            foreach ($issue in $prereqResults.Issues) {
                $quickMsg += "* $issue`n"
            }
            $quickMsg += "`nContinue anyway? (You can use Guided Setup if you need help fixing these)"
            
            $result = [System.Windows.Forms.MessageBox]::Show(
                $quickMsg,
                "Quick Start - Issues Detected",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            
            if ($result -eq "No") {
                if ($Debug) { Write-Host "User declined to continue with issues" -ForegroundColor Red }
                return $false
            }
        }
        
        if ($Debug) {
            Write-Host "Quick start validation complete" -ForegroundColor Green
        }
        return $true
        
    } catch {
        if ($Debug) {
            Write-Host "Error in Quick Start: $($_.Exception.Message)" -ForegroundColor Red
        }
        [System.Windows.Forms.MessageBox]::Show(
            "An error occurred during quick start validation: $($_.Exception.Message)",
            "Quick Start Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        return $false
    }
}

# ===== EXPORT FUNCTIONALITY =====

# Function to display a form for collecting user information before exporting report
function Show-ExportInfoForm {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Export Info"
    $form.Size = New-Object System.Drawing.Size(400, 360)
    $form.StartPosition = "CenterScreen"

    $labels = @("Your Name:", "ID Number:", "Email Address:", "Telephone Number:", "Building:", "Room Number:")
    $textboxes = @()

    for ($i = 0; $i -lt $labels.Count; $i++) {
        $label = New-Object System.Windows.Forms.Label
        $label.Text = $labels[$i]
        $label.Location = New-Object System.Drawing.Point -ArgumentList 20, (30 + ($i * 40))
        $label.Size = New-Object System.Drawing.Size(120, 20)
        $form.Controls.Add($label)

        $textbox = New-Object System.Windows.Forms.TextBox
        $textbox.Location = New-Object System.Drawing.Point -ArgumentList 150, (30 + ($i * 40))
        $textbox.Size = New-Object System.Drawing.Size(220, 20)
        $form.Controls.Add($textbox)
        $textboxes += $textbox
    }

    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Text = "OK"
    $okButton.Location = New-Object System.Drawing.Point -ArgumentList 150, 270
    $okButton.Size = New-Object System.Drawing.Size(100, 30)
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $okButton
    $form.Controls.Add($okButton)

    if ($form.ShowDialog() -eq "OK") {
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

# Function to export the WiFi analysis report to a text file
function Export-Report($networks, $mac, $recommendedChannels, $computerName, $ipAddress, $userInfo, $connectedSSID, $connectedBSSID, $speedTest, $congestionData) {
    $desktop = [Environment]::GetFolderPath("Desktop")
    $filePath = Join-Path $desktop "WiFi_Analysis_Report.txt"
    $report = @()

    $report += "Wi-Fi Analysis Report"
    $report += ("=" * 25)
    
    $report += "Submitted By:"
    $report += "Name         : $($userInfo.Name)"
    $report += "ID Number    : $($userInfo.ID)"
    $report += "Email        : $($userInfo.Email)"
    $report += "Telephone    : $($userInfo.Phone)"
    $report += "Building     : $($userInfo.Building)"
    $report += "Room Number  : $($userInfo.RoomNumber)"
    $report += ""
    
    $report += "System Info:"
    $report += "Computer Name      : $computerName"
    $report += "Computer IP        : $ipAddress"
    $report += "Wi-Fi MAC Address  : $mac"
    $report += "Connected SSID     : $connectedSSID ($connectedBSSID)"
    $report += ""
    
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
    
    $report += "Nearby Networks:"
    $report += ""
    $report += ("{0,-35} {1,-10} {2,-10} {3,-15} {4,-10} {5,-10} {6,-15}" -f "SSID", "Signal(%)", "Channel", "Security", "Quality", "Band", "Width")
    $report += ("-" * 105)
    
    foreach ($net in $networks) {
        $ssidLabel = if ($net.SSID -eq $connectedSSID -and $net.BSSID -eq $connectedBSSID) { 
            "[*] $($net.SSID)" 
        } else { 
            $net.SSID 
        }
        
        $signalQuality, $_ = Get-SignalColor $net.Signal
        
        $report += ("{0,-35} {1,-10} {2,-10} {3,-15} {4,-10} {5,-10} {6,-15}" -f $ssidLabel, $net.Signal, $net.Channel, $net.Security, $signalQuality, $net.Band, $net.Width)
    }
    
    $report += ""
    $report += "Channel Congestion Analysis:"
    
    $report += "2.4 GHz Band:"
    $congestion24 = $congestionData.GetEnumerator() | Where-Object { $_.Name -le 14 } | Sort-Object Name
    foreach ($channel in $congestion24) {
        $congestionLevel = if ($channel.Value -gt 150) { "High" } elseif ($channel.Value -gt 75) { "Medium" } else { "Low" }
        $report += "  Channel $($channel.Name): $congestionLevel congestion (Score: $([math]::Round($channel.Value, 1)))"
    }
    
    $report += ""
    $report += "5 GHz Band:"
    $congestion5 = $congestionData.GetEnumerator() | Where-Object { $_.Name -gt 14 } | Sort-Object Name
    foreach ($channel in $congestion5) {
        $congestionLevel = if ($channel.Value -gt 150) { "High" } elseif ($channel.Value -gt 75) { "Medium" } else { "Low" }
        $report += "  Channel $($channel.Name): $congestionLevel congestion (Score: $([math]::Round($channel.Value, 1)))"
    }
    
    $report += ""
    $report += "Recommended Channels:"
    $report += "2.4 GHz Band: Channel $($recommendedChannels.'2.4GHz')"
    $report += "5 GHz Band  : Channel $($recommendedChannels.'5GHz')"
    $report += ""
    $report += "Signal Strength Legend:"
    $report += "Strong: 70-100% | Medium: 40-69% | Weak: 0-39%"
    $report += ""
    $report += "Security Type Legend:"
    $report += "WPA3: Most Secure | WPA2: Secure | WPA: Less Secure | Open: Not Secure"
    
    $report | Set-Content -Path $filePath -Encoding UTF8
    
    [System.Windows.Forms.MessageBox]::Show("Report exported to Desktop", "Done")
}

# ===== MAIN GUI INTERFACE =====

# Script-level shared variables
$script:networks = @()
$script:mac = ""
$script:recommended = @{}
$script:computerName = ""
$script:ipAddress = ""
$script:connectedSSID = ""
$script:connectedBSSID = ""
$script:congestionData = @{}
$script:speedTest = @{
    DownloadSpeed = 0
    Latency = 0
    Status = "Not Run"
    Details = ""
}

function Show-MainWiFiAnalyzerForm {
    # Create main form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Wi-Fi Analyzer"
    $form.Size = New-Object System.Drawing.Size(850, 600)
    $form.StartPosition = "CenterScreen"
    $form.Padding = New-Object System.Windows.Forms.Padding(15)

    # Create Scan button
    $scanButton = New-Object System.Windows.Forms.Button
    $scanButton.Text = "Scan Wi-Fi"
    $scanButton.Size = New-Object System.Drawing.Size(120, 35)
    $scanButton.Location = New-Object System.Drawing.Point -ArgumentList 20, 20
    $scanButton.Font = New-Object System.Drawing.Font("Segoe UI", 10)

    # Create Export button
    $exportButton = New-Object System.Windows.Forms.Button
    $exportButton.Text = "Export"
    $exportButton.Size = New-Object System.Drawing.Size(120, 35)
    $exportButton.Location = New-Object System.Drawing.Point -ArgumentList 160, 20
    $exportButton.Enabled = $false
    $exportButton.Font = New-Object System.Drawing.Font("Segoe UI", 10)

    # Create output box
    $outputBox = New-Object System.Windows.Forms.RichTextBox
    $outputBox.Multiline = $true
    $outputBox.ScrollBars = "Vertical"
    $outputBox.Location = New-Object System.Drawing.Point -ArgumentList 20, 70
    $outputBox.Size = New-Object System.Drawing.Size(790, 470)
    $outputBox.Font = New-Object System.Drawing.Font("Consolas", 10)
    $outputBox.BackColor = [System.Drawing.Color]::White

    # Add controls to form
    $form.Controls.Add($scanButton)
    $form.Controls.Add($exportButton)
    $form.Controls.Add($outputBox)

    # Scan button event handler
    $scanButton.Add_Click({
        $outputBox.Text = "Scanning WiFi networks and analyzing environment..."
        
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
            "2.4GHz" = $recommendationData."2.4GHz"
            "5GHz" = $recommendationData."5GHz"
        }
        $script:congestionData = $recommendationData."CongestionData"
        
        # Clear output and display results
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
        
        # Speed test with original working function
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
            $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
            $outputBox.AppendText("Latency           : ")
            $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10)
            $outputBox.AppendText("$($script:speedTest.Latency) ms`r`n")
            
            $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
            $outputBox.AppendText("Speed Test Status : ")
            $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10)
            $outputBox.SelectionColor = "Orange"
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
            
            $outputBox.AppendText("Note: Speed testing may be limited on networks with security restrictions.`r`n`r`n")
        }
        
        # Display networks table
        $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
        $outputBox.AppendText("Nearby Networks:`r`n")
        $outputBox.SelectionFont = New-Object System.Drawing.Font("Consolas", 10, [System.Drawing.FontStyle]::Bold)
        $outputBox.AppendText(("{0,-35} {1,-10} {2,-10} {3,-15} {4,-10} {5,-10} {6,-15}`r`n" -f "SSID", "Signal(%)", "Channel", "Security", "Quality", "Band", "Width"))
        $outputBox.AppendText(("".PadRight(115, "-")) + "`r`n")
        $outputBox.SelectionFont = New-Object System.Drawing.Font("Consolas", 10)
        
        foreach ($net in $script:networks) {
            $ssidLabel = if ($net.SSID -eq $script:connectedSSID -and $net.BSSID -eq $script:connectedBSSID) {
                "[*] $($net.SSID)"
            } else {
                $net.SSID
            }
            
            $signalQuality, $signalColor = Get-SignalColor $net.Signal
            $securityLabel, $securityColor = Get-SecurityColor $net.Security
            
            # Format with colors
            $outputBox.SelectionStart = $outputBox.TextLength
            $outputBox.SelectionLength = 0
            $outputBox.SelectionColor = "Black"
            $outputBox.AppendText(("{0,-35} " -f $ssidLabel))
            
            $outputBox.SelectionStart = $outputBox.TextLength
            $outputBox.SelectionLength = 0
            $outputBox.SelectionColor = $signalColor
            $outputBox.AppendText(("{0,-10} " -f $net.Signal))
            
            $outputBox.SelectionStart = $outputBox.TextLength
            $outputBox.SelectionLength = 0
            $outputBox.SelectionColor = "Black"
            $outputBox.AppendText(("{0,-10} " -f $net.Channel))
            
            $outputBox.SelectionStart = $outputBox.TextLength
            $outputBox.SelectionLength = 0
            $outputBox.SelectionColor = $securityColor
            $outputBox.AppendText(("{0,-15} " -f $securityLabel))
            
            $outputBox.SelectionStart = $outputBox.TextLength
            $outputBox.SelectionLength = 0
            $outputBox.SelectionColor = $signalColor
            $outputBox.AppendText(("{0,-10} " -f $signalQuality))
            
            $outputBox.SelectionStart = $outputBox.TextLength
            $outputBox.SelectionLength = 0
            $outputBox.SelectionColor = "Black"
            $outputBox.AppendText(("{0,-10} " -f $net.Band))
            
            $outputBox.SelectionStart = $outputBox.TextLength
            $outputBox.SelectionLength = 0
            $outputBox.SelectionColor = "Black"
            $outputBox.AppendText(("{0,-15}`r`n" -f $net.Width))
        }
        
        # Channel congestion analysis
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
        
        # Channel recommendations
        $outputBox.SelectionStart = $outputBox.TextLength
        $outputBox.SelectionLength = 0
        $outputBox.SelectionColor = "Black"
        $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
        $outputBox.AppendText("`r`nRecommended Channels:`r`n")
        $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10)
        $outputBox.AppendText("2.4 GHz Band: Channel $($script:recommended.'2.4GHz')`r`n")
        $outputBox.AppendText("5 GHz Band  : Channel $($script:recommended.'5GHz')`r`n`r`n")
        
        # Legends
        $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
        $outputBox.AppendText("Signal Strength Legend:`r`n")
        $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10)
        
        $outputBox.SelectionStart = $outputBox.TextLength
        $outputBox.SelectionLength = 0
        $outputBox.SelectionColor = "Green"
        $outputBox.AppendText("Strong: 70-100% ")
        
        $outputBox.SelectionStart = $outputBox.TextLength
        $outputBox.SelectionLength = 0
        $outputBox.SelectionColor = "Black"
        $outputBox.AppendText("| ")
        
        $outputBox.SelectionStart = $outputBox.TextLength
        $outputBox.SelectionLength = 0
        $outputBox.SelectionColor = "Orange"
        $outputBox.AppendText("Medium: 40-69% ")
        
        $outputBox.SelectionStart = $outputBox.TextLength
        $outputBox.SelectionLength = 0
        $outputBox.SelectionColor = "Black"
        $outputBox.AppendText("| ")
        
        $outputBox.SelectionStart = $outputBox.TextLength
        $outputBox.SelectionLength = 0
        $outputBox.SelectionColor = "Red"
        $outputBox.AppendText("Weak: 0-39%")
        
        $outputBox.SelectionStart = $outputBox.TextLength
        $outputBox.SelectionLength = 0
        $outputBox.SelectionColor = "Black"
        $outputBox.AppendText("`r`n`r`n")
        
        # Security legend
        $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
        $outputBox.AppendText("Security Type Legend:`r`n")
        $outputBox.SelectionFont = New-Object System.Drawing.Font("Segoe UI", 10)
        
        $outputBox.SelectionStart = $outputBox.TextLength
        $outputBox.SelectionLength = 0
        $outputBox.SelectionColor = "Green"
        $outputBox.AppendText("WPA3: Most Secure ")
        
        $outputBox.SelectionStart = $outputBox.TextLength
        $outputBox.SelectionLength = 0
        $outputBox.SelectionColor = "Black"
        $outputBox.AppendText("| ")
        
        $outputBox.SelectionStart = $outputBox.TextLength
        $outputBox.SelectionLength = 0
        $outputBox.SelectionColor = "Blue"
        $outputBox.AppendText("WPA2: Secure ")
        
        $outputBox.SelectionStart = $outputBox.TextLength
        $outputBox.SelectionLength = 0
        $outputBox.SelectionColor = "Black"
        $outputBox.AppendText("| ")
        
        $outputBox.SelectionStart = $outputBox.TextLength
        $outputBox.SelectionLength = 0
        $outputBox.SelectionColor = "Orange"
        $outputBox.AppendText("WPA: Less Secure ")
        
        $outputBox.SelectionStart = $outputBox.TextLength
        $outputBox.SelectionLength = 0
        $outputBox.SelectionColor = "Black"
        $outputBox.AppendText("| ")
        
        $outputBox.SelectionStart = $outputBox.TextLength
        $outputBox.SelectionLength = 0
        $outputBox.SelectionColor = "Red"
        $outputBox.AppendText("Open: Not Secure")
        
        $outputBox.SelectionColor = "Black"
        
        # Enable export button
        $exportButton.Enabled = $script:networks.Count -gt 0
    })

    # Export button event handler
    $exportButton.Add_Click({
        if ($script:networks.Count -gt 0) {
            $userInfo = Show-ExportInfoForm
            
            if ($userInfo) {
                Export-Report -networks $script:networks -mac $script:mac `
                    -recommendedChannels $script:recommended `
                    -computerName $script:computerName -ipAddress $script:ipAddress `
                    -userInfo $userInfo -connectedSSID $script:connectedSSID -connectedBSSID $script:connectedBSSID `
                    -speedTest $script:speedTest -congestionData $script:congestionData
            }
        } else {
            [System.Windows.Forms.MessageBox]::Show("Nothing to export. Please run a scan first.", "Export Error")
        }
    })

    # Show the form
    [void]$form.ShowDialog()
}

# ===== FIXED STARTUP LOGIC =====

function Start-WiFiAnalyzer {
    if ($Debug) {
        Write-Host "WiFi Analyzer - Hybrid Startup Mode" -ForegroundColor Green
        Write-Host "======================================" -ForegroundColor Green
    }
    
    # Check command line parameters first
    if ($QuickStart -or $SkipPreflightCheck) {
        if ($Debug) {
            Write-Host "Command line: Quick start requested" -ForegroundColor Cyan
        }
        if (Start-QuickStart) {
            Show-MainWiFiAnalyzerForm
        } else {
            Write-Host "Quick start cancelled" -ForegroundColor Red
        }
        return
    }
    
    # Check saved preference
    $savedPreference = Get-UserPreference
    if ($savedPreference) {
        if ($Debug) {
            Write-Host "Found saved preference: $savedPreference" -ForegroundColor Cyan
        }
        
        switch ($savedPreference.Trim()) {
            "Guided" {
                if ($Debug) { Write-Host "Using saved Guided preference" -ForegroundColor Yellow }
                if (Start-GuidedSetup) {
                    Show-MainWiFiAnalyzerForm
                }
                return
            }
            "Quick" {
                if ($Debug) { Write-Host "Using saved Quick preference" -ForegroundColor Yellow }
                if (Start-QuickStart) {
                    Show-MainWiFiAnalyzerForm
                }
                return
            }
        }
    }
    
    # No preference saved, show choice dialog
    if ($Debug) {
        Write-Host "No saved preference found, showing choice dialog" -ForegroundColor Cyan
    }
    
    $choice = Show-StartupChoiceDialog
    
    if ($Debug) {
        Write-Host "User choice returned: '$choice'" -ForegroundColor Yellow
    }
    
    switch ($choice) {
        "Guided" {
            if ($Debug) { Write-Host "Starting Guided Setup..." -ForegroundColor Green }
            if (Start-GuidedSetup) {
                if ($Debug) { Write-Host "Guided setup completed, showing main form" -ForegroundColor Green }
                Show-MainWiFiAnalyzerForm
            } else {
                if ($Debug) { Write-Host "Guided setup was cancelled" -ForegroundColor Red }
            }
        }
        "Quick" {
            if ($Debug) { Write-Host "Starting Quick Start..." -ForegroundColor Green }
            if (Start-QuickStart) {
                if ($Debug) { Write-Host "Quick start completed, showing main form" -ForegroundColor Green }
                Show-MainWiFiAnalyzerForm
            } else {
                if ($Debug) { Write-Host "Quick start was cancelled" -ForegroundColor Red }
            }
        }
        "Cancel" {
            if ($Debug) { Write-Host "User cancelled startup dialog" -ForegroundColor Red }
        }
        default {
            if ($Debug) { 
                Write-Host "Unexpected choice returned: '$choice'" -ForegroundColor Red 
                Write-Host "Startup cancelled" -ForegroundColor Red
            }
        }
    }
}

# Command line help
function Show-Help {
    Write-Host @"
WiFi Analyzer - Usage Options:

INTERACTIVE MODE (Default):
  .\WiFiAnalyzer.ps1
  Shows startup choice dialog (Guided Setup vs Quick Start)

COMMAND LINE OPTIONS:
  .\WiFiAnalyzer.ps1 -QuickStart
    Skip all checks and go straight to WiFi scanning

  .\WiFiAnalyzer.ps1 -SkipPreflightCheck  
    Same as -QuickStart (alternative name)

  .\WiFiAnalyzer.ps1 -Debug
    Enable debug output for troubleshooting

PREFERENCE MANAGEMENT:
  The app remembers your choice if you check "Remember my choice"
  To reset: Delete `$env:APPDATA\WiFiAnalyzer_Preference.txt

EXAMPLES:
  First time users:     .\WiFiAnalyzer.ps1
  Experienced users:    .\WiFiAnalyzer.ps1 -QuickStart
  Troubleshooting:      .\WiFiAnalyzer.ps1 -Debug

"@ -ForegroundColor Cyan
}

# ===== ENTRY POINT =====

# Main entry point
if ($args -contains "-help" -or $args -contains "--help" -or $args -contains "/?") {
    Show-Help
} else {
    Start-WiFiAnalyzer
}