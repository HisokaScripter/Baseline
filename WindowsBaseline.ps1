# Windows System Baseline Script
# Purpose: Collect comprehensive system information for baseline documentation
# Author: System Administrator
# Date: Get-Date
# Requirements: PowerShell 5.0+ and Administrator privileges recommended

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "$env:TEMP\Baseline_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    
    [Parameter(Mandatory=$false)]
    [switch]$CreateArchive = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeSensitive = $false
)

# Set error action preference
$ErrorActionPreference = "Continue"

# Initialize variables
$script:LogFile = ""
$script:IsAdmin = $false

# Function to write colored output
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White",
        [string]$Type = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Type] $Message"
    
    # Color mapping
    $colorMap = @{
        "INFO" = "Green"
        "WARNING" = "Yellow"
        "ERROR" = "Red"
        "SECTION" = "Cyan"
    }
    
    if ($colorMap.ContainsKey($Type)) {
        Write-Host $logMessage -ForegroundColor $colorMap[$Type]
    } else {
        Write-Host $logMessage -ForegroundColor $Color
    }
    
    # Log to file if available
    if ($script:LogFile -and (Test-Path (Split-Path $script:LogFile -Parent))) {
        Add-Content -Path $script:LogFile -Value $logMessage
    }
}

# Function to check administrator privileges
function Test-AdminPrivileges {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to run command and capture output
function Invoke-BaselineCommand {
    param(
        [string]$Command,
        [string]$OutputFile,
        [string]$Description,
        [scriptblock]$ScriptBlock = $null
    )
    
    Write-ColorOutput "Collecting: $Description" -Type "INFO"
    
    $header = @"
# $Description
# Command: $Command
# Date: $(Get-Date)
# Computer: $env:COMPUTERNAME
# User: $env:USERNAME

"@
    
    Add-Content -Path $OutputFile -Value $header
    
    try {
        if ($ScriptBlock) {
            $result = & $ScriptBlock
        } else {
            $result = Invoke-Expression $Command
        }
        
        if ($result) {
            Add-Content -Path $OutputFile -Value ($result | Out-String)
        } else {
            Add-Content -Path $OutputFile -Value "No output returned"
        }
        
        Add-Content -Path $OutputFile -Value "Status: SUCCESS"
    }
    catch {
        Add-Content -Path $OutputFile -Value "Status: FAILED - $($_.Exception.Message)"
        Write-ColorOutput "Command failed: $Command - $($_.Exception.Message)" -Type "WARNING"
    }
    
    Add-Content -Path $OutputFile -Value ("=" * 80)
    Add-Content -Path $OutputFile -Value ""
}

# Function to collect system information
function Get-SystemInformation {
    Write-ColorOutput "=== SYSTEM INFORMATION ===" -Type "SECTION"
    $outputFile = Join-Path $OutputPath "01_System_Information.txt"
    
    Invoke-BaselineCommand -Command "Get-ComputerInfo" -OutputFile $outputFile -Description "Computer Information" -ScriptBlock {
        Get-ComputerInfo | Format-List
    }
    
    Invoke-BaselineCommand -Command "Get-WmiObject Win32_ComputerSystem" -OutputFile $outputFile -Description "Computer System Details" -ScriptBlock {
        Get-WmiObject Win32_ComputerSystem | Format-List
    }
    
    Invoke-BaselineCommand -Command "Get-WmiObject Win32_OperatingSystem" -OutputFile $outputFile -Description "Operating System Information" -ScriptBlock {
        Get-WmiObject Win32_OperatingSystem | Format-List
    }
    
    Invoke-BaselineCommand -Command "systeminfo" -OutputFile $outputFile -Description "System Information (systeminfo)" -ScriptBlock {
        systeminfo
    }
    
    Invoke-BaselineCommand -Command "Get-HotFix" -OutputFile $outputFile -Description "Installed Updates and Hotfixes" -ScriptBlock {
        Get-HotFix | Sort-Object InstalledOn -Descending | Format-Table -AutoSize
    }
    
    Invoke-BaselineCommand -Command "Get-TimeZone" -OutputFile $outputFile -Description "Time Zone Information" -ScriptBlock {
        Get-TimeZone | Format-List
    }
}

# Function to collect hardware information
function Get-HardwareInformation {
    Write-ColorOutput "=== HARDWARE INFORMATION ===" -Type "SECTION"
    $outputFile = Join-Path $OutputPath "02_Hardware_Information.txt"
    
    Invoke-BaselineCommand -Command "Get-WmiObject Win32_Processor" -OutputFile $outputFile -Description "Processor Information" -ScriptBlock {
        Get-WmiObject Win32_Processor | Format-List
    }
    
    Invoke-BaselineCommand -Command "Get-WmiObject Win32_PhysicalMemory" -OutputFile $outputFile -Description "Physical Memory" -ScriptBlock {
        Get-WmiObject Win32_PhysicalMemory | Format-Table DeviceLocator, Capacity, Speed, Manufacturer -AutoSize
    }
    
    Invoke-BaselineCommand -Command "Get-WmiObject Win32_LogicalDisk" -OutputFile $outputFile -Description "Disk Drives" -ScriptBlock {
        Get-WmiObject Win32_LogicalDisk | Format-Table DeviceID, FileSystem, Size, FreeSpace, @{Name="UsedSpace";Expression={$_.Size - $_.FreeSpace}} -AutoSize
    }
    
    Invoke-BaselineCommand -Command "Get-WmiObject Win32_PhysicalDisk" -OutputFile $outputFile -Description "Physical Disks" -ScriptBlock {
        Get-WmiObject Win32_PhysicalDisk | Format-List
    }
    
    Invoke-BaselineCommand -Command "Get-WmiObject Win32_VideoController" -OutputFile $outputFile -Description "Video Controllers" -ScriptBlock {
        Get-WmiObject Win32_VideoController | Format-List Name, AdapterRAM, DriverVersion, DriverDate
    }
    
    Invoke-BaselineCommand -Command "Get-PnpDevice" -OutputFile $outputFile -Description "Plug and Play Devices" -ScriptBlock {
        Get-PnpDevice | Where-Object {$_.Status -eq "OK"} | Format-Table FriendlyName, InstanceId, Status -AutoSize
    }
}

# Function to collect network information
function Get-NetworkInformation {
    Write-ColorOutput "=== NETWORK INFORMATION ===" -Type "SECTION"
    $outputFile = Join-Path $OutputPath "03_Network_Information.txt"
    
    Invoke-BaselineCommand -Command "Get-NetAdapter" -OutputFile $outputFile -Description "Network Adapters" -ScriptBlock {
        Get-NetAdapter | Format-Table Name, InterfaceDescription, LinkSpeed, Status -AutoSize
    }
    
    Invoke-BaselineCommand -Command "Get-NetIPAddress" -OutputFile $outputFile -Description "IP Addresses" -ScriptBlock {
        Get-NetIPAddress | Format-Table InterfaceAlias, IPAddress, PrefixLength, AddressFamily -AutoSize
    }
    
    Invoke-BaselineCommand -Command "Get-NetRoute" -OutputFile $outputFile -Description "Routing Table" -ScriptBlock {
        Get-NetRoute | Format-Table DestinationPrefix, NextHop, InterfaceAlias, RouteMetric -AutoSize
    }
    
    Invoke-BaselineCommand -Command "Get-DnsClientServerAddress" -OutputFile $outputFile -Description "DNS Configuration" -ScriptBlock {
        Get-DnsClientServerAddress | Format-Table InterfaceAlias, AddressFamily, ServerAddresses -AutoSize
    }
    
    Invoke-BaselineCommand -Command "ipconfig /all" -OutputFile $outputFile -Description "IP Configuration Details"
    
    Invoke-BaselineCommand -Command "netstat -an" -OutputFile $outputFile -Description "Network Connections"
    
    Invoke-BaselineCommand -Command "Get-NetFirewallProfile" -OutputFile $outputFile -Description "Windows Firewall Profiles" -ScriptBlock {
        Get-NetFirewallProfile | Format-List
    }
    
    Invoke-BaselineCommand -Command "Get-NetFirewallRule" -OutputFile $outputFile -Description "Firewall Rules Summary" -ScriptBlock {
        Get-NetFirewallRule | Where-Object {$_.Enabled -eq "True"} | Group-Object Direction | Format-Table Count, Name -AutoSize
    }
}

# Function to collect services and processes
function Get-ServicesAndProcesses {
    Write-ColorOutput "=== SERVICES AND PROCESSES ===" -Type "SECTION"
    $outputFile = Join-Path $OutputPath "04_Services_Processes.txt"
    
    Invoke-BaselineCommand -Command "Get-Service" -OutputFile $outputFile -Description "All Services" -ScriptBlock {
        Get-Service | Sort-Object Status, Name | Format-Table Name, Status, StartType, DisplayName -AutoSize
    }
    
    Invoke-BaselineCommand -Command "Get-Service | Where {`$_.Status -eq 'Running'}" -OutputFile $outputFile -Description "Running Services" -ScriptBlock {
        Get-Service | Where-Object {$_.Status -eq "Running"} | Sort-Object Name | Format-Table Name, StartType, DisplayName -AutoSize
    }
    
    Invoke-BaselineCommand -Command "Get-Process" -OutputFile $outputFile -Description "Running Processes" -ScriptBlock {
        Get-Process | Sort-Object CPU -Descending | Select-Object Name, Id, CPU, WorkingSet, Path | Format-Table -AutoSize
    }
    
    Invoke-BaselineCommand -Command "Get-WmiObject Win32_StartupCommand" -OutputFile $outputFile -Description "Startup Programs" -ScriptBlock {
        Get-WmiObject Win32_StartupCommand | Format-Table Command, Location, User -AutoSize
    }
    
    Invoke-BaselineCommand -Command "schtasks /query /fo csv /v" -OutputFile $outputFile -Description "Scheduled Tasks"
    
    Invoke-BaselineCommand -Command "Get-ScheduledTask" -OutputFile $outputFile -Description "Scheduled Tasks (PowerShell)" -ScriptBlock {
        Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} | Format-Table TaskName, State, Author, Description -AutoSize
    }
}

# Function to collect user and group information
function Get-UserAndGroupInformation {
    Write-ColorOutput "=== USER AND GROUP INFORMATION ===" -Type "SECTION"
    $outputFile = Join-Path $OutputPath "05_Users_Groups.txt"
    
    Invoke-BaselineCommand -Command "Get-LocalUser" -OutputFile $outputFile -Description "Local Users" -ScriptBlock {
        Get-LocalUser | Format-Table Name, Enabled, LastLogon, PasswordLastSet, PasswordRequired -AutoSize
    }
    
    Invoke-BaselineCommand -Command "Get-LocalGroup" -OutputFile $outputFile -Description "Local Groups" -ScriptBlock {
        Get-LocalGroup | Format-Table Name, Description -AutoSize
    }
    
    Invoke-BaselineCommand -Command "net user" -OutputFile $outputFile -Description "User Accounts (net user)"
    
    Invoke-BaselineCommand -Command "net localgroup" -OutputFile $outputFile -Description "Local Groups (net localgroup)"
    
    Invoke-BaselineCommand -Command "whoami /all" -OutputFile $outputFile -Description "Current User Information"
    
    Invoke-BaselineCommand -Command "Get-WmiObject Win32_UserProfile" -OutputFile $outputFile -Description "User Profiles" -ScriptBlock {
        Get-WmiObject Win32_UserProfile | Format-Table LocalPath, LastUseTime, Loaded -AutoSize
    }
    
    if ($script:IsAdmin) {
        Invoke-BaselineCommand -Command "Get-EventLog -LogName Security -Newest 20 -InstanceId 4624" -OutputFile $outputFile -Description "Recent Successful Logons" -ScriptBlock {
            try {
                Get-EventLog -LogName Security -Newest 20 -InstanceId 4624 | Format-Table TimeGenerated, UserName, MachineName -AutoSize
            } catch {
                Write-Output "Unable to access Security event log or no logon events found"
            }
        }
    }
}

# Function to collect security information
function Get-SecurityInformation {
    Write-ColorOutput "=== SECURITY INFORMATION ===" -Type "SECTION"
    $outputFile = Join-Path $OutputPath "06_Security_Information.txt"
    
    Invoke-BaselineCommand -Command "Get-MpComputerStatus" -OutputFile $outputFile -Description "Windows Defender Status" -ScriptBlock {
        try {
            Get-MpComputerStatus | Format-List
        } catch {
            Write-Output "Windows Defender module not available"
        }
    }
    
    Invoke-BaselineCommand -Command "Get-WmiObject Win32_Product" -OutputFile $outputFile -Description "Installed Antivirus Products" -ScriptBlock {
        Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct | Format-List displayName, productState, timestamp
    }
    
    Invoke-BaselineCommand -Command "secedit /export /cfg security_policy.inf" -OutputFile $outputFile -Description "Security Policy Export" -ScriptBlock {
        $tempFile = "$env:TEMP\security_policy.inf"
        secedit /export /cfg $tempFile /quiet
        if (Test-Path $tempFile) {
            Get-Content $tempFile
            Remove-Item $tempFile -Force
        }
    }
    
    Invoke-BaselineCommand -Command "gpresult /r" -OutputFile $outputFile -Description "Group Policy Results"
    
    Invoke-BaselineCommand -Command "Get-WmiObject Win32_LoggedOnUser" -OutputFile $outputFile -Description "Currently Logged On Users" -ScriptBlock {
        Get-WmiObject Win32_LoggedOnUser | Format-Table Antecedent, Dependent -AutoSize
    }
    
    Invoke-BaselineCommand -Command "Get-SmbShare" -OutputFile $outputFile -Description "SMB Shares" -ScriptBlock {
        Get-SmbShare | Format-Table Name, Path, Description -AutoSize
    }
    
    if ($script:IsAdmin) {
        Invoke-BaselineCommand -Command "Get-WinEvent -FilterHashtable @{LogName='System'; Level=2,3} -MaxEvents 20" -OutputFile $outputFile -Description "Recent System Errors and Warnings" -ScriptBlock {
            try {
                Get-WinEvent -FilterHashtable @{LogName='System'; Level=2,3} -MaxEvents 20 | Format-Table TimeCreated, Id, LevelDisplayName, Message -AutoSize
            } catch {
                Write-Output "Unable to access System event log"
            }
        }
    }
}

# Function to collect software information
function Get-SoftwareInformation {
    Write-ColorOutput "=== SOFTWARE INFORMATION ===" -Type "SECTION"
    $outputFile = Join-Path $OutputPath "07_Software_Information.txt"
    
    Invoke-BaselineCommand -Command "Get-WmiObject Win32_Product" -OutputFile $outputFile -Description "Installed Software (WMI)" -ScriptBlock {
        Get-WmiObject Win32_Product | Sort-Object Name | Format-Table Name, Version, Vendor -AutoSize
    }
    
    Invoke-BaselineCommand -Command "Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -OutputFile $outputFile -Description "Installed Programs (Registry)" -ScriptBlock {
        Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
        Where-Object {$_.DisplayName} | 
        Sort-Object DisplayName | 
        Format-Table DisplayName, DisplayVersion, Publisher -AutoSize
    }
    
    Invoke-BaselineCommand -Command "Get-WindowsFeature" -OutputFile $outputFile -Description "Windows Features" -ScriptBlock {
        try {
            Get-WindowsFeature | Where-Object {$_.InstallState -eq "Installed"} | Format-Table Name, DisplayName, InstallState -AutoSize
        } catch {
            Write-Output "Get-WindowsFeature not available (likely not Server OS)"
        }
    }
    
    Invoke-BaselineCommand -Command "Get-WindowsCapability -Online" -OutputFile $outputFile -Description "Windows Capabilities" -ScriptBlock {
        try {
            Get-WindowsCapability -Online | Where-Object {$_.State -eq "Installed"} | Format-Table Name, State -AutoSize
        } catch {
            Write-Output "Get-WindowsCapability not available"
        }
    }
    
    Invoke-BaselineCommand -Command "dism /online /get-features /format:table" -OutputFile $outputFile -Description "DISM Features"
}

# Function to collect environment and registry information
function Get-EnvironmentInformation {
    Write-ColorOutput "=== ENVIRONMENT AND REGISTRY ===" -Type "SECTION"
    $outputFile = Join-Path $OutputPath "08_Environment_Registry.txt"
    
    Invoke-BaselineCommand -Command "Get-ChildItem Env:" -OutputFile $outputFile -Description "Environment Variables" -ScriptBlock {
        Get-ChildItem Env: | Sort-Object Name | Format-Table Name, Value -AutoSize
    }
    
    Invoke-BaselineCommand -Command "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'" -OutputFile $outputFile -Description "Windows Version Registry" -ScriptBlock {
        Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | Format-List
    }
    
    Invoke-BaselineCommand -Command "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'" -OutputFile $outputFile -Description "System Environment Variables" -ScriptBlock {
        Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' | Format-List
    }
    
    Invoke-BaselineCommand -Command "Get-WmiObject Win32_Environment" -OutputFile $outputFile -Description "Environment Variables (WMI)" -ScriptBlock {
        Get-WmiObject Win32_Environment | Format-Table Name, VariableValue, UserName -AutoSize
    }
    
    Invoke-BaselineCommand -Command "reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -OutputFile $outputFile -Description "Registry Run Keys (HKLM)"
    
    Invoke-BaselineCommand -Command "reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -OutputFile $outputFile -Description "Registry Run Keys (HKCU)"
}

# Function to collect event logs
function Get-EventLogInformation {
    Write-ColorOutput "=== EVENT LOGS ===" -Type "SECTION"
    $outputFile = Join-Path $OutputPath "09_Event_Logs.txt"
    
    Invoke-BaselineCommand -Command "Get-EventLog -List" -OutputFile $outputFile -Description "Available Event Logs" -ScriptBlock {
        Get-EventLog -List | Format-Table Log, MaximumKilobytes, OverflowAction, MinimumRetentionDays -AutoSize
    }
    
    if ($script:IsAdmin) {
        Invoke-BaselineCommand -Command "Get-EventLog -LogName System -Newest 10" -OutputFile $outputFile -Description "Recent System Events" -ScriptBlock {
            try {
                Get-EventLog -LogName System -Newest 10 | Format-Table TimeGenerated, EntryType, Source, Message -AutoSize
            } catch {
                Write-Output "Unable to access System event log"
            }
        }
        
        Invoke-BaselineCommand -Command "Get-EventLog -LogName Application -Newest 10" -OutputFile $outputFile -Description "Recent Application Events" -ScriptBlock {
            try {
                Get-EventLog -LogName Application -Newest 10 | Format-Table TimeGenerated, EntryType, Source, Message -AutoSize
            } catch {
                Write-Output "Unable to access Application event log"
            }
        }
    }
    
    Invoke-BaselineCommand -Command "wevtutil el" -OutputFile $outputFile -Description "Windows Event Logs List"
}

# Function to collect performance information
function Get-PerformanceInformation {
    Write-ColorOutput "=== PERFORMANCE INFORMATION ===" -Type "SECTION"
    $outputFile = Join-Path $OutputPath "10_Performance_Information.txt"
    
    Invoke-BaselineCommand -Command "Get-Counter '\Memory\Available MBytes'" -OutputFile $outputFile -Description "Available Memory" -ScriptBlock {
        (Get-Counter '\Memory\Available MBytes').CounterSamples | Format-Table Path, CookedValue -AutoSize
    }
    
    Invoke-BaselineCommand -Command "Get-Counter '\Processor(_Total)\% Processor Time'" -OutputFile $outputFile -Description "CPU Usage" -ScriptBlock {
        (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples | Format-Table Path, CookedValue -AutoSize
    }
    
    Invoke-BaselineCommand -Command "Get-WmiObject Win32_PageFile" -OutputFile $outputFile -Description "Page File Information" -ScriptBlock {
        Get-WmiObject Win32_PageFile | Format-List
    }
    
    Invoke-BaselineCommand -Command "Get-WmiObject Win32_PageFileUsage" -OutputFile $outputFile -Description "Page File Usage" -ScriptBlock {
        Get-WmiObject Win32_PageFileUsage | Format-List
    }
    
    Invoke-BaselineCommand -Command "typeperf '\Memory\Available MBytes' -sc 1" -OutputFile $outputFile -Description "Memory Performance Sample"
    
    Invoke-BaselineCommand -Command "wmic cpu get loadpercentage /value" -OutputFile $outputFile -Description "CPU Load Percentage"
}

# Function to generate summary report
function New-SummaryReport {
    Write-ColorOutput "=== GENERATING SUMMARY REPORT ===" -Type "SECTION"
    $summaryFile = Join-Path $OutputPath "00_SUMMARY.txt"
    
    $computerInfo = Get-ComputerInfo
    $osInfo = Get-WmiObject Win32_OperatingSystem
    $systemInfo = Get-WmiObject Win32_ComputerSystem
    
    $summary = @"
WINDOWS SYSTEM BASELINE SUMMARY
===============================
Generated: $(Get-Date)
Computer: $env:COMPUTERNAME
Domain: $env:USERDOMAIN
Script Version: 1.0
Admin Privileges: $script:IsAdmin

SYSTEM OVERVIEW:
- OS: $($osInfo.Caption) $($osInfo.Version)
- Architecture: $($osInfo.OSArchitecture)
- Install Date: $($osInfo.InstallDate)
- Last Boot: $($osInfo.LastBootUpTime)
- Uptime: $((Get-Date) - $osInfo.ConvertToDateTime($osInfo.LastBootUpTime))

HARDWARE SUMMARY:
- Manufacturer: $($systemInfo.Manufacturer)
- Model: $($systemInfo.Model)
- Processors: $($systemInfo.NumberOfProcessors)
- Total Memory: $([math]::Round($systemInfo.TotalPhysicalMemory/1GB, 2)) GB
- System Type: $($systemInfo.SystemType)

NETWORK SUMMARY:
- Computer Name: $($systemInfo.Name)
- Workgroup/Domain: $($systemInfo.Domain)
- Network Adapters: $(((Get-NetAdapter | Where-Object {$_.Status -eq "Up"}).Count))

SECURITY STATUS:
- Windows Defender: $(try { (Get-MpComputerStatus).AntivirusEnabled } catch { "Unknown" })
- Firewall Domain Profile: $(try { (Get-NetFirewallProfile -Name Domain).Enabled } catch { "Unknown" })
- UAC Status: $(try { (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA } catch { "Unknown" })

FILES GENERATED:
"@

    # Add list of generated files
    Get-ChildItem $OutputPath -Filter "*.txt" | Sort-Object Name | ForEach-Object {
        $summary += "`n- $($_.Name)"
    }
    
    $summary += @"

`nBASELINE DIRECTORY: $OutputPath

This baseline can be used for:
- System documentation and inventory
- Change management and tracking
- Security auditing and compliance
- Troubleshooting and diagnostics
- Disaster recovery planning
- Configuration management

RECOMMENDATIONS:
- Store this baseline in a secure location
- Review and update baselines regularly
- Compare against future baselines to detect changes
- Use for compliance auditing and security assessments
"@
    
    Set-Content -Path $summaryFile -Value $summary
    Write-ColorOutput "Summary report created: $summaryFile" -Type "INFO"
}

# Function to create archive
function New-BaselineArchive {
    if (-not $CreateArchive) { return }
    
    Write-ColorOutput "=== CREATING ARCHIVE ===" -Type "SECTION"
    $archivePath = "$OutputPath.zip"
    
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory($OutputPath, $archivePath)
        
        $archiveInfo = Get-Item $archivePath
        Write-ColorOutput "Archive created: $archivePath" -Type "INFO"
        Write-ColorOutput "Archive size: $([math]::Round($archiveInfo.Length/1MB, 2)) MB" -Type "INFO"
    }
    catch {
        Write-ColorOutput "Failed to create archive: $($_.Exception.Message)" -Type "ERROR"
    }
}

# Main execution function
function Start-WindowsBaseline {
    # Display banner
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║            Windows System Baseline Script           ║" -ForegroundColor Cyan
    Write-Host "║                                                      ║" -ForegroundColor Cyan
    Write-Host "║  Collects comprehensive system information for      ║" -ForegroundColor Cyan
    Write-Host "║  baseline documentation and analysis                ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # Check privileges
    $script:IsAdmin = Test-AdminPrivileges
    if ($script:IsAdmin) {
        Write-ColorOutput "Running with Administrator privileges - full access available" -Type "INFO"
    } else {
        Write-ColorOutput "Running without Administrator privileges - some information may be limited" -Type "WARNING"
        Write-ColorOutput "For complete baseline, run as Administrator" -Type "WARNING"
    }
    
    # Create output directory
    try {
        if (-not (Test-Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }
        Write-ColorOutput "Created baseline directory: $OutputPath" -Type "INFO"
    }
    catch {
        Write-ColorOutput "Failed to create output directory: $($_.Exception.Message)" -Type "ERROR"
        return
    }
    
    # Initialize log file
    $script:LogFile = Join-Path $OutputPath "baseline.log"
    Write-ColorOutput "Baseline collection started: $(Get-Date)" -Type "INFO"
    
    # Collect all information
    try {
        Get-SystemInformation
        Get-HardwareInformation
        Get-NetworkInformation
        Get-ServicesAndProcesses
        Get-UserAndGroupInformation
        Get-SecurityInformation
        Get-SoftwareInformation
        Get-EnvironmentInformation
        Get-EventLogInformation
        Get-PerformanceInformation
        
        # Generate summary and archive
        New-SummaryReport
        New-BaselineArchive
        
        Write-ColorOutput "=== BASELINE COLLECTION COMPLETE ===" -Type "SECTION"
        Write-ColorOutput "Baseline directory: $OutputPath" -Type "INFO"
        Write-ColorOutput "Log file: $script:LogFile" -Type "INFO"
        Write-ColorOutput "All files have been collected and organized" -Type "INFO"
        
        if ($CreateArchive -and (Test-Path "$OutputPath.zip")) {
            Write-ColorOutput "Archive created: $OutputPath.zip" -Type "INFO"
        }
        
        Write-Host "`nBaseline collection completed successfully!" -ForegroundColor Green
        Write-Host "Review the files in: $OutputPath" -ForegroundColor Yellow
    }
    catch {
        Write-ColorOutput "An error occurred during baseline collection: $($_.Exception.Message)" -Type "ERROR"
    }
}

# Execute main function
Start-WindowsBaseline