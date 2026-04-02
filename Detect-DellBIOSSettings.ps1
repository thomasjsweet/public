<#
.SYNOPSIS
    Intune Proactive Remediation - Detect Dell BIOS Settings (MSUefiCA, CapsuleFirmwareUpdate)
.DESCRIPTION
    Checks whether MSUefiCA and CapsuleFirmwareUpdate are Enabled via Dell CCTK.
    Exit 0 = compliant (both Enabled, or non-Dell device, or CCTK not installed)
    Exit 1 = non-compliant (one or both Disabled/unavailable)
.NOTES
    Run context: SYSTEM
#>

$LogPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\DellBIOSSettings.log"
$CCTKPath = "C:\Program Files\Dell\EndpointConfigure\x86_64\cctk.exe"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "$timestamp [DETECT] $Message"
    try {
        $logDir = Split-Path -Path $LogPath -Parent
        if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
        Add-Content -Path $LogPath -Value $entry -ErrorAction Stop
    } catch {
        # Logging failure should not break detection
    }
}

# Check if Dell device
$manufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer
if ($manufacturer -notmatch "Dell") {
    Write-Output "Not a Dell device ($manufacturer). Compliant."
    Write-Log "Not a Dell device ($manufacturer). Skipping."
    exit 0
}

Write-Log "Dell device detected: $manufacturer"

# Check if CCTK is installed
if (-not (Test-Path $CCTKPath)) {
    Write-Output "Dell CCTK not installed. Compliant."
    Write-Log "CCTK not found at $CCTKPath. Skipping."
    exit 0
}

Write-Log "CCTK found at $CCTKPath"

# Query MSUefiCA
try {
    $msUefiResult = & $CCTKPath --MSUefiCA 2>&1
    $msUefiValue = ($msUefiResult | Out-String).Trim()
    Write-Log "MSUefiCA query result: $msUefiValue"
} catch {
    $msUefiValue = "Error: $_"
    Write-Log "MSUefiCA query failed: $_"
}

# Query CapsuleFirmwareUpdate
try {
    $capsuleResult = & $CCTKPath --CapsuleFirmwareUpdate 2>&1
    $capsuleValue = ($capsuleResult | Out-String).Trim()
    Write-Log "CapsuleFirmwareUpdate query result: $capsuleValue"
} catch {
    $capsuleValue = "Error: $_"
    Write-Log "CapsuleFirmwareUpdate query failed: $_"
}

Write-Output "MSUefiCA=$msUefiValue | CapsuleFirmwareUpdate=$capsuleValue"

# Evaluate compliance
# "not available" means the model doesn't support the option - treat as compliant (can't fix)
$msOK = ($msUefiValue -match "Enabled") -or ($msUefiValue -match "not available")
$capsuleOK = ($capsuleValue -match "Enabled") -or ($capsuleValue -match "not available")

if ($msOK -and $capsuleOK) {
    Write-Output "Compliant. MSUefiCA=$msUefiValue | CapsuleFirmwareUpdate=$capsuleValue"
    Write-Log "Compliant."
    exit 0
} else {
    Write-Output "Non-compliant: MSUefiCA OK=$msOK, CapsuleFirmwareUpdate OK=$capsuleOK"
    Write-Log "Non-compliant: MSUefiCA OK=$msOK, CapsuleFirmwareUpdate OK=$capsuleOK"
    exit 1
}
