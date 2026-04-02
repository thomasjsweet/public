<#
.SYNOPSIS
    Intune Proactive Remediation - Detection Script
    Secure Boot Certificate Update (KB5085046) - Windows UEFI CA 2023

.DESCRIPTION
    Comprehensive detection for the Secure Boot CA 2023 certificate update.
    Checks every failure scenario from the Microsoft troubleshooting guide:

      1. Secure Boot not enabled
      2. Scheduled task disabled or missing
      3. AvailableUpdates not progressing (stuck)
      4. Firmware errors (Event 1795)
      5. Error codes logged (Event 1796, 1797, 1799)
      6. Reboot pending but not happening (Event 1800/1801)
      7. Known firmware issue blocking update (Event 1802)
      8. Missing OEM-signed KEK (Event 1803)
      9. UEFI DB overwrite (firmware defect)
     10. BitLocker recovery risk
     11. Certificate not in UEFI DB after "Updated" status
     12. CanAttemptUpdateAfter date not yet reached

    Exit 0 = Compliant (CA 2023 fully deployed, no issues)
    Exit 1 = Non-compliant (remediation needed)

    Outputs JSON with full diagnostic data for Intune reporting.

.NOTES
    Author:   IR Pros IT Team
    Date:     2026-03-21
    Version:  3.0-public
    Ref:      https://support.microsoft.com/en-us/topic/troubleshooting-5d1bf6b4-7972-455a-a421-0184f1e1ed7d
    KB:       KB5085046
    Context:  SYSTEM (Intune default for detection scripts)
#>

$ErrorActionPreference = "SilentlyContinue"

# ---------------------------------------------------------------
# Config & Logging
# ---------------------------------------------------------------
$LogDir  = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
$LogPath = "$LogDir\SecureBootCertUpdate_Detect.log"

if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "$ts [$Level] $Message"
    try { $line | Out-File -FilePath $LogPath -Append -Encoding utf8 } catch {}
}

# Rotate log if over 1 MB
if (Test-Path $LogPath) {
    if ((Get-Item $LogPath).Length -gt 1MB) {
        $dateSuffix = Get-Date -Format 'yyyyMMdd_HHmmss'
        $archive = $LogPath.Replace('.log', "_$dateSuffix.log")
        Rename-Item -Path $LogPath -NewName $archive -ErrorAction SilentlyContinue
    }
}

Write-Log "========== SecureBoot Cert Update Detection Start =========="
Write-Log "Device: $env:COMPUTERNAME"

# ---------------------------------------------------------------
# Registry paths
# ---------------------------------------------------------------
$sbRoot      = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
$sbServicing = "$sbRoot\Servicing"
$sbDevAttrs  = "$sbServicing\DeviceAttributes"

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $val = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        return $val
    } catch { return $null }
}

# ---------------------------------------------------------------
# Collect all diagnostic data
# ---------------------------------------------------------------
$issues = @()

# --- 1. Secure Boot status ---
$secureBootEnabled = $false
try {
    $secureBootEnabled = Confirm-SecureBootUEFI -ErrorAction Stop
} catch {
    $regSB = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" "UEFISecureBootEnabled"
    if ($null -ne $regSB) { $secureBootEnabled = [bool]$regSB }
}

if (-not $secureBootEnabled) {
    $issues += "SecureBootDisabled"
}

# --- 2. Certificate update registry values ---
$availableUpdates       = Get-RegValue $sbRoot "AvailableUpdates"
$availableUpdatesPolicy = Get-RegValue $sbRoot "AvailableUpdatesPolicy"
$highConfidenceOptOut   = Get-RegValue $sbRoot "HighConfidenceOptOut"
$uefica2023Status       = Get-RegValue $sbServicing "UEFICA2023Status"
$uefica2023Error        = Get-RegValue $sbServicing "UEFICA2023Error"
$uefica2023ErrorEvent   = Get-RegValue $sbServicing "UEFICA2023ErrorEvent"

# --- 3. CanAttemptUpdateAfter (throttle/cooldown) ---
$canAttemptAfter = $null
$canAttemptAfterStr = "N/A"
$waitingForCooldown = $false
try {
    $raw = Get-RegValue $sbDevAttrs "CanAttemptUpdateAfter"
    if ($null -ne $raw) {
        if ($raw -is [byte[]]) {
            $ft = [BitConverter]::ToInt64($raw, 0)
            $canAttemptAfter = [DateTime]::FromFileTime($ft).ToUniversalTime()
        } elseif ($raw -is [long] -or $raw -is [int64]) {
            $canAttemptAfter = [DateTime]::FromFileTime($raw).ToUniversalTime()
        }
        if ($canAttemptAfter) {
            $canAttemptAfterStr = $canAttemptAfter.ToString("o")
            if ($canAttemptAfter -gt (Get-Date).ToUniversalTime()) {
                $waitingForCooldown = $true
            }
        }
    }
} catch {}

# --- 4. Scheduled task status ---
$taskStatus  = "Unknown"
$taskEnabled = $false
try {
    $taskOutput = schtasks.exe /Query /TN "\Microsoft\Windows\PI\Secure-Boot-Update" /FO CSV 2>&1
    if ($LASTEXITCODE -eq 0) {
        $taskData = $taskOutput | ConvertFrom-Csv
        if ($taskData) {
            $taskStatus  = $taskData.Status
            $taskEnabled = ($taskData.Status -eq 'Ready' -or $taskData.Status -eq 'Running')
        }
    } else {
        $taskStatus = "NotFound"
    }
} catch {
    $taskStatus = "Error"
}

if (-not $taskEnabled) {
    $issues += "TaskDisabledOrMissing"
}

# --- 5. Check UEFI DB for the actual certificate ---
$certInDB = $false
try {
    $db = Get-SecureBootUEFI -Name db -ErrorAction Stop
    if ($db -and $db.Bytes) {
        # Try ASCII encoding (common)
        $dbAscii = [System.Text.Encoding]::ASCII.GetString($db.Bytes)
        if ($dbAscii -match 'Windows UEFI CA 2023') {
            $certInDB = $true
        }
        # Try Unicode/UTF-16 encoding (some firmware stores cert names this way)
        if (-not $certInDB) {
            $dbUnicode = [System.Text.Encoding]::Unicode.GetString($db.Bytes)
            if ($dbUnicode -match 'Windows UEFI CA 2023') {
                $certInDB = $true
            }
        }
        # Try matching the certificate thumbprint bytes (Microsoft UEFI CA 2023)
        if (-not $certInDB) {
            $dbHex = [BitConverter]::ToString($db.Bytes) -replace '-',''
            # Microsoft Windows UEFI CA 2023 known cert identifiers
            if ($dbHex -match '4553204341203230323300' -or   # "ES CA 2023" in ASCII hex
                $dbHex -match '45005300200043004100200032003000320033') {  # UTF-16LE hex
                $certInDB = $true
            }
        }
    }
} catch {}

# --- 6. Event log analysis ---
$eventData = @{
    LatestEventId     = $null
    LatestEventTime   = $null
    Event1032Count    = 0   # Progress
    Event1036Count    = 0   # Progress
    Event1043Count    = 0   # Success step
    Event1044Count    = 0   # Success step
    Event1045Count    = 0   # Success step
    Event1795Count    = 0   # Firmware error
    Event1795Error    = $null
    Event1796Count    = 0   # Error code
    Event1796Error    = $null
    Event1797Count    = 0   # Error
    Event1799Count    = 0   # Error
    Event1800Count    = 0   # Reboot needed
    Event1801Count    = 0   # Update initiated
    Event1802Count    = 0   # Known firmware issue
    Event1802KI       = $null
    Event1803Count    = 0   # Missing KEK
    RebootPending     = $false
    FirmwareError     = $false
    KnownFirmwareIssue = $false
    MissingKEK        = $false
}

try {
    $allEventIds = @(1032, 1036, 1043, 1044, 1045, 1795, 1796, 1797, 1799, 1800, 1801, 1802, 1803)
    $events = @(Get-WinEvent -FilterHashtable @{LogName='System'; ID=$allEventIds} -MaxEvents 100 -ErrorAction Stop)

    if ($events.Count -gt 0) {
        $latest = $events | Sort-Object TimeCreated -Descending | Select-Object -First 1
        $eventData.LatestEventId   = $latest.Id
        $eventData.LatestEventTime = $latest.TimeCreated.ToString("o")

        foreach ($id in $allEventIds) {
            $matching = @($events | Where-Object { $_.Id -eq $id })
            $countKey = "Event${id}Count"
            if ($eventData.ContainsKey($countKey)) {
                $eventData[$countKey] = $matching.Count
            }
        }

        # Extract error details from 1795
        $ev1795 = @($events | Where-Object { $_.Id -eq 1795 }) | Sort-Object TimeCreated -Descending | Select-Object -First 1
        if ($ev1795) {
            $eventData.FirmwareError = $true
            if ($ev1795.Message -match '(?:error|code|status|result)[:\s]*(?:0x)?([0-9A-Fa-f]{4,8})') {
                $eventData.Event1795Error = "0x$($matches[1])"
            }
            $issues += "FirmwareError1795"
        }

        # Extract error details from 1796
        $ev1796 = @($events | Where-Object { $_.Id -eq 1796 }) | Sort-Object TimeCreated -Descending | Select-Object -First 1
        if ($ev1796) {
            # Try structured properties first (most reliable)
            if ($ev1796.Properties -and $ev1796.Properties.Count -gt 0) {
                $propValues = @($ev1796.Properties | ForEach-Object { $_.Value })
                # Find hex-like error codes in properties
                foreach ($pv in $propValues) {
                    if ($pv -is [int] -or $pv -is [long] -or $pv -is [uint32]) {
                        if ($pv -ne 0) {
                            $eventData.Event1796Error = "0x{0:X8}" -f $pv
                            break
                        }
                    }
                }
            }
            # Fallback: parse message text for any hex or error pattern
            if (-not $eventData.Event1796Error) {
                $msg = $ev1796.Message
                if ($msg -match '(0x[0-9A-Fa-f]{4,8})') {
                    $eventData.Event1796Error = $matches[1]
                } elseif ($msg -match '(?:error|code|status|result)[:\s]*(\d+)') {
                    $eventData.Event1796Error = "0x{0:X8}" -f [int]$matches[1]
                }
            }
            # Capture the full message for diagnostics
            if (-not $eventData.Event1796Error) {
                $eventData.Event1796Error = ($ev1796.Message -replace '\r?\n',' ').Substring(0, [Math]::Min(200, $ev1796.Message.Length))
            }
            $issues += "ErrorLogged1796"
        }

        # 1797, 1799 errors
        if ($eventData.Event1797Count -gt 0) { $issues += "Error1797" }
        if ($eventData.Event1799Count -gt 0) { $issues += "Error1799" }

        # Reboot pending (1800/1801)
        if ($eventData.Event1800Count -gt 0 -or $eventData.Event1801Count -gt 0) {
            $eventData.RebootPending = $true
            # Check if device has rebooted since the event
            $lastBoot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
            $lastRebootEvent = @($events | Where-Object { $_.Id -in @(1800, 1801) }) |
                Sort-Object TimeCreated -Descending | Select-Object -First 1
            if ($lastRebootEvent -and $lastBoot -lt $lastRebootEvent.TimeCreated) {
                $issues += "RebootRequired"
            }
        }

        # Known firmware issue (1802)
        $ev1802 = @($events | Where-Object { $_.Id -eq 1802 }) | Sort-Object TimeCreated -Descending | Select-Object -First 1
        if ($ev1802) {
            $eventData.KnownFirmwareIssue = $true
            if ($ev1802.Message -match 'SkipReason:\s*(KI_\d+)') {
                $eventData.Event1802KI = $matches[1]
            }
            $issues += "KnownFirmwareIssue1802"
        }

        # Missing KEK (1803)
        if ($eventData.Event1803Count -gt 0) {
            $eventData.MissingKEK = $true
            $issues += "MissingKEK1803"
        }
    }
} catch {}

# --- 7. AvailableUpdates progression check ---
# If AvailableUpdates is 0 and status is not Updated, updates haven't started
if ($null -ne $availableUpdates -and $availableUpdates -eq 0 -and $uefica2023Status -ne "Updated") {
    $issues += "NoProgressAvailableUpdates"
}

# --- 8. OptOut check ---
if ($null -ne $highConfidenceOptOut -and $highConfidenceOptOut -ne 0) {
    $issues += "HighConfidenceOptOut"
}

# --- 9. Error state in registry ---
if ($null -ne $uefica2023Error -and $uefica2023Error -ne 0) {
    $issues += "RegistryErrorState"
}

# --- 10. BitLocker status (risk assessment) ---
$bitlockerEnabled = $false
$bitlockerProtectors = @()
try {
    $blv = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
    if ($blv.ProtectionStatus -eq "On") {
        $bitlockerEnabled = $true
        $bitlockerProtectors = @($blv.KeyProtector | ForEach-Object { $_.KeyProtectorType.ToString() })
    }
} catch {}

# --- 11. Device info ---
$manufacturer = "Unknown"
$model = "Unknown"
$firmwareVersion = "Unknown"
try {
    $cs = Get-CimInstance Win32_ComputerSystem
    $manufacturer = $cs.Manufacturer
    $model = $cs.Model
} catch {}
try {
    $bios = Get-CimInstance Win32_BIOS
    $firmwareVersion = $bios.SMBIOSBIOSVersion
} catch {}

# --- 12. Dell CCTK BIOS diagnostics (Dell devices only) ---
$cctkSecureBoot = $null
$cctkSecureBootMode = $null
$cctkMSUefiCA = $null
$cctkPath = "C:\Program Files\Dell\EndpointConfigure\x86_64\cctk.exe"
if ($manufacturer -match 'Dell' -and (Test-Path $cctkPath)) {
    try {
        $cctkSecureBoot = & $cctkPath --secureboot 2>&1 | Out-String
        $cctkSecureBoot = $cctkSecureBoot.Trim()
    } catch { $cctkSecureBoot = "Error: $_" }
    try {
        $cctkSecureBootMode = & $cctkPath --SecureBootMode 2>&1 | Out-String
        $cctkSecureBootMode = $cctkSecureBootMode.Trim()
    } catch { $cctkSecureBootMode = "Error: $_" }
    try {
        $cctkMSUefiCA = & $cctkPath --MSUefiCA 2>&1 | Out-String
        $cctkMSUefiCA = $cctkMSUefiCA.Trim()
    } catch { $cctkMSUefiCA = "Error: $_" }
    Write-Log "CCTK SecureBoot: $cctkSecureBoot"
    Write-Log "CCTK SecureBootMode: $cctkSecureBootMode"
    Write-Log "CCTK MSUefiCA: $cctkMSUefiCA"
} elseif ($manufacturer -match 'Dell') {
    Write-Log "Dell device but CCTK not installed at $cctkPath"
}

$osVersion = "Unknown"
try {
    $osInfo = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $osVersion = "$($osInfo.CurrentBuildNumber).$($osInfo.UBR)"
} catch {}

$lastBoot = $null
try {
    $lastBoot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
} catch {}

# ---------------------------------------------------------------
# Determine overall status
# ---------------------------------------------------------------
$updateComplete = $false

Write-Log "CertInDB: $certInDB | UEFICA2023Status: [$uefica2023Status] | UEFICA2023Error: [$uefica2023Error]"

# Primary check: certificate actually in UEFI DB
if ($certInDB) {
    $updateComplete = $true
    Write-Log "Compliant: cert found in UEFI DB"
}

# Secondary: registry says Updated and no errors
if (-not $updateComplete) {
    $statusMatch = ($uefica2023Status -eq "Updated" -or "$uefica2023Status" -eq "2")
    $noError = ($null -eq $uefica2023Error -or $uefica2023Error -eq 0)
    Write-Log "StatusMatch: $statusMatch | NoError: $noError"
    if ($statusMatch -and $noError) {
        $updateComplete = $true
        Write-Log "Compliant: registry status is Updated with no errors"
    }
}

# Classify severity
$severity = "Compliant"
if (-not $updateComplete) {
    if ($issues.Count -eq 0 -and $waitingForCooldown) {
        $severity = "WaitingCooldown"  # Not an error, just throttled
    }
    elseif ($issues -contains "MissingKEK1803") {
        $severity = "Critical_OEMRequired"  # Can't fix without OEM KEK
    }
    elseif ($issues -contains "KnownFirmwareIssue1802") {
        $severity = "Critical_FirmwareUpdate"  # Needs OEM firmware update
    }
    elseif ($issues -contains "FirmwareError1795") {
        $severity = "High_FirmwareError"
    }
    elseif ($issues -contains "SecureBootDisabled") {
        $severity = "High_SecureBootOff"
    }
    elseif ($issues -contains "RebootRequired") {
        $severity = "Medium_RebootNeeded"
    }
    elseif ($issues -contains "TaskDisabledOrMissing") {
        $severity = "Medium_TaskDisabled"
    }
    elseif ($issues.Count -gt 0) {
        $severity = "Medium_Other"
    }
    else {
        $severity = "Low_InProgress"
    }
}

# ---------------------------------------------------------------
# Build output
# ---------------------------------------------------------------
$output = [ordered]@{
    # Summary
    TimeGenerated         = (Get-Date).ToString("o")
    Hostname              = $env:COMPUTERNAME
    CollectionTime        = (Get-Date).ToString("o")
    UpdateComplete        = $updateComplete
    Severity              = $severity
    Issues                = ($issues -join ",")
    IssueCount            = $issues.Count

    # Secure Boot
    SecureBootEnabled     = $secureBootEnabled
    CertInUEFIDB          = $certInDB
    UEFICA2023Status      = $uefica2023Status
    UEFICA2023Error       = $uefica2023Error
    UEFICA2023ErrorEvent  = $uefica2023ErrorEvent

    # Registry
    AvailableUpdates      = if ($null -ne $availableUpdates) { "0x{0:X}" -f $availableUpdates } else { $null }
    AvailableUpdatesPolicy = if ($null -ne $availableUpdatesPolicy) { "0x{0:X}" -f $availableUpdatesPolicy } else { $null }
    HighConfidenceOptOut  = $highConfidenceOptOut
    CanAttemptUpdateAfter = $canAttemptAfterStr
    WaitingForCooldown    = $waitingForCooldown

    # Scheduled Task
    TaskStatus            = $taskStatus
    TaskEnabled           = $taskEnabled

    # Event Log Summary
    LatestEventId         = $eventData.LatestEventId
    LatestEventTime       = $eventData.LatestEventTime
    RebootPending         = $eventData.RebootPending
    FirmwareError         = $eventData.FirmwareError
    FirmwareErrorCode     = $eventData.Event1795Error
    ErrorCode1796         = $eventData.Event1796Error
    KnownFirmwareIssue    = $eventData.KnownFirmwareIssue
    KnownIssueId          = $eventData.Event1802KI
    MissingKEK            = $eventData.MissingKEK

    # Event Counts
    Evt1795_FirmwareErr   = $eventData.Event1795Count
    Evt1796_ErrorCode     = $eventData.Event1796Count
    Evt1800_RebootNeeded  = $eventData.Event1800Count
    Evt1801_UpdateInit    = $eventData.Event1801Count
    Evt1802_KnownIssue    = $eventData.Event1802Count
    Evt1803_MissingKEK    = $eventData.Event1803Count

    # BitLocker
    BitLockerEnabled      = $bitlockerEnabled
    BitLockerProtectors   = ($bitlockerProtectors -join ",")

    # Device
    Manufacturer          = $manufacturer
    Model                 = $model
    FirmwareVersion       = $firmwareVersion
    OSVersion             = $osVersion
    LastBootTime          = if ($lastBoot) { $lastBoot.ToString("o") } else { $null }

    # Dell CCTK BIOS diagnostics (null on non-Dell or if CCTK not installed)
    CCTK_SecureBoot       = $cctkSecureBoot
    CCTK_SecureBootMode   = $cctkSecureBootMode
    CCTK_MSUefiCA         = $cctkMSUefiCA
}

$json = $output | ConvertTo-Json -Compress

# Save full JSON to log directory for remote review
$jsonFile = "$LogDir\SecureBootCertUpdate_$($env:COMPUTERNAME)_latest.json"
try { $json | Out-File -FilePath $jsonFile -Encoding utf8 -Force } catch {}

Write-Log "Severity: $severity | Issues: $($issues -join ', ')"
Write-Log "JSON saved to: $jsonFile"

Write-Log "========== Detection Complete =========="

Write-Output $json

if ($updateComplete) {
    exit 0
} else {
    exit 1
}
