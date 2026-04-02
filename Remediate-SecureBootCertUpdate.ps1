<#
.SYNOPSIS
    Intune Proactive Remediation - Remediation Script
    Secure Boot Certificate Update (KB5085046) - Windows UEFI CA 2023

.DESCRIPTION
    Remediates every failure scenario from the Microsoft Secure Boot
    certificate update troubleshooting guide (KB5085046):

    Scenario 1: Scheduled task disabled/missing
      -> Re-enable the \Microsoft\Windows\PI\Secure-Boot-Update task

    Scenario 2: Secure Boot disabled in firmware
      -> Log + flag (cannot enable from OS - needs manual BIOS entry)

    Scenario 3: AvailableUpdates stuck at 0 / not progressing
      -> Set AvailableUpdates registry to 0x5944 to deploy all certs + boot manager

    Scenario 4: Reboot required but hasn't happened (Event 1800/1801)
      -> Suspend BitLocker for 1 reboot, schedule midnight restart

    Scenario 5: Firmware error (Event 1795)
      -> Clear error state, reset AvailableUpdates, re-run scheduled task

    Scenario 6: Known firmware issue blocking update (Event 1802)
      -> Log KI number, check for firmware update via WU

    Scenario 7: Missing OEM KEK (Event 1803)
      -> Log (cannot fix without OEM action), trigger WU scan for firmware

    Scenario 8: Error state in registry (UEFICA2023Error != 0)
      -> Clear error values, reset AvailableUpdates, re-trigger task

    Scenario 9: HighConfidenceOptOut blocking update
      -> Remove opt-out registry value

    Scenario 10: BitLocker recovery prevention
      -> Suspend BitLocker protectors for 1 reboot cycle before any
         firmware-touching operation

    This script is safe to run repeatedly. It detects current state and
    only applies fixes relevant to the device's specific failure mode.

.NOTES
    Author:   IR Pros IT Team
    Date:     2026-03-21
    Version:  3.0-public
    Ref:      https://support.microsoft.com/en-us/topic/troubleshooting-5d1bf6b4-7972-455a-a421-0184f1e1ed7d
    KB:       KB5085046
    Context:  SYSTEM (Intune default)
    Requires: Admin / SYSTEM context
#>

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------
# Config
# ---------------------------------------------------------------
$LogDir       = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
$LogPath      = "$LogDir\SecureBootCertUpdate_Remediate.log"
$sbRoot       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
$sbServicing  = "$sbRoot\Servicing"
$taskPath     = "\Microsoft\Windows\PI\Secure-Boot-Update"

# ---------------------------------------------------------------
# Logging
# ---------------------------------------------------------------
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "$ts [$Level] $Message"
    try { $line | Out-File -FilePath $LogPath -Append -Encoding utf8 } catch {}
    Write-Output $line
}

# Rotate log if over 1 MB
if (Test-Path $LogPath) {
    if ((Get-Item $LogPath).Length -gt 1MB) {
        $dateSuffix = Get-Date -Format 'yyyyMMdd_HHmmss'
        $archive = $LogPath.Replace('.log', "_$dateSuffix.log")
        Rename-Item -Path $LogPath -NewName $archive -ErrorAction SilentlyContinue
    }
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
    } catch { return $null }
}

Write-Log "========== SecureBoot Cert Update Remediation Start =========="
Write-Log "Device: $env:COMPUTERNAME"

# ---------------------------------------------------------------
# STEP 0: Quick exit if already updated
# ---------------------------------------------------------------
$uefica2023Status = Get-RegValue $sbServicing "UEFICA2023Status"
$uefica2023Error  = Get-RegValue $sbServicing "UEFICA2023Error"
$certInDB = $false
try {
    $db = Get-SecureBootUEFI -Name db -ErrorAction Stop
    if ($db -and $db.Bytes) {
        $dbString = [System.Text.Encoding]::ASCII.GetString($db.Bytes)
        $certInDB = $dbString -match 'Windows UEFI CA 2023'
    }
} catch {}

if ($certInDB) {
    Write-Log "Windows UEFI CA 2023 already present in Secure Boot DB. No remediation needed."
    exit 0
}

if ($uefica2023Status -eq "Updated" -and ($null -eq $uefica2023Error -or $uefica2023Error -eq 0)) {
    Write-Log "Registry shows Updated with no errors. Certificate may be pending reboot to appear in DB."
    # Don't exit - continue to check if reboot is needed
}

# ---------------------------------------------------------------
# STEP 1: Check Secure Boot status
# ---------------------------------------------------------------
Write-Log "--- Phase 1: Secure Boot status ---"
$secureBootEnabled = $false
try {
    $secureBootEnabled = Confirm-SecureBootUEFI -ErrorAction Stop
} catch {
    $regSB = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" "UEFISecureBootEnabled"
    if ($null -ne $regSB) { $secureBootEnabled = [bool]$regSB }
}

if (-not $secureBootEnabled) {
    Write-Log "CRITICAL: Secure Boot is DISABLED. Cannot apply certificate update." "ERROR"
    Write-Log "Manual action required: Enter BIOS/UEFI setup and enable Secure Boot." "ERROR"
    $mfr = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).Manufacturer
    $mdl = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).Model
    Write-Log "Manufacturer: $mfr"
    Write-Log "Model: $mdl"
    # Cannot proceed without Secure Boot - exit with error
    exit 1
}

Write-Log "Secure Boot: Enabled"

# ---------------------------------------------------------------
# STEP 2: Suspend BitLocker (prevent recovery on firmware change)
# ---------------------------------------------------------------
Write-Log "--- Phase 2: BitLocker protection ---"
$bitlockerSuspended = $false
try {
    $blv = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
    if ($blv.ProtectionStatus -eq "On") {
        Write-Log "BitLocker is ON. Suspending for 1 reboot cycle to prevent recovery prompt."
        Suspend-BitLocker -MountPoint "C:" -RebootCount 2 -ErrorAction Stop
        $bitlockerSuspended = $true
        Write-Log "BitLocker suspended for 2 reboots (firmware update + cert update)"
    } else {
        Write-Log "BitLocker protection is Off or not configured"
    }
} catch {
    Write-Log "BitLocker check failed (may not be available): $_" "WARN"
}

# ---------------------------------------------------------------
# STEP 2b: Disable Fast Startup (Hybrid Shutdown)
# ---------------------------------------------------------------
# Fast Startup causes "Shut Down" to hibernate the kernel instead of
# performing a full reboot. The Secure Boot cert update requires a real
# reboot to apply. Users who "shut down daily" never actually reboot.
$hiberbootPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
$hiberboot = Get-RegValue $hiberbootPath "HiberbootEnabled"
if ($null -ne $hiberboot -and $hiberboot -ne 0) {
    Write-Log "Fast Startup (HiberbootEnabled) is ON. Disabling so Shut Down performs a full reboot." "WARN"
    try {
        Set-ItemProperty -Path $hiberbootPath -Name "HiberbootEnabled" -Value 0 -Type DWord -ErrorAction Stop
        Write-Log "Fast Startup disabled"
    } catch {
        Write-Log "Failed to disable Fast Startup: $_" "WARN"
    }
} else {
    Write-Log "Fast Startup: Already disabled (OK)"
}

# ---------------------------------------------------------------
# STEP 3: Remove HighConfidenceOptOut if set
# ---------------------------------------------------------------
Write-Log "--- Phase 3: Opt-out check ---"
$optOut = Get-RegValue $sbRoot "HighConfidenceOptOut"
if ($null -ne $optOut -and $optOut -ne 0) {
    Write-Log "HighConfidenceOptOut is set ($optOut). Removing to allow update." "WARN"
    try {
        Remove-ItemProperty -Path $sbRoot -Name "HighConfidenceOptOut" -ErrorAction Stop
        Write-Log "HighConfidenceOptOut removed"
    } catch {
        Write-Log "Failed to remove HighConfidenceOptOut: $_" "ERROR"
    }
} else {
    Write-Log "HighConfidenceOptOut: Not set (OK)"
}

# ---------------------------------------------------------------
# STEP 4: Clear error state in registry
# ---------------------------------------------------------------
Write-Log "--- Phase 4: Registry error state ---"
$errorCleared = $false

$currentError = Get-RegValue $sbServicing "UEFICA2023Error"
$currentErrorEvent = Get-RegValue $sbServicing "UEFICA2023ErrorEvent"

if ($null -ne $currentError -and $currentError -ne 0) {
    Write-Log "UEFICA2023Error = $currentError (clearing to allow retry)" "WARN"
    try {
        Set-ItemProperty -Path $sbServicing -Name "UEFICA2023Error" -Value 0 -ErrorAction Stop
        $errorCleared = $true
        Write-Log "UEFICA2023Error cleared to 0"
    } catch {
        Write-Log "Failed to clear UEFICA2023Error: $_" "ERROR"
    }
}

if ($null -ne $currentErrorEvent -and $currentErrorEvent -ne 0) {
    Write-Log "UEFICA2023ErrorEvent = $currentErrorEvent (clearing)" "WARN"
    try {
        Set-ItemProperty -Path $sbServicing -Name "UEFICA2023ErrorEvent" -Value 0 -ErrorAction Stop
        Write-Log "UEFICA2023ErrorEvent cleared to 0"
    } catch {
        Write-Log "Failed to clear UEFICA2023ErrorEvent: $_" "ERROR"
    }
}

# Clear the status if it's in a failed state to allow re-attempt
$currentStatus = Get-RegValue $sbServicing "UEFICA2023Status"
if ($null -ne $currentStatus -and $currentStatus -notin @("Updated", $null, "")) {
    if ($errorCleared) {
        Write-Log "UEFICA2023Status = $currentStatus. Error was cleared, resetting status to allow re-attempt." "WARN"
        try {
            Remove-ItemProperty -Path $sbServicing -Name "UEFICA2023Status" -ErrorAction Stop
            Write-Log "UEFICA2023Status removed to allow fresh attempt"
        } catch {
            Write-Log "Could not remove UEFICA2023Status: $_" "WARN"
        }
    }
}

if (-not $errorCleared) {
    Write-Log "No registry errors found (OK)"
}

# ---------------------------------------------------------------
# STEP 5: Event log analysis - identify specific failure mode
# ---------------------------------------------------------------
Write-Log "--- Phase 5: Event log failure analysis ---"

$firmwareError = $false
$knownFirmwareIssue = $false
$knownIssueId = $null
$missingKEK = $false
$rebootNeeded = $false

try {
    $allEventIds = @(1795, 1796, 1797, 1799, 1800, 1801, 1802, 1803)
    $events = @(Get-WinEvent -FilterHashtable @{LogName='System'; ID=$allEventIds} -MaxEvents 50 -ErrorAction Stop)

    if ($events.Count -gt 0) {
        # Check for firmware error (Event 1795)
        $ev1795 = @($events | Where-Object { $_.Id -eq 1795 })
        if ($ev1795.Count -gt 0) {
            $firmwareError = $true
            $errCode = $null
            if ($ev1795[0].Message -match '(?:error|code|status|result)[:\s]*(?:0x)?([0-9A-Fa-f]{4,8})') {
                $errCode = "0x$($matches[1])"
            }
            Write-Log "Event 1795: Firmware returned error during variable update. Code: $errCode" "WARN"
            Write-Log "  This usually means the device firmware has a bug preventing Secure Boot DB updates." "WARN"
            Write-Log "  Check for BIOS/UEFI firmware updates from the device manufacturer." "WARN"
        }

        # Check for known firmware issue (Event 1802)
        $ev1802 = @($events | Where-Object { $_.Id -eq 1802 })
        if ($ev1802.Count -gt 0) {
            $knownFirmwareIssue = $true
            $latest1802 = $ev1802 | Sort-Object TimeCreated -Descending | Select-Object -First 1
            if ($latest1802.Message -match 'SkipReason:\s*(KI_\d+)') {
                $knownIssueId = $matches[1]
            }
            Write-Log "Event 1802: Known firmware issue detected. KI: $knownIssueId" "WARN"
            Write-Log "  Microsoft has identified a compatibility issue with this device's firmware." "WARN"
            Write-Log "  The update is intentionally blocked until a firmware fix is available." "WARN"
        }

        # Check for missing KEK (Event 1803)
        $ev1803 = @($events | Where-Object { $_.Id -eq 1803 })
        if ($ev1803.Count -gt 0) {
            $missingKEK = $true
            Write-Log "Event 1803: No matching KEK update found for this device." "ERROR"
            Write-Log "  The OEM needs to provide a PK-signed KEK to Microsoft." "ERROR"
            Write-Log "  This cannot be resolved by the end user or IT admin." "ERROR"
            Write-Log "  Manufacturer: $((Get-CimInstance Win32_ComputerSystem).Manufacturer)"
            Write-Log "  Model: $((Get-CimInstance Win32_ComputerSystem).Model)"
        }

        # Check for reboot needed (Event 1800/1801)
        $evReboot = @($events | Where-Object { $_.Id -in @(1800, 1801) })
        if ($evReboot.Count -gt 0) {
            $lastBoot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
            $latestRebootEvent = $evReboot | Sort-Object TimeCreated -Descending | Select-Object -First 1
            if ($lastBoot -lt $latestRebootEvent.TimeCreated) {
                $rebootNeeded = $true
                Write-Log "Event $($latestRebootEvent.Id): Update requires reboot. Device has NOT rebooted since event." "WARN"
            } else {
                Write-Log "Event $($latestRebootEvent.Id): Reboot event found, but device has rebooted since. Update may have progressed."
            }
        }
    } else {
        Write-Log "No Secure Boot update events found in System log"
    }
} catch {
    Write-Log "Could not query event logs: $_" "WARN"
}

# ---------------------------------------------------------------
# STEP 6: Enable/run the Secure-Boot-Update scheduled task
# ---------------------------------------------------------------
Write-Log "--- Phase 6: Scheduled task ---"

$taskFixed = $false
try {
    $taskQuery = schtasks.exe /Query /TN $taskPath /FO CSV 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log "Scheduled task not found: $taskPath" "WARN"
        Write-Log "This may indicate the device needs the latest Windows security update installed." "WARN"

        # Try to trigger via Windows Update to get the task created
        Write-Log "Triggering Windows Update scan to install prerequisites..."
        Start-Process "USOClient.exe" -ArgumentList "StartInteractiveScan" -Wait -NoNewWindow -ErrorAction SilentlyContinue
    } else {
        $taskData = $taskQuery | ConvertFrom-Csv
        if ($taskData.Status -eq 'Disabled') {
            Write-Log "Task is Disabled. Enabling..." "WARN"
            schtasks.exe /Change /TN $taskPath /ENABLE 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Scheduled task enabled successfully"
                $taskFixed = $true
            } else {
                Write-Log "Failed to enable task via schtasks. Trying PowerShell..." "WARN"
                try {
                    $task = Get-ScheduledTask -TaskPath "\Microsoft\Windows\PI\" -TaskName "Secure-Boot-Update" -ErrorAction Stop
                    $task | Enable-ScheduledTask -ErrorAction Stop
                    Write-Log "Scheduled task enabled via PowerShell"
                    $taskFixed = $true
                } catch {
                    Write-Log "Failed to enable task: $_" "ERROR"
                }
            }
        } elseif ($taskData.Status -eq 'Ready' -or $taskData.Status -eq 'Running') {
            Write-Log "Task status: $($taskData.Status) (OK)"
        } else {
            Write-Log "Task status: $($taskData.Status)" "WARN"
        }

        # Run the task now if we cleared errors or the task was just enabled
        if ($errorCleared -or $taskFixed -or (-not $knownFirmwareIssue -and -not $missingKEK)) {
            Write-Log "Running Secure-Boot-Update task now..."
            try {
                schtasks.exe /Run /TN $taskPath 2>&1 | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    Write-Log "Task triggered successfully"
                } else {
                    # Fallback to PowerShell
                    Start-ScheduledTask -TaskPath "\Microsoft\Windows\PI\" -TaskName "Secure-Boot-Update" -ErrorAction Stop
                    Write-Log "Task triggered via PowerShell"
                }
            } catch {
                Write-Log "Could not trigger task: $_" "WARN"
            }
        }
    }
} catch {
    Write-Log "Error managing scheduled task: $_" "ERROR"
}

# ---------------------------------------------------------------
# STEP 7: Set AvailableUpdates if not progressing
# ---------------------------------------------------------------
Write-Log "--- Phase 7: AvailableUpdates check ---"
$availableUpdates = Get-RegValue $sbRoot "AvailableUpdates"
$availableUpdatesHex = if ($null -ne $availableUpdates) { "0x{0:X}" -f $availableUpdates } else { "null" }
Write-Log "Current AvailableUpdates: $availableUpdatesHex"

if ($null -eq $availableUpdates -or $availableUpdates -eq 0) {
    if (-not $knownFirmwareIssue -and -not $missingKEK) {
        Write-Log "AvailableUpdates is 0 or null. Setting to 0x5944 to deploy all certs + boot manager (per MS playbook)." "WARN"
        try {
            if (!(Test-Path $sbRoot)) {
                New-Item -Path $sbRoot -Force | Out-Null
            }
            Set-ItemProperty -Path $sbRoot -Name "AvailableUpdates" -Value 0x5944 -Type DWord -ErrorAction Stop
            Write-Log "AvailableUpdates set to 0x5944"
        } catch {
            Write-Log "Failed to set AvailableUpdates: $_" "ERROR"
        }
    } else {
        Write-Log "Skipping AvailableUpdates reset due to known firmware/KEK issue"
    }
} elseif ($availableUpdates -eq 0x80) {
    # Old remediation set 0x80 which is the wrong bit. Upgrade to 0x5944.
    if (-not $knownFirmwareIssue -and -not $missingKEK) {
        Write-Log "AvailableUpdates is 0x80 (old value). Upgrading to 0x5944 (per MS playbook)." "WARN"
        try {
            Set-ItemProperty -Path $sbRoot -Name "AvailableUpdates" -Value 0x5944 -Type DWord -ErrorAction Stop
            Write-Log "AvailableUpdates upgraded from 0x80 to 0x5944"
        } catch {
            Write-Log "Failed to upgrade AvailableUpdates: $_" "ERROR"
        }
    }
} else {
    Write-Log "AvailableUpdates already set ($availableUpdatesHex) - update process has started"
}

# ---------------------------------------------------------------
# STEP 7b: Dell CCTK - enable MSUefiCA and CapsuleFirmwareUpdate
# ---------------------------------------------------------------
$cctkPath = "C:\Program Files\Dell\EndpointConfigure\x86_64\cctk.exe"
$mfr = $null
try { $mfr = (Get-CimInstance Win32_ComputerSystem).Manufacturer } catch {}
if ($mfr -match 'Dell' -and (Test-Path $cctkPath)) {
    Write-Log "--- Phase 7b: Dell CCTK BIOS settings ---"

    # Query current SecureBootMode
    $currentSBMode = $null
    try {
        $currentSBMode = (& $cctkPath --SecureBootMode 2>&1 | Out-String).Trim()
        Write-Log "SecureBootMode: $currentSBMode"
    } catch {}

    try {
        $msUefiCA = & $cctkPath --MSUefiCA 2>&1 | Out-String
        if ($msUefiCA -match 'Disabled') {
            Write-Log "MSUefiCA is Disabled - enabling via CCTK..." "WARN"
            $result = & $cctkPath --MSUefiCA=Enabled 2>&1 | Out-String
            $cctkExit = $LASTEXITCODE

            if ($cctkExit -ne 0 -and ($cctkExit -eq 43 -or $result -match 'error setting') -and $currentSBMode -match 'DeployedMode') {
                # DeployedMode locks Secure Boot DB changes. Try AuditMode workaround.
                Write-Log "MSUefiCA blocked by DeployedMode (exit $cctkExit). Trying AuditMode workaround..." "WARN"

                $switchResult = & $cctkPath --SecureBootMode=AuditMode 2>&1 | Out-String
                Write-Log "Switch to AuditMode: $($switchResult.Trim())"

                if ($LASTEXITCODE -eq 0) {
                    $retryResult = & $cctkPath --MSUefiCA=Enabled 2>&1 | Out-String
                    Write-Log "MSUefiCA=Enabled in AuditMode: $($retryResult.Trim())"

                    # Restore DeployedMode regardless of MSUefiCA result
                    $restoreResult = & $cctkPath --SecureBootMode=DeployedMode 2>&1 | Out-String
                    Write-Log "Restore DeployedMode: $($restoreResult.Trim())"
                } else {
                    Write-Log "Cannot switch to AuditMode (exit $LASTEXITCODE). Manual BIOS change required for MSUefiCA." "ERROR"
                }
            } elseif ($cctkExit -eq 0) {
                Write-Log "CCTK --MSUefiCA=Enabled: $($result.Trim())"
            } else {
                Write-Log "CCTK --MSUefiCA=Enabled failed (exit $cctkExit): $($result.Trim())" "WARN"
            }
        } elseif ($msUefiCA -match 'Enabled') {
            Write-Log "MSUefiCA: already Enabled (OK)"
        } else {
            Write-Log "MSUefiCA: $($msUefiCA.Trim()) (option not available on this model)"
        }
    } catch {
        Write-Log "CCTK MSUefiCA check failed: $_" "WARN"
    }
    try {
        $capsule = & $cctkPath --CapsuleFirmwareUpdate 2>&1 | Out-String
        if ($capsule -match 'Disabled') {
            Write-Log "CapsuleFirmwareUpdate is Disabled - enabling via CCTK..." "WARN"
            $result = & $cctkPath --CapsuleFirmwareUpdate=Enabled 2>&1 | Out-String
            Write-Log "CCTK --CapsuleFirmwareUpdate=Enabled: $($result.Trim())"
        } elseif ($capsule -match 'Enabled') {
            Write-Log "CapsuleFirmwareUpdate: already Enabled (OK)"
        } else {
            Write-Log "CapsuleFirmwareUpdate: $($capsule.Trim())"
        }
    } catch {
        Write-Log "CCTK CapsuleFirmwareUpdate check failed: $_" "WARN"
    }
} elseif ($mfr -match 'Dell') {
    Write-Log "Dell device but CCTK not installed - skipping BIOS settings"
}

# ---------------------------------------------------------------
# STEP 8: Trigger firmware update check via Windows Update
# ---------------------------------------------------------------
# Always trigger WU scan - firmware updates are a prerequisite for the cert
# update on many Dell models. Event 1796 errors often clear after a BIOS update.
Write-Log "--- Phase 8: Firmware update check ---"
Write-Log "Triggering Windows Update scan for firmware/driver updates..."
try {
    Start-Process "USOClient.exe" -ArgumentList "StartInteractiveScan" -Wait -NoNewWindow -ErrorAction SilentlyContinue
    Write-Log "WU scan triggered. Firmware updates will install on next reboot."
} catch {
    Write-Log "Could not trigger WU scan: $_" "WARN"
}

# ---------------------------------------------------------------
# STEP 9: Schedule reboot if needed
# ---------------------------------------------------------------
if ($rebootNeeded) {
    Write-Log "--- Phase 9: Reboot scheduling ---"

    # Ensure BitLocker is suspended (may have already been done in Step 2)
    if (-not $bitlockerSuspended) {
        try {
            $blv = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
            if ($blv -and $blv.ProtectionStatus -eq "On") {
                Suspend-BitLocker -MountPoint "C:" -RebootCount 2 -ErrorAction Stop
                Write-Log "BitLocker suspended for 2 reboots"
            }
        } catch {
            Write-Log "Could not suspend BitLocker for reboot: $_" "WARN"
        }
    }

    # Schedule two reboots:
    #   Reboot 1 (23:59) - installs pending firmware/BIOS updates
    #   Reboot 2 (00:30) - applies the Secure Boot cert update after firmware is current
    # This two-pass approach is needed because firmware updates install on reboot,
    # and the cert update can only succeed once the firmware is updated.

    $rebootScript1 = @'
$lastBoot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$uptimeHours = ((Get-Date) - $lastBoot).TotalHours
if ($uptimeHours -lt 1) {
    Unregister-ScheduledTask -TaskName "SecureBootCert_Reboot1" -Confirm:$false -ErrorAction SilentlyContinue
} else {
    shutdown.exe /r /f /t 300 /c "Your computer will restart in 5 minutes to install firmware updates for a Secure Boot security update. Please save your work."
    Unregister-ScheduledTask -TaskName "SecureBootCert_Reboot1" -Confirm:$false -ErrorAction SilentlyContinue
}
'@

    $rebootScript2 = @'
$lastBoot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$uptimeMinutes = ((Get-Date) - $lastBoot).TotalMinutes
if ($uptimeMinutes -lt 20) {
    # Just rebooted from Reboot 1 - trigger the Secure Boot update task, then reboot again
    schtasks.exe /Run /TN "\Microsoft\Windows\PI\Secure-Boot-Update" 2>$null
    Start-Sleep -Seconds 30
    shutdown.exe /r /f /t 60 /c "Completing Secure Boot certificate update. Restarting in 1 minute."
} else {
    # Device was already up for a while - still reboot to apply cert
    shutdown.exe /r /f /t 300 /c "Your computer will restart in 5 minutes to complete a Secure Boot security update. Please save your work."
}
Unregister-ScheduledTask -TaskName "SecureBootCert_Reboot2" -Confirm:$false -ErrorAction SilentlyContinue
'@

    $encoded1 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($rebootScript1))
    $encoded2 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($rebootScript2))

    try {
        # Clean up any existing tasks
        Unregister-ScheduledTask -TaskName "SecureBootCert_MidnightRestart" -Confirm:$false -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName "SecureBootCert_Reboot1" -Confirm:$false -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName "SecureBootCert_Reboot2" -Confirm:$false -ErrorAction SilentlyContinue

        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

        # Reboot 1: 23:59 - firmware update reboot
        $action1  = New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand $encoded1"
        $trigger1 = New-ScheduledTaskTrigger -Once -At "23:59"
        Register-ScheduledTask -Action $action1 -Trigger $trigger1 -Settings $settings -Principal $principal `
            -TaskName "SecureBootCert_Reboot1" `
            -Description "Reboot 1/2: Install firmware updates for Secure Boot cert update" -Force | Out-Null

        # Reboot 2: 00:30 - cert update reboot
        $action2  = New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand $encoded2"
        $trigger2 = New-ScheduledTaskTrigger -Once -At "00:30"
        Register-ScheduledTask -Action $action2 -Trigger $trigger2 -Settings $settings -Principal $principal `
            -TaskName "SecureBootCert_Reboot2" `
            -Description "Reboot 2/2: Apply Secure Boot certificate after firmware update" -Force | Out-Null

        Write-Log "Scheduled two-pass reboot: 23:59 (firmware) + 00:30 (cert update)"
    } catch {
        Write-Log "Failed to schedule reboots: $_" "ERROR"
    }
}

# ---------------------------------------------------------------
# Summary
# ---------------------------------------------------------------
Write-Log "--- Remediation Summary ---"
Write-Log "Secure Boot: Enabled"
Write-Log "BitLocker suspended: $bitlockerSuspended"
Write-Log "HighConfidenceOptOut removed: $($optOut -ne $null -and $optOut -ne 0)"
Write-Log "Error state cleared: $errorCleared"
Write-Log "Task fixed: $taskFixed"
Write-Log "Reboot scheduled: $rebootNeeded"
Write-Log "Firmware error present: $firmwareError"
Write-Log "Known firmware issue: $knownFirmwareIssue $(if ($knownIssueId) { "($knownIssueId)" })"
Write-Log "Missing KEK (OEM required): $missingKEK"

if ($missingKEK) {
    Write-Log "ACTION REQUIRED: Contact device manufacturer regarding missing KEK for Secure Boot CA 2023 update." "ERROR"
    Write-Log "========== Remediation Complete (partial - OEM action needed) =========="
    exit 1
}
elseif ($knownFirmwareIssue) {
    Write-Log "ACTION REQUIRED: Check for firmware update from device manufacturer. KI: $knownIssueId" "WARN"
    Write-Log "========== Remediation Complete (partial - firmware update needed) =========="
    exit 1
}
elseif ($firmwareError) {
    Write-Log "Firmware error detected. Error state cleared and update re-triggered." "WARN"
    Write-Log "If this persists, a firmware update from the manufacturer is needed." "WARN"
    Write-Log "========== Remediation Complete (retry initiated) =========="
    exit 0
}
else {
    Write-Log "========== Remediation Complete =========="
    exit 0
}
