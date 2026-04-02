<#
.SYNOPSIS
    Intune Proactive Remediation - Remediate Dell BIOS Settings (MSUefiCA, CapsuleFirmwareUpdate)
.DESCRIPTION
    Enables MSUefiCA and CapsuleFirmwareUpdate via Dell CCTK if currently Disabled.
    No BIOS password is used.
    Exit 0 = success, Exit 1 = failure
.NOTES
    Run context: SYSTEM
#>

$LogPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\DellBIOSSettings.log"
$CCTKPath = "C:\Program Files\Dell\EndpointConfigure\x86_64\cctk.exe"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "$timestamp [REMEDIATE] $Message"
    try {
        $logDir = Split-Path -Path $LogPath -Parent
        if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
        Add-Content -Path $LogPath -Value $entry -ErrorAction Stop
    } catch {
        # Logging failure should not break remediation
    }
}

# Check if Dell device
$manufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer
if ($manufacturer -notmatch "Dell") {
    Write-Output "Not a Dell device ($manufacturer). No action needed."
    Write-Log "Not a Dell device ($manufacturer). Skipping."
    exit 0
}

Write-Log "Dell device detected: $manufacturer"

# Check if CCTK is installed
if (-not (Test-Path $CCTKPath)) {
    Write-Output "Dell CCTK not installed. Cannot remediate."
    Write-Log "CCTK not found at $CCTKPath. Cannot remediate."
    exit 1
}

Write-Log "CCTK found at $CCTKPath"

$failed = $false

# Query current SecureBootMode (needed for MSUefiCA workaround)
$currentSBMode = $null
try {
    $sbModeResult = & $CCTKPath --SecureBootMode 2>&1
    $currentSBMode = ($sbModeResult | Out-String).Trim()
    Write-Log "Current SecureBootMode: $currentSBMode"
} catch {
    Write-Log "Could not query SecureBootMode: $_"
}

# Query and remediate MSUefiCA
try {
    $msUefiResult = & $CCTKPath --MSUefiCA 2>&1
    $msUefiValue = ($msUefiResult | Out-String).Trim()
    Write-Log "Current MSUefiCA: $msUefiValue"

    if ($msUefiValue -match "not available") {
        Write-Log "MSUefiCA not available on this model. Skipping."
        Write-Output "MSUefiCA not available on this model."
    } elseif ($msUefiValue -notmatch "Enabled") {
        Write-Log "Setting MSUefiCA=Enabled"
        $setResult = & $CCTKPath --MSUefiCA=Enabled 2>&1
        $setOutput = ($setResult | Out-String).Trim()
        Write-Log "MSUefiCA set result: $setOutput"

        if ($LASTEXITCODE -ne 0 -and ($LASTEXITCODE -eq 43 -or $setOutput -match "error setting") -and $currentSBMode -match "DeployedMode") {
            # DeployedMode locks Secure Boot DB changes. Switch to AuditMode, enable, switch back.
            Write-Log "MSUefiCA blocked by DeployedMode (exit code $LASTEXITCODE). Trying AuditMode workaround..."

            $switchResult = & $CCTKPath --SecureBootMode=AuditMode 2>&1 | Out-String
            Write-Log "Switch to AuditMode: $($switchResult.Trim())"

            if ($LASTEXITCODE -eq 0) {
                $retryResult = & $CCTKPath --MSUefiCA=Enabled 2>&1 | Out-String
                Write-Log "MSUefiCA=Enabled in AuditMode: $($retryResult.Trim())"

                if ($LASTEXITCODE -eq 0) {
                    # Switch back to DeployedMode
                    $restoreResult = & $CCTKPath --SecureBootMode=DeployedMode 2>&1 | Out-String
                    Write-Log "Restore DeployedMode: $($restoreResult.Trim())"
                    Write-Output "MSUefiCA enabled via AuditMode workaround."
                } else {
                    # Restore DeployedMode even on failure
                    & $CCTKPath --SecureBootMode=DeployedMode 2>&1 | Out-Null
                    Write-Log "MSUefiCA still failed in AuditMode (exit code $LASTEXITCODE)"
                    Write-Output "MSUefiCA cannot be changed even in AuditMode (exit code $LASTEXITCODE)."
                }
            } else {
                Write-Log "Cannot switch to AuditMode (exit code $LASTEXITCODE). Manual BIOS change required."
                Write-Output "Cannot switch SecureBootMode. Manual BIOS change required for MSUefiCA."
            }
        } elseif ($LASTEXITCODE -ne 0) {
            Write-Log "MSUefiCA remediation failed (exit code $LASTEXITCODE)"
            Write-Output "MSUefiCA remediation failed (exit code $LASTEXITCODE)"
            $failed = $true
        } else {
            Write-Output "MSUefiCA set result: $setOutput"
        }
    } else {
        Write-Log "MSUefiCA already Enabled. No action needed."
        Write-Output "MSUefiCA already Enabled."
    }
} catch {
    Write-Log "MSUefiCA remediation error: $_"
    Write-Output "MSUefiCA remediation error: $_"
    $failed = $true
}

# Query and remediate CapsuleFirmwareUpdate
try {
    $capsuleResult = & $CCTKPath --CapsuleFirmwareUpdate 2>&1
    $capsuleValue = ($capsuleResult | Out-String).Trim()
    Write-Log "Current CapsuleFirmwareUpdate: $capsuleValue"

    if ($capsuleValue -match "not available") {
        Write-Log "CapsuleFirmwareUpdate not available on this model. Skipping."
        Write-Output "CapsuleFirmwareUpdate not available on this model."
    } elseif ($capsuleValue -notmatch "Enabled") {
        Write-Log "Setting CapsuleFirmwareUpdate=Enabled"
        $setResult = & $CCTKPath --CapsuleFirmwareUpdate=Enabled 2>&1
        $setOutput = ($setResult | Out-String).Trim()
        Write-Log "CapsuleFirmwareUpdate set result: $setOutput"
        Write-Output "CapsuleFirmwareUpdate set result: $setOutput"

        if ($LASTEXITCODE -ne 0) {
            if ($LASTEXITCODE -eq 43 -or $setOutput -match "error setting") {
                Write-Log "CapsuleFirmwareUpdate cannot be changed on this device (exit code $LASTEXITCODE)"
                Write-Output "CapsuleFirmwareUpdate cannot be changed (exit code $LASTEXITCODE). Skipping."
            } else {
                Write-Log "CapsuleFirmwareUpdate remediation failed (exit code $LASTEXITCODE)"
                Write-Output "CapsuleFirmwareUpdate remediation failed (exit code $LASTEXITCODE)"
                $failed = $true
            }
        }
    } else {
        Write-Log "CapsuleFirmwareUpdate already Enabled. No action needed."
        Write-Output "CapsuleFirmwareUpdate already Enabled."
    }
} catch {
    Write-Log "CapsuleFirmwareUpdate remediation error: $_"
    Write-Output "CapsuleFirmwareUpdate remediation error: $_"
    $failed = $true
}

# Final result
if ($failed) {
    Write-Output "Remediation completed with errors."
    Write-Log "Remediation completed with errors."
    exit 1
} else {
    Write-Output "Remediation completed successfully."
    Write-Log "Remediation completed successfully."
    exit 0
}
