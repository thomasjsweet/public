# Secure Boot Certificate Update (KB5085046) - Intune Proactive Remediation

Intune Proactive Remediation scripts to detect and fix failures with the **Windows UEFI CA 2023** Secure Boot certificate update (KB5085046).

Microsoft is rolling out a new Secure Boot signing certificate to replace the expiring Windows UEFI CA 2011. This update modifies the UEFI Secure Boot DB and requires multiple reboots, firmware compatibility, and specific BIOS settings. Many devices get stuck due to firmware bugs, missing KEKs, disabled scheduled tasks, paused updates, or BitLocker recovery triggers.

These scripts automate detection and remediation of every documented failure scenario.

## Scripts

### Secure Boot Certificate Update

| Script | Purpose |
|--------|---------|
| `Detect-SecureBootCertUpdate.ps1` | Detection script - checks 12 failure scenarios and outputs JSON diagnostics |
| `Remediate-SecureBootCertUpdate.ps1` | Remediation script - fixes all remediable scenarios automatically |

### Dell BIOS Settings

| Script | Purpose |
|--------|---------|
| `Detect-DellBIOSSettings.ps1` | Detects if MSUefiCA and CapsuleFirmwareUpdate are enabled via Dell CCTK |
| `Remediate-DellBIOSSettings.ps1` | Enables MSUefiCA and CapsuleFirmwareUpdate, with AuditMode workaround for DeployedMode |

## What the detection script checks

1. **Secure Boot not enabled** - cert update cannot apply without Secure Boot
2. **Scheduled task disabled or missing** - `\Microsoft\Windows\PI\Secure-Boot-Update`
3. **AvailableUpdates not progressing** - registry stuck at 0
4. **Firmware errors** (Event 1795) - firmware bug preventing DB writes
5. **Error codes logged** (Event 1796, 1797, 1799) - various CBS/update errors
6. **Reboot pending but not happening** (Event 1800/1801) - update waiting for reboot
7. **Known firmware issue blocking update** (Event 1802) - Microsoft-identified incompatibility
8. **Missing OEM-signed KEK** (Event 1803) - OEM hasn't provided key to Microsoft
9. **UEFI DB overwrite** - firmware defect replacing DB contents
10. **BitLocker recovery risk** - protection status before firmware changes
11. **Certificate not in UEFI DB** - verify actual cert presence after "Updated" status
12. **CanAttemptUpdateAfter cooldown** - throttle/retry timer not yet expired

## What the remediation script fixes

| Scenario | Fix |
|----------|-----|
| Scheduled task disabled/missing | Re-enables the task, triggers WU scan for prerequisites |
| Secure Boot disabled | Logs manufacturer/model (requires manual BIOS entry) |
| AvailableUpdates stuck at 0 | Sets to `0x5944` per Microsoft playbook |
| Reboot required | Suspends BitLocker, disables Fast Startup, schedules two-pass midnight reboot |
| Firmware error (Event 1795) | Clears error state, resets AvailableUpdates, re-triggers task |
| Known firmware issue (Event 1802) | Logs KI number, triggers WU scan for firmware update |
| Missing KEK (Event 1803) | Logs for IT review (cannot fix without OEM action) |
| Registry error state | Clears UEFICA2023Error/ErrorEvent, resets status for retry |
| HighConfidenceOptOut set | Removes opt-out registry value |
| BitLocker recovery risk | Suspends protectors for 2 reboots before firmware changes |
| Fast Startup enabled | Disables HiberbootEnabled so "Shut Down" performs a real reboot |
| Dell MSUefiCA disabled | Enables via CCTK with AuditMode workaround for DeployedMode |
| Dell CapsuleFirmwareUpdate disabled | Enables via CCTK |

## Intune setup

1. Go to **Devices > Remediations** (or **Proactive remediations** in older portal)
2. Create two remediation packages:

**Package 1: Secure Boot Certificate Update**
- Detection script: `Detect-SecureBootCertUpdate.ps1`
- Remediation script: `Remediate-SecureBootCertUpdate.ps1`
- Run as: **System** (64-bit)
- Schedule: Daily

**Package 2: Dell BIOS Settings** (Dell fleet only)
- Detection script: `Detect-DellBIOSSettings.ps1`
- Remediation script: `Remediate-DellBIOSSettings.ps1`
- Run as: **System** (64-bit)
- Schedule: Daily
- Assign to a device group filtered to Dell devices

## Prerequisites

- Windows 10 22H2+ or Windows 11
- KB5085046 or later cumulative update installed
- Dell CCTK (`Dell Command | Endpoint Configure`) for the Dell BIOS scripts
- Intune-managed devices running as SYSTEM context

## Log locations

All scripts log to:
```
%ProgramData%\Microsoft\IntuneManagementExtension\Logs\SecureBootCertUpdate_Detect.log
%ProgramData%\Microsoft\IntuneManagementExtension\Logs\SecureBootCertUpdate_Remediate.log
%ProgramData%\Microsoft\IntuneManagementExtension\Logs\DellBIOSSettings.log
```

The detection script also saves a JSON diagnostic snapshot:
```
%ProgramData%\Microsoft\IntuneManagementExtension\Logs\SecureBootCertUpdate_<HOSTNAME>_latest.json
```

## References

- [KB5085046 - Secure Boot certificate update](https://support.microsoft.com/topic/kb5085046)
- [Troubleshooting guide](https://support.microsoft.com/en-us/topic/troubleshooting-5d1bf6b4-7972-455a-a421-0184f1e1ed7d)
- [Microsoft Secure Boot UEFI CA 2023 announcement](https://techcommunity.microsoft.com/blog/windows-itpro-blog/updating-secure-boot-uefi-ca-for-windows/)

## License

MIT
