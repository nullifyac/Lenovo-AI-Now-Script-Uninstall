Lenovo AI Now Removal Script
============================

PowerShell scripts to detect and remove **Lenovo AI Now** — an OEM-installed application bundled on recent Lenovo devices that many organisations treat as bloatware. Designed for **Microsoft Intune Proactive Remediation**, though the scripts can be adapted to other SYSTEM-context deployment tools.

> **Note**: This is a substantially rewritten fork of the upstream
> [`nullifyac/Lenovo-AI-Now-Script-Uninstall`](https://github.com/nullifyac/Lenovo-AI-Now-Script-Uninstall).
> See "What this fork changes" below for the reasoning.

Why removal is non-trivial
--------------------------

Lenovo AI Now installs two shell-extension DLLs (`AINppShell.dll` and `OverlayIcon.dll`) that are loaded by virtually every shell-using GUI process on the machine — File Explorer, Office apps, browsers, anything that opens a common file dialog. The DLLs cannot be deleted in-session because the OS marks them as in-use across many processes. Killing Explorer doesn't help: Windows auto-restarts it within ~1 second (`AutoRestartShell`), and the DLLs are still held by all the non-Explorer consumers. The reliable cleanup path is to schedule the locked files via `PendingFileRenameOperations` and let SMSS delete them at the next boot, before any shell process starts.

The scripts also handle the **MSIX/AppX** side (`AINowContextWIN11`, the Win11 context-menu extension), the **full COM registration surface** (3 CLSIDs + AppID + TypeLib + 2 ProgIDs + 10 shellex handler subkeys + `ShellIconOverlayIdentifiers` entry + `Shell Extensions\Approved` value), the **per-user repository stubs** that Microsoft's `Remove-AppxPackage` leaves behind, and **multi-user machines** (enumerates HKEY_USERS by SID).

Two-phase model
---------------

| Phase | When it runs | What it does | Exit code |
|---|---|---|---|
| **Phase A** | First Intune Proactive Remediation cycle | Cleans services, processes, AppX package, AppX repository stubs, shell extension surface, user data, shortcuts, scheduled tasks. Removes the install directory if possible; queues locked files via PFRO if not. Writes a sentinel so detect doesn't loop. | **3010** (Intune reports 0 / success) |
| **Phase B** | After the user's organic reboot, next detect cycle | Verifies install directory is gone, removes any AppX repository stubs that resurfaced, confirms clean state. | **0** |

Between Phase A and the user's reboot, `detect.ps1` reads the sentinel and short-circuits to **exit 0**, so Intune won't keep firing remediate (which would bloat `PendingFileRenameOperations`).

Exit code semantics
-------------------

`remediate.ps1` distinguishes its internal result from the Intune-reported code:

| Internal | Intune | Meaning |
|---|---|---|
| 0 | 0 | Clean removal, no reboot needed |
| 3010 | 0 | Phase A complete, reboot pending. Reported as success so Intune doesn't re-trigger before the user reboots |
| 1603 | 1 | Partial failure — residuals remain and PFRO queue failed |
| 1 | 1 | Unhandled exception |

Requirements
------------

- **Run script in 64-bit PowerShell** must be **Yes** in the Intune PR settings.
  - Reason: Intune defaults Proactive Remediation scripts to 32-bit PowerShell, which silently redirects `HKLM:\SOFTWARE\Classes\CLSID` reads to the `Wow6432Node` hive. All of Lenovo AI Now's CLSIDs and uninstall registry entry live in the **64-bit** hive, so a 32-bit script reads an empty view and cleans nothing.
  - Both scripts include a self-relaunch guard that re-invokes them under `C:\Windows\SysNative\WindowsPowerShell\v1.0\powershell.exe` if Intune started them 32-bit. The toggle is still recommended (saves one process spawn per cycle).
- **Targeting**: assign the PR script to Lenovo devices only. A device filter on `Manufacturer -eq "LENOVO"` is reasonable.
- **Schedule**: daily detection is fine; the default 8-hour cadence is fine too. The sentinel prevents detection-loop bloat between Phase A and reboot.

Deployment
----------

1. In the Intune admin centre, go to **Devices → Scripts and remediations → Platform scripts (Proactive Remediations)**.
2. Create a new script package:
   - **Detection script**: `detect.ps1`
   - **Remediation script**: `remediate.ps1`
   - **Run script as logged-on user**: No (run as SYSTEM)
   - **Enforce script signature check**: No
   - **Run script in 64-bit PowerShell**: **Yes** (important — see Requirements)
3. Assign to a Lenovo-only device group.

Files
-----

| File | Description |
|---|---|
| `detect.ps1` | Detection: registry, install paths, processes, services, AppX packages, AppX repository stubs, sentinel suppression. Exits 1 on any find. |
| `remediate.ps1` | Full removal: two-phase model, COM surface cleanup, MSIX removal, PFRO queue for locked files, sentinel write. |
| `tools/diagnose_clsid_walk.ps1` | Optional read-only diagnostic that times the CLSID hive walk via PowerShell cmdlets vs the .NET registry API. Useful when investigating registry-walk performance on a specific device. |
| `README.md` | This file. |
| `CLAUDE.md` | Design contract for the repo (escalation ladder, exit code mapping, per-user cleanup approach). |

Logs & troubleshooting
----------------------

**Log path**: `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Lenovo_AI_Now_Remediate.log`

(The detect script writes to Intune's standard PR stdout capture, not a separate log file. Use the Intune console or `AgentExecutor.log` for detection output.)

**Common scenarios:**

- **Exit 3010 (Phase A complete, reboot pending)**: expected on first run for any device with the install dir still present. User reboots, PFRO clears the install dir at next boot, next detect cycle exits 0.
- **Exit 1603 (partial failure)**: residuals remain AND the PFRO queue write failed. Check the log for `Failed to write PendingFileRenameOperations`. Rare; usually indicates registry write protection (e.g., very aggressive ASR/EDR policy).
- **Exit 1 (unhandled exception)**: check the log for `REMEDIATION FAILED: Unhandled exception` and the position message that follows.
- **Detect keeps triggering remediate with no observed cleanup**: the device may not be receiving the latest script version. Verify with `Get-ChildItem 'C:\Windows\IMECache\HealthScripts\<guid>_*' -Directory` and check the highest-numbered cache version is current.

**MDE Advanced Hunting queries** (useful for monitoring fleet rollout):

```kql
// Devices in Phase A (sentinel set, waiting for reboot)
DeviceRegistryEvents
| where Timestamp > ago(14d)
| where RegistryKey has @"SOFTWARE\LenovoAINowRemediation"
| where RegistryValueName == "PhaseAComplete"
| where ActionType == "RegistryValueSet"
| summarize PhaseAAt = max(Timestamp) by DeviceName, DeviceId
| extend HoursSincePhaseA = datetime_diff('hour', now(), PhaseAAt)
```

```kql
// Cleanup progress: should trend to zero as devices reboot
DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where FileName in~ ("AINppShell.dll", "OverlayIcon.dll")
| summarize Loads = count(), Devices = dcount(DeviceId) by FileName
```

What this fork changes
----------------------

The upstream version tries to delete files in-session and uses an Explorer-kill window plus a "schedule ≤5 locked files for reboot delete" fallback. In production this loses against `AutoRestartShell` and against the 17+ non-Explorer processes that also hold the DLLs, so most devices end up with 270 residual files and no PFRO queue. Notable changes in this fork:

- **Pivot to PFRO + reboot as the primary path** for the install directory. Drop the Explorer-kill block and the ≤5-file PFRO gate.
- **Self-relaunch under 64-bit PowerShell** so the script sees the correct registry hive.
- **Full mapping of the COM registration surface**: hardcodes the 3 confirmed CLSIDs + AppID + TypeLib + 2 ProgIDs + 10 shellex handler subkeys; also walks both 64-bit and `Wow6432Node` CLSID hives dynamically via the .NET registry API (`Microsoft.Win32.Registry`), which is ~200× faster than `Get-ChildItem` on registry paths.
- **MSIX/AppX handling**: `Remove-AppxPackage -AllUsers` for `AINowContextWIN11`, plus `Remove-AppxProvisionedPackage -Online`, plus explicit cleanup of the orphaned per-user repository stubs at `HKU\<sid>\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages` and the HKLM `AppxAllUserStore` mirrors. Microsoft's removal leaves these behind.
- **Service disable-before-stop** sequence (`sc config start= disabled` → `Stop-Service` → `WaitForStatus('Stopped', 30s)` → `sc delete`) to prevent auto-restart races.
- **Wildcard match for the uninstall DisplayName** — the upstream regex `^Lenovo AI Now\b` silently didn't match the actual `Lenovo AI Now 1.3` entry on observed devices.
- **`-LiteralPath` for registry paths containing literal `*`** — the upstream used `-Path`, which expanded `*` as a wildcard across every HKCR subkey and could hang for minutes.
- **Sentinel + suppression** in detect to prevent retrigger between Phase A and reboot.
- **Removed dead code** (`Invoke-Uninstaller`, `Invoke-MsiUninstall`) and the robocopy fallback (which can deadlock against kernel-locked DLLs).

Validated on two real Lenovo devices: one starting from full fresh-install state (exercised the PFRO + reboot path), one in mid-cleanup state (exercised direct deletion after natural reboot). Both reached exit 0.

Caveats
-------

- The scripts do not handle Lenovo Vantage / Commercial Vantage re-pushing AI Now after removal. If your fleet has a Vantage policy that re-installs the app, a separate Vantage policy change is needed.
- "Lenovo AI Solution", "Lenovo AI Meeting Manager", and other Lenovo AI-family apps are **out of scope**. The scripts match specifically on `*Lenovo AI Now*` and the known CLSIDs.
- Win32 app deployment is untested. Test thoroughly in a pilot environment first.
- Tested against Lenovo AI Now version 1.3 only. Future versions with different CLSIDs would still be caught by the dynamic walk (matched by DLL filename + parent path containing `\Lenovo\Lenovo AI\`), but new DLL filenames would need the script's `$lenovoAIDllFileNames` list extended.
