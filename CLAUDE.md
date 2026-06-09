# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository purpose

Two PowerShell scripts that pair together as a Microsoft Intune **Proactive Remediation** (Platform Scripts): `detect.ps1` decides whether action is needed and `remediate.ps1` does the cleanup. They run as SYSTEM, log to the Intune Management Extension log folder, and target Lenovo AI Now bloatware on Lenovo OEM devices.

There is no build, test, or package step — these are deployed by uploading the two `.ps1` files to Intune. Validate changes by running them locally on a Windows test box (or a VM with the target software installed) under an elevated PowerShell session. There is no test harness to run from this repo.

## How the two scripts contract together

`detect.ps1` exit code drives whether Intune invokes `remediate.ps1`:

- **exit 1** → remediation needed. Trigger conditions (any of): matching uninstall registry entry, known executable found under an install root, running process matching a known name, matching service, OR file count under any install root exceeds `$fileThreshold` (currently 5).
- **exit 0** → no action. Note: residual files *below* the threshold still produce exit 0 — this is intentional, to avoid re-triggering remediation cycles after a 3010 reboot-pending success.

If you change one script's detection/match patterns, change the other's to match. The two scripts maintain parallel lists of: registry roots, install paths, executable names, service-name regex/wildcards.

## Remediation pipeline (order matters)

`Invoke-LenovoAiNowRemediation` in `remediate.ps1` runs steps in this order, and the order is load-bearing:

1. Discover install paths from uninstall registry entries (`Get-LenovoAiNowEntries`), union with `$defaultInstallPaths`.
2. Early exit (return 0) if no entries AND no install paths exist — but still scrub user-profile leftovers and Start Menu shortcuts before returning.
3. Stop services under those paths, then stop processes (twice — once by path, once by executable name) so handles are released before file deletion.
4. `Remove-LenovoAIServices` deletes service registrations via `sc.exe delete` (must come *after* stops).
5. `Unregister-LenovoAIShellExtensions` removes CLSID entries whose `InprocServer32` points at a Lenovo AI Now DLL — these hold Explorer file locks if left in place.
6. `Remove-UserData`, `Remove-StartMenuShortcuts`, `Remove-ScheduledTasks`.
7. `Remove-Residuals` deletes remaining install directories and a hardcoded list of registry keys.
8. **Re-run** the stop-services/stop-processes pass — some components respawn during cleanup.
9. Verify residuals; if any remain, escalate (see below) and compute the return code.

Keep this order when refactoring. Skipping the second stop pass or running shell-extension cleanup after the directory delete will cause locked-file failures.

## Escalation ladder for stubborn directories

`Remove-DirectoryWithRetry` in `remediate.ps1` is the central deletion utility, with progressive escalation across attempts:

1. **Attempt 1**: `takeown /r /d y` + `icacls /grant Administrators:F /t`, then `Remove-Item -Recurse -Force`.
2. **Attempt 2 (on failure)**: stop services/processes under the path again, then **robocopy with `/MIR` from an empty temp directory** to forcibly empty the target, then remove the now-empty dir. Robocopy reliably deletes files that `Remove-Item` chokes on (long paths, unusual ACLs).
3. **Attempt 2 fallback**: stop `explorer.exe` and `dllhost.exe` for ~3 seconds to release shell-extension DLL handles, retry deletion, then restart Explorer.
4. **Final attempt (on max retries)**: if ≤5 files remain, rename each to `*.tobedeleted` and queue them via `Add-PendingFileDelete` (writes to `HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations`) so Windows deletes them on next boot. This drives the **3010** exit code.

When debugging "won't delete" issues, work down this ladder rather than adding more `Remove-Item` retries at the top.

## Exit code translation (Intune compatibility)

`remediate.ps1` distinguishes between its **internal** result and the **Intune-reported** exit code:

| Internal | Intune (`$intuneExitCode`) | Meaning |
|----------|---------------------------|---------|
| 0        | 0                         | Clean removal |
| 3010     | 0                         | Success, reboot pending — Intune sees this as success so it doesn't re-trigger before reboot |
| 1603     | 1                         | Partial failure (residuals remain) |
| 1        | 1                         | Unhandled exception |

Both values are logged. **Don't collapse this into a single exit value** — Intune retries on non-zero, and treating 3010 as failure causes loops on devices that need a reboot.

## Per-user cleanup (HKEY_USERS via SID)

`Remove-UserData` enumerates `C:\Users\*` (skipping system profiles via `Get-UserProfileDirectories`), and for each user resolves the SID through three fallbacks in `Resolve-UserProfileSid`:

1. `Win32_UserProfile` CIM class by `LocalPath`.
2. `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` by `ProfileImagePath`.
3. `NTAccount.Translate(SecurityIdentifier)`.

It then cleans `Registry::HKEY_USERS\<sid>\...` keys directly — this is necessary because the user's `HKCU` hive is only mounted while they're logged in, so SYSTEM-context scripts must address per-user data through the `HKEY_USERS` hive by SID. Reuse `Resolve-UserProfileSid` rather than rolling new SID-resolution logic.

## Logging

All `Write-Log` calls in `remediate.ps1` go to `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Lenovo_AI_Now_Remediate.log`. `detect.ps1` uses `Write-Host` only — Intune captures stdout for detection scripts, so logging there is implicit. When adding diagnostic output to `remediate.ps1`, prefer `Write-Log` with an explicit level (`INFO`/`WARNING`/`ERROR`/`DEBUG`).
