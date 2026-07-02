Lenovo AI Now Removal
=====================

PowerShell proactive remediation scripts for detecting and removing Lenovo AI Now from Intune-managed Windows devices.

Files
-----

| File | Purpose |
|------|---------|
| `detect.ps1` | Detects Lenovo AI Now traces and exits `1` when remediation should run. |
| `remediate.ps1` | Removes Lenovo AI Now components, including locked shell-extension files that require reboot-time deletion. |

Detection
---------

`detect.ps1` re-launches itself in native 64-bit Windows PowerShell when Intune starts it in a 32-bit host. It checks:

- 32-bit and 64-bit uninstall registry entries.
- Common install directories under `C:\Program Files`, `C:\Program Files (x86)`, and `C:\ProgramData`.
- Known Lenovo AI Now executable names, running processes, and services.
- Installed and provisioned AppX/MSIX packages.
- Orphaned AppX repository stubs under loaded user hives and HKLM AppX store keys.

Detection exits:

- `1` when Lenovo AI Now is detected and remediation should run.
- `0` when no remediation is needed.
- `0` while a fresh remediation sentinel and Lenovo `PendingFileRenameOperations` entries exist, which prevents repeat remediation loops while the device is waiting for a reboot.

Remediation
-----------

`remediate.ps1` also re-launches itself in native 64-bit Windows PowerShell. It performs manual cleanup because the vendor uninstall path is not reliable in SYSTEM context.

The remediation flow:

1. Attempt Lenovo's vendor uninstaller with the current typoed silent switch: `SlientUninstall`.
2. Stop and disable Lenovo AI Now services.
3. Stop Lenovo AI Now processes by install path and executable name.
4. Remove installed and provisioned AppX/MSIX packages.
5. Scrub orphaned AppX repository stubs.
6. Unregister known and discovered Lenovo AI Now shell extensions.
7. Remove user data, shortcuts, scheduled tasks, registry keys, and Run values.
8. Remove install directories in-session when possible.
9. Rename remaining files to `*.tobedeleted`, queue locked files and directories in `PendingFileRenameOperations`, and write a Phase A sentinel when a reboot is required.

The vendor uninstall is best-effort only. Validation against Lenovo AI Now `1.3.3.912` showed `SlientUninstall` removes the app, uninstall entry, install directory, and AppX package, but can leave shell/COM registry traces behind. The script continues the manual cleanup path so those leftovers are still removed.

Locked shell-extension DLLs such as `AINppShell.dll` and `OverlayIcon.dll` are expected on active desktops. The script queues those files for boot-time deletion instead of killing Explorer or attempting long-running deletion workarounds.

Exit Behavior
-------------

The remediation log records the internal result:

- `0`: Complete success.
- `3010`: Cleanup succeeded, reboot required to finish file deletion.
- `1603`: Partial failure; residual components remain and could not be queued for reboot deletion.
- `1`: Unhandled remediation error.

For Intune compatibility, `3010` is reported to Intune as process exit `0`. Check the log for the actual remediation result.

Logs
----

Remediation writes to:

`C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Lenovo_AI_Now_Remediate.log`

The detection script writes status to script output, which Intune captures in the remediation run details.

Intune Settings
---------------

- Run under SYSTEM context.
- Set **Run script as 32-bit process on 64-bit clients** to **No** when possible.
- The scripts include a 64-bit relaunch guard, but using the 64-bit host directly avoids an extra process hop.

Validation
----------

Test on a pilot device before broad deployment:

1. Run `detect.ps1`; expect `1` when Lenovo AI Now is present.
2. Run `remediate.ps1`; expect Intune-compatible exit `0`.
3. Run `detect.ps1` again; expect `0` if cleanup completed or reboot-time cleanup is queued.
4. Reboot if the remediation log records internal result `3010`.
5. Run `detect.ps1` again; expect `0` with no Lenovo AI Now traces.
