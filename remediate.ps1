# Remediate Lenovo AI Now.
#
# Two-phase model:
#   Phase A -- clean what can be cleaned in-session (services, processes,
#             user data, shortcuts, uninstall reg entry, shell-extension
#             registrations, AppX/MSIX package). Queue any locked install-
#             dir files for boot-time deletion via PendingFileRenameOperations.
#             Write a sentinel so detect.ps1 can suppress retrigger until
#             the user reboots. Exit 3010, Intune treats as success.
#   Phase B -- after user reboots, SMSS processes PFRO, install dir is gone,
#             detect re-fires clean, exit 0.
#
# Why reboot-time deletion: AINppShell.dll (property handler) and
# OverlayIcon.dll (icon overlay handler) are loaded by virtually every
# shell-using GUI app on the machine (Word, Edge, Outlook, Chrome,
# any app that opens a file dialog). In-session deletion is unwinnable;
# SMSS processes PFRO before any of those processes exist on the next boot.

# Re-launch under native 64-bit PowerShell if Intune started us in 32-bit
# (the default for Proactive Remediation scripts). 32-bit PS reads of
# HKLM:\SOFTWARE\... are silently WOW64-redirected to Wow6432Node, where
# the Lenovo AI Now CLSIDs and uninstall key are NOT present -- so the
# script runs blind and deletes nothing.
if ($env:PROCESSOR_ARCHITECTURE -eq 'x86' -and (Test-Path "$env:WINDIR\SysNative\WindowsPowerShell\v1.0\powershell.exe")) {
    & "$env:WINDIR\SysNative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @args
    exit $LASTEXITCODE
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

### Logging Setup ###
$logFolder = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs"
if (-not (Test-Path $logFolder)) { New-Item -ItemType Directory -Path $logFolder | Out-Null }
$logFile = Join-Path $logFolder "Lenovo_AI_Now_Remediate.log"

# Rotate log if larger than 5 MB; many remediation cycles can otherwise
# fill the IME log folder.
try {
    if ((Test-Path $logFile) -and ((Get-Item $logFile).Length -gt 5MB)) {
        $rotated = "$logFile.old"
        if (Test-Path $rotated) { Remove-Item $rotated -Force -ErrorAction SilentlyContinue }
        Move-Item $logFile $rotated -Force -ErrorAction SilentlyContinue
    }
} catch {
    # rotation is best-effort
}

function Write-Log {
    param(
        [Parameter(Position=0)]
        [string]$Message,
        [Parameter(Position=1)]
        [ValidateSet("INFO","WARNING","ERROR","DEBUG")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$Level] $Message"
    Write-Host $logEntry
    Add-Content -Path $logFile -Value $logEntry
}

Write-Log "=== Starting Lenovo AI Now Remediation Script ==="

# Wildcard match (same as detect.ps1). Earlier regex `^Lenovo AI Now\b`
# failed to match the actual uninstall DisplayName on real devices, which
# is why the uninstall key survived prior remediation runs.
$targetDisplayNamePattern = '*Lenovo AI Now*'

$uninstallRoots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)
$defaultInstallPaths = @(
    'C:\Program Files\Lenovo\Lenovo AI Now',
    'C:\Program Files (x86)\Lenovo\Lenovo AI Now',
    'C:\ProgramData\Lenovo\Lenovo AI Now'
)

# Confirmed via direct registry inspection on Lenovo AI Now 1.3.
$knownLenovoAIClsids = @(
    '{281E645C-1F68-4276-80F6-8476CED89BB1}',  # AINppShell handler (Win11 MSIX-bound + legacy)
    '{B872E6A0-3D43-48B9-BF55-6952BE5B297A}',  # AINppShell handler (Win10 legacy, "LenovoAINowShell")
    '{4B48C68B-80D6-40FB-B4D1-63C19130EC75}'   # OverlayIcon handler
)

# COM satellite keys created by the OverlayIcon registration.
$knownLenovoAISatelliteKeys = @(
    'HKLM:\SOFTWARE\Classes\AppID\{5D1C76DE-B933-40AC-B588-6B46EA0A45C9}',
    'HKLM:\SOFTWARE\Classes\TypeLib\{8EE1DABC-E488-4AB8-8184-817AA4456D51}',
    'HKLM:\SOFTWARE\Classes\LenovoAINowOverlayIcon.MyLenovoAINowOverlayIcon.1',
    'HKLM:\SOFTWARE\Classes\LenovoAINowOverlayIcon.MyLenovoAINowOverlayIcon'
)

# shellex handler registrations under each file-type root. Subkey name
# is literally "Lenovo AI Now" (with spaces).
$knownLenovoAIShellexKeys = @(
    'HKLM:\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\Lenovo AI Now',
    'HKLM:\SOFTWARE\Classes\*\shellex\DragDropHandlers\Lenovo AI Now',
    'HKLM:\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\Lenovo AI Now',
    'HKLM:\SOFTWARE\Classes\Directory\shellex\DragDropHandlers\Lenovo AI Now',
    'HKLM:\SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\Lenovo AI Now',
    'HKLM:\SOFTWARE\Classes\Drive\shellex\DragDropHandlers\Lenovo AI Now',
    'HKLM:\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers\Lenovo AI Now',
    'HKLM:\SOFTWARE\Classes\Folder\shellex\DragDropHandlers\Lenovo AI Now',
    'HKLM:\SOFTWARE\Classes\lnkfile\shellex\ContextMenuHandlers\Lenovo AI Now',
    'HKLM:\SOFTWARE\Classes\lnkfile\shellex\DragDropHandlers\Lenovo AI Now'
)

# DLL filenames that identify a Lenovo AI Now COM in-proc server, used by
# the registry-walk fallback. Path must also contain "\Lenovo\" to avoid
# colliding with unrelated DLLs of the same name from other vendors.
$lenovoAIDllFileNames = @('AINppShell.dll', 'OverlayIcon.dll')

# Sentinel written after Phase A queues PFRO, read by detect.ps1.
$sentinelKey = 'HKLM:\SOFTWARE\LenovoAINowRemediation'
$sentinelValueName = 'PhaseAComplete'

# Process executable names (lowercased, with .exe) for path-less kill pass.
# Match Win32_Process.Name which includes the extension.
$processExecutables = @(
    'lenovo ainow.exe',
    'lenovo ainow helper.exe',
    'lenovo ainow launcher.exe',
    'lenovo ainow mini.exe',
    'lenovo ainow oobe.exe',
    'lenovo ainow safetychecker.exe',
    'lenovo ainow service.exe',
    'lenovo ainow utility.exe',
    'lenovo ainow uninstall.exe',
    'ainow.tostnotification.exe'
)

function Get-UninstallEntries {
    param([string[]]$Roots)
    foreach ($root in $Roots) {
        if (-not (Test-Path -Path $root)) { continue }
        foreach ($child in Get-ChildItem -Path $root -ErrorAction SilentlyContinue) {
            try {
                $item = Get-ItemProperty -Path $child.PSPath -ErrorAction Stop
                $item | Add-Member -NotePropertyName RegistryPath -NotePropertyValue $child.PSPath -Force
                $item
            } catch {
                Write-Log "Failed to read uninstall entry at $($child.PSPath): $($_.Exception.Message)"
            }
        }
    }
}

function Get-LenovoAiNowEntries {
    Get-UninstallEntries -Roots $uninstallRoots |
        Where-Object {
            $_.PSObject.Properties['DisplayName'] -and
            $_.DisplayName -like $targetDisplayNamePattern
        }
}

function Stop-ProcessesUnderPaths {
    param(
        [string[]]$Paths,
        [string[]]$ExecutableNames,
        [int]$MaxAttempts = 5,
        [int]$DelaySeconds = 2
    )

    $normalizedPaths = @($Paths |
        Where-Object { $_ } |
        ForEach-Object { $_.TrimEnd('\') } |
        Where-Object { $_ })

    $normalizedExecutables = @($ExecutableNames |
        Where-Object { $_ } |
        ForEach-Object { $_.Trim().ToLowerInvariant() } |
        Select-Object -Unique)

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $processes = Get-CimInstance Win32_Process -ErrorAction Stop
        } catch {
            Write-Log "Unable to enumerate processes: $($_.Exception.Message)"
            return
        }

        $targets = @()
        foreach ($process in $processes) {
            if (-not $process.Name) { continue }
            $match = $false
            $processNameLower = $process.Name.ToLowerInvariant()

            if ($normalizedExecutables -and ($normalizedExecutables -contains $processNameLower)) {
                $match = $true
            }

            if (-not $match -and $normalizedPaths) {
                $executablePath = $process.ExecutablePath
                if ($executablePath) {
                    foreach ($path in $normalizedPaths) {
                        if ($executablePath.StartsWith($path, [System.StringComparison]::OrdinalIgnoreCase)) {
                            $match = $true
                            break
                        }
                    }
                }
            }

            if ($match) { $targets += $process }
        }

        if (-not $targets) {
            if ($attempt -eq 1) { Write-Log 'No Lenovo AI Now processes detected.' }
            break
        }

        foreach ($process in $targets | Sort-Object -Property ProcessId -Unique) {
            try {
                Write-Log "Stopping process $($process.Name) (PID $($process.ProcessId))"
                Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
            } catch {
                Write-Log "Failed to stop process $($process.Name) (PID $($process.ProcessId)): $($_.Exception.Message)"
                try {
                    Start-Process -FilePath 'taskkill.exe' -ArgumentList "/PID $($process.ProcessId) /T /F" -WindowStyle Hidden -ErrorAction Stop | Out-Null
                    Write-Log "Issued taskkill for PID $($process.ProcessId)."
                } catch {
                    Write-Log "taskkill failed for PID $($process.ProcessId): $($_.Exception.Message)"
                }
            }
        }

        Start-Sleep -Seconds $DelaySeconds
    }
}

function Disable-AndStopService {
    # Disable the service so SCM can't restart it, then stop, wait for
    # Stopped state, and delete. Prevents the auto-restart race that left
    # AINppShell.dll locked in prior runs.
    param([Parameter(Mandatory)][string]$Name)

    try {
        Start-Process -FilePath 'sc.exe' -ArgumentList "config `"$Name`" start= disabled" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue | Out-Null
    } catch {
        Write-Log "sc config disabled failed for $Name : $($_.Exception.Message)" "DEBUG"
    }

    try {
        Stop-Service -Name $Name -Force -ErrorAction Stop
    } catch {
        Write-Log "Stop-Service $Name failed: $($_.Exception.Message)" "DEBUG"
    }

    try {
        $svc = Get-Service -Name $Name -ErrorAction Stop
        $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    } catch {
        Write-Log "WaitForStatus Stopped on $Name failed: $($_.Exception.Message)" "DEBUG"
    }

    try {
        $del = Start-Process -FilePath 'sc.exe' -ArgumentList "delete `"$Name`"" -WindowStyle Hidden -Wait -PassThru -ErrorAction Stop
        if ($del.ExitCode -ne 0) {
            Write-Log "sc delete $Name returned exit code $($del.ExitCode)"
        } else {
            Write-Log "Service $Name deleted."
        }
    } catch {
        Write-Log "sc delete $Name failed: $($_.Exception.Message)"
    }
}

function Stop-ServicesUnderPaths {
    param([string[]]$Paths)
    $normalized = @($Paths |
        Where-Object { $_ } |
        ForEach-Object { $_.TrimEnd('\') } |
        Where-Object { $_ })
    if (-not $normalized) { return }

    try {
        $services = Get-CimInstance Win32_Service -ErrorAction Stop
    } catch {
        Write-Log "Unable to enumerate services: $($_.Exception.Message)"
        return
    }

    foreach ($service in $services) {
        $pathName = $service.PathName
        if (-not $pathName) { continue }

        $executable = $null
        if ($pathName -match '^\s*"(?<path>[^"]+)"') {
            $executable = $matches.path
        } else {
            $executable = ($pathName -split '\s+', 2)[0]
        }
        if (-not $executable) { continue }

        $matchesInstallPath = $false
        foreach ($path in $normalized) {
            if ($executable.StartsWith($path, [System.StringComparison]::OrdinalIgnoreCase)) {
                $matchesInstallPath = $true
                break
            }
        }
        if (-not $matchesInstallPath) { continue }

        if ($service.State -eq 'Running') {
            Write-Log "Stopping service $($service.Name) with path $executable"
        }
        Disable-AndStopService -Name $service.Name
    }
}

function Remove-DirectoryWithRetry {
    # Attempts in-session deletion only. Any files that can't be removed
    # are handled by the caller via Add-PendingFileDeleteBatch for boot-time
    # cleanup. No Explorer-kill or AutoRestartShell race -- that approach
    # cannot succeed when shell-extension DLLs are loaded into 18+
    # processes across the system.
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [int]$MaxAttempts = 2,
        [int]$DelaySeconds = 3
    )

    if (-not (Test-Path -Path $Path)) { return $true }

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            Write-Log "Removing directory $Path (attempt $attempt of $MaxAttempts)"
            try {
                & takeown /f "$Path" /r /d y 2>&1 | Out-Null
                & icacls "$Path" /grant Administrators:F /t 2>&1 | Out-Null
            } catch {
                Write-Log "takeown/icacls failed on $Path : $($_.Exception.Message)" "DEBUG"
            }
            Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
            return $true
        } catch {
            Write-Log "Failed to remove $Path : $($_.Exception.Message)"
            if ($attempt -lt $MaxAttempts) {
                # Kill anything new under the path before retrying takeown +
                # Remove-Item. Don't try robocopy as a fallback -- it can
                # hang indefinitely against kernel-locked DLLs (e.g. loaded
                # shell extensions), exceeding Intune's PR timeout. Locked
                # files are PFRO's job, not robocopy's.
                Stop-ServicesUnderPaths -Paths @($Path)
                Stop-ProcessesUnderPaths -Paths @($Path) -ExecutableNames $processExecutables
                Start-Sleep -Seconds $DelaySeconds
            }
        }
    }
    return $false
}

function Add-PendingFileDeleteBatch {
    # Atomic, deduped, single-write batch of PendingFileRenameOperations
    # entries. SMSS processes PFRO during early boot before any shell
    # process is loaded, which is the only reliable way to delete files
    # held open by shell-extension DLLs across many processes.
    #
    # The MULTI_SZ format is paired strings: source, destination. Empty
    # destination means delete. Source must be in NT path form (\??\<path>).
    # Directories must come AFTER their contents (bottom-up); SMSS won't
    # delete a non-empty directory.
    param(
        [Parameter(Mandatory)][string[]]$FilePaths,
        [Parameter(Mandatory)][string[]]$DirectoryPaths   # already ordered bottom-up
    )

    $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    $regName = 'PendingFileRenameOperations'

    # Read existing entries; preserve them so we don't clobber Windows
    # Update / driver-install pending operations from other components.
    $existing = @()
    try {
        $raw = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop
        if ($raw.PSObject.Properties[$regName]) {
            $existing = @($raw.$regName)
        }
    } catch {
        $existing = @()
    }

    # Build a hashset of source paths already queued so we don't duplicate.
    $existingSources = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    for ($i = 0; $i -lt $existing.Count; $i += 2) {
        if ($existing[$i]) { [void]$existingSources.Add($existing[$i]) }
    }

    $newEntries = New-Object System.Collections.Generic.List[string]
    $added = 0

    foreach ($file in $FilePaths) {
        if (-not $file) { continue }
        $src = "\??\$file"
        if ($existingSources.Contains($src)) { continue }
        $newEntries.Add($src)
        $newEntries.Add('')
        [void]$existingSources.Add($src)
        $added++
    }

    foreach ($dir in $DirectoryPaths) {
        if (-not $dir) { continue }
        $src = "\??\$dir"
        if ($existingSources.Contains($src)) { continue }
        $newEntries.Add($src)
        $newEntries.Add('')
        [void]$existingSources.Add($src)
        $added++
    }

    if ($added -eq 0) {
        Write-Log "PendingFileRenameOperations: no new entries to queue."
        return 0
    }

    $combined = @($existing) + $newEntries.ToArray()
    try {
        Set-ItemProperty -Path $regPath -Name $regName -Value $combined -Type MultiString -Force -ErrorAction Stop
        Write-Log "Queued $added items in PendingFileRenameOperations (total: $($combined.Count / 2) entries)."
        return $added
    } catch {
        Write-Log "Failed to write PendingFileRenameOperations: $($_.Exception.Message)" "ERROR"
        return 0
    }
}

function Get-PendingDeleteCandidates {
    # Walk a directory bottom-up, returning files and dirs in delete order
    # (files first, then leaf dirs, then parents, root last).
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -Path $Path)) {
        return @{ Files = @(); Directories = @() }
    }

    $files = @()
    $dirs = @()
    try {
        # SortByLength descending => deepest paths first. Files appear deeper
        # than the dirs containing them; this gives a usable bottom-up order
        # without recursive traversal.
        $allItems = Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue |
            Sort-Object -Property { $_.FullName.Length } -Descending
        foreach ($item in $allItems) {
            if ($item.PSIsContainer) {
                $dirs += $item.FullName
            } else {
                $files += $item.FullName
            }
        }
    } catch {
        Write-Log "Enumerating $Path for PFRO failed: $($_.Exception.Message)"
    }
    $dirs += $Path

    return @{ Files = $files; Directories = $dirs }
}

function Set-PhaseACompleteSentinel {
    try {
        if (-not (Test-Path -Path $sentinelKey)) {
            New-Item -Path $sentinelKey -Force -ErrorAction Stop | Out-Null
        }
        $stamp = (Get-Date).ToUniversalTime().ToString('o')
        Set-ItemProperty -Path $sentinelKey -Name $sentinelValueName -Value $stamp -Type String -Force
        Write-Log "Phase A sentinel written: $stamp"
    } catch {
        Write-Log "Failed to write Phase A sentinel: $($_.Exception.Message)" "WARNING"
    }
}

function Clear-PhaseACompleteSentinel {
    try {
        if (Test-Path -Path $sentinelKey) {
            Remove-Item -Path $sentinelKey -Recurse -Force -ErrorAction Stop
            Write-Log "Phase A sentinel cleared."
        }
    } catch {
        Write-Log "Failed to clear Phase A sentinel: $($_.Exception.Message)" "DEBUG"
    }
}

function Get-UserProfileDirectories {
    $excluded = @('All Users', 'Default', 'Default User', 'Public', 'DefaultAppPool')
    Get-ChildItem -Path 'C:\Users' -Directory -ErrorAction SilentlyContinue |
        Where-Object {
            $name = $_.Name
            -not ($excluded -contains $name) -and
            -not $name.StartsWith('.', [System.StringComparison]::OrdinalIgnoreCase)
        }
}

function Resolve-UserProfileSid {
    param(
        [Parameter(Mandatory = $true)][string]$LocalPath,
        [Parameter(Mandatory = $true)][string]$ProfileName
    )

    try {
        $cimProfiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalPath -eq $LocalPath }
        foreach ($cimProfile in @($cimProfiles)) {
            if ($cimProfile.SID) { return $cimProfile.SID }
        }
    } catch {
        Write-Log "Resolve-UserProfileSid: CIM lookup failed for $LocalPath : $($_.Exception.Message)" "DEBUG"
    }

    try {
        $profileListKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        if (Test-Path -Path $profileListKey) {
            foreach ($entry in Get-ChildItem -Path $profileListKey -ErrorAction SilentlyContinue) {
                try {
                    $profileData = Get-ItemProperty -Path $entry.PSPath -ErrorAction Stop
                    if ($profileData.PSObject.Properties['ProfileImagePath'] -and
                        $profileData.ProfileImagePath -and
                        ($profileData.ProfileImagePath -ieq $LocalPath)) {
                        return $entry.PSChildName
                    }
                } catch { }
            }
        }
    } catch {
        Write-Log "Resolve-UserProfileSid: registry lookup failed for $LocalPath : $($_.Exception.Message)" "DEBUG"
    }

    try {
        $ntAccount = New-Object System.Security.Principal.NTAccount($ProfileName)
        $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
        if ($sid) { return $sid }
    } catch { }

    return $null
}

function Remove-UserData {
    $userProfiles = Get-UserProfileDirectories
    $targets = @()

    foreach ($userProfile in $userProfiles) {
        $profilePath = $userProfile.FullName
        $targets += @(
            (Join-Path -Path $profilePath -ChildPath 'AppData\Local\Lenovo\Lenovo AI Now'),
            (Join-Path -Path $profilePath -ChildPath 'AppData\Local\Lenovo\LenovoAI Now'),
            (Join-Path -Path $profilePath -ChildPath 'AppData\Local\Lenovo\AI Now'),
            (Join-Path -Path $profilePath -ChildPath 'AppData\Roaming\Lenovo\Lenovo AI Now'),
            (Join-Path -Path $profilePath -ChildPath 'AppData\Roaming\Lenovo\LenovoAI Now'),
            (Join-Path -Path $profilePath -ChildPath 'AppData\Roaming\Lenovo\AI Now')
        )

        $userSid = Resolve-UserProfileSid -LocalPath $profilePath -ProfileName $userProfile.Name
        if ($userSid) {
            $userRegPaths = @(
                "Registry::HKEY_USERS\$userSid\SOFTWARE\Lenovo\AI Now",
                "Registry::HKEY_USERS\$userSid\SOFTWARE\Lenovo\Lenovo AI Now",
                "Registry::HKEY_USERS\$userSid\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Lenovo AI Now",
                "Registry::HKEY_USERS\$userSid\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\LenovoAINow"
            )
            foreach ($regPath in $userRegPaths) {
                if (Test-Path -Path $regPath) {
                    try {
                        Write-Log "Removing user registry key $regPath for user $($userProfile.Name)"
                        Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
                    } catch {
                        Write-Log "Failed to remove user registry key $regPath : $($_.Exception.Message)"
                    }
                }
            }
        } else {
            Write-Log "Could not resolve SID for user $($userProfile.Name) at $profilePath" "DEBUG"
        }
    }

    foreach ($target in $targets | Where-Object { $_ } | Select-Object -Unique) {
        if (-not (Remove-DirectoryWithRetry -Path $target)) {
            Write-Log "Unable to remove user data directory $target." "WARNING"
        }
    }
}

function Remove-StartMenuShortcuts {
    $shortcutRoots = @(
        'C:\ProgramData\Microsoft\Windows\Start Menu',
        'C:\ProgramData\Microsoft\Windows\Start Menu\Programs',
        'C:\Users\Public\Desktop'
    )
    foreach ($userProfile in Get-UserProfileDirectories) {
        $shortcutRoots += @(
            (Join-Path $userProfile.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu'),
            (Join-Path $userProfile.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs'),
            (Join-Path $userProfile.FullName 'Desktop')
        )
    }
    $shortcutRoots = $shortcutRoots | Where-Object { $_ } | Select-Object -Unique

    foreach ($root in $shortcutRoots) {
        if (-not (Test-Path -Path $root)) { continue }
        try {
            $shortcuts = @(Get-ChildItem -Path $root -Filter '*Lenovo*AI*.lnk' -Recurse -ErrorAction SilentlyContinue)
        } catch {
            Write-Log "Failed to enumerate shortcuts under $root : $($_.Exception.Message)"
            continue
        }
        foreach ($shortcut in $shortcuts) {
            try {
                Write-Log "Removing shortcut $($shortcut.FullName)"
                Remove-Item -Path $shortcut.FullName -Force -ErrorAction Stop
            } catch {
                Write-Log "Failed to remove shortcut $($shortcut.FullName): $($_.Exception.Message)"
            }
        }
    }
}

function Remove-Residuals {
    param(
        [string[]]$InstallPaths,
        [string[]]$RegistryPaths
    )

    foreach ($path in $InstallPaths | Where-Object { $_ }) {
        if (-not (Test-Path -Path $path)) { continue }
        if (-not (Remove-DirectoryWithRetry -Path $path)) {
            Write-Log "Could not remove directory $path in-session; will queue for boot delete." "WARNING"
        }
    }

    foreach ($regPath in $RegistryPaths | Where-Object { $_ }) {
        if (-not (Test-Path -Path $regPath)) { continue }
        try {
            Write-Log "Removing residual registry key $regPath"
            Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
        } catch {
            Write-Log "Failed to remove registry key $regPath : $($_.Exception.Message)"
        }
    }
}

function Remove-LenovoAIServices {
    try {
        $services = @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object {
            $_.Name -match '(?i)lenovo.*ai.*now' -or
            $_.Name -match '(?i)lenovoai' -or
            $_.DisplayName -match '(?i)lenovo.*ai.*now'
        })

        foreach ($service in $services) {
            Write-Log "Cleaning up Lenovo AI service: $($service.Name) ($($service.DisplayName))"
            Disable-AndStopService -Name $service.Name
        }
    } catch {
        Write-Log "Error enumerating services for removal: $($_.Exception.Message)"
    }
}

function Remove-LenovoAINowAppxPackages {
    # Removes the AINowContextWIN11 MSIX (and any sibling). Remove-AppxPackage
    # terminates the package's processes (AINow.Service.exe etc.) as part of
    # removal so we don't need to kill them manually.
    try {
        $packages = @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like '*AINow*' -or $_.Name -like '*LenovoAI*' })
        foreach ($pkg in $packages) {
            try {
                Write-Log "Removing AppX package $($pkg.PackageFullName) for all users."
                Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
            } catch {
                Write-Log "Remove-AppxPackage failed for $($pkg.PackageFullName): $($_.Exception.Message)"
            }
        }
    } catch {
        Write-Log "Error enumerating AppX packages: $($_.Exception.Message)"
    }

    try {
        $provisioned = @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
            Where-Object { $_.PackageName -like '*AINow*' -or $_.DisplayName -like '*Lenovo*AI*' })
        foreach ($pkg in $provisioned) {
            try {
                Write-Log "Removing provisioned AppX package $($pkg.PackageName)."
                Remove-AppxProvisionedPackage -Online -PackageName $pkg.PackageName -ErrorAction Stop | Out-Null
            } catch {
                Write-Log "Remove-AppxProvisionedPackage failed for $($pkg.PackageName): $($_.Exception.Message)"
            }
        }
    } catch {
        # Some PowerShell hosts lack the DISM module; this is best-effort.
    }
}

function Remove-LenovoAINowAppxRepositoryStubs {
    # Remove orphaned AppX repository entries left behind by
    # Remove-AppxPackage. Microsoft's AppX uninstall doesn't reliably
    # clean these, so Get-AppxPackage returns nothing while a per-user
    # registry stub still references C:\Program Files\Lenovo\Lenovo AI Now.
    # Functionally harmless but a real residual; can confuse reinstalls.
    Write-Log 'Scrubbing orphaned AppX repository entries.'

    foreach ($userProfile in Get-UserProfileDirectories) {
        $userSid = Resolve-UserProfileSid -LocalPath $userProfile.FullName -ProfileName $userProfile.Name
        if (-not $userSid) { continue }
        $repoPath = "Registry::HKEY_USERS\$userSid\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages"
        if (-not (Test-Path -LiteralPath $repoPath)) { continue }
        foreach ($entry in Get-ChildItem -LiteralPath $repoPath -ErrorAction SilentlyContinue) {
            if ($entry.PSChildName -like '*AINow*' -or $entry.PSChildName -like '*LenovoAI*') {
                try {
                    Write-Log "Removing orphaned per-user AppX repository entry: $($entry.PSChildName) (user: $($userProfile.Name))"
                    Remove-Item -LiteralPath $entry.PSPath -Recurse -Force -ErrorAction Stop
                } catch {
                    Write-Log "Failed to remove $($entry.PSPath): $($_.Exception.Message)"
                }
            }
        }
    }

    foreach ($root in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications'
    )) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($entry in Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue) {
            if ($entry.PSChildName -like '*AINow*' -or $entry.PSChildName -like '*LenovoAI*') {
                try {
                    Write-Log "Removing orphaned HKLM AppX entry: $($entry.PSPath)"
                    Remove-Item -LiteralPath $entry.PSPath -Recurse -Force -ErrorAction Stop
                } catch {
                    Write-Log "Failed to remove $($entry.PSPath): $($_.Exception.Message)"
                }
            }
        }
    }
}

function Remove-ScheduledTasks {
    try {
        $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            $_.TaskName -match '(?i)lenovo.*ai.*now' -or
            $_.TaskName -match '(?i)lenovoai'
        })

        foreach ($task in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
            try {
                foreach ($action in @($task.Actions)) {
                    if ($action.PSObject.Properties['Execute'] -and
                        $action.Execute -and ($action.Execute -match '(?i)lenovo.*ai.*now')) {
                        $tasks += $task
                        break
                    }
                }
            } catch { continue }
        }

        $tasks = $tasks | Select-Object -Unique
        foreach ($task in $tasks) {
            try {
                Write-Log "Removing scheduled task: $($task.TaskName)"
                Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction Stop
            } catch {
                Write-Log "Failed to remove scheduled task $($task.TaskName): $($_.Exception.Message)"
            }
        }
    } catch {
        Write-Log "Error enumerating scheduled tasks: $($_.Exception.Message)"
    }
}

function Test-IsLenovoAIDllPath {
    # Returns $true if the given DLL path is one of the known Lenovo AI
    # filenames AND lives under a Lenovo AI* product directory.
    #
    # The path anchor is `\Lenovo\Lenovo AI` rather than just `\Lenovo\`
    # so we don't match DLLs from other Lenovo products (Vantage, Now,
    # Commercial Vantage, etc.) that may ship a generically-named
    # OverlayIcon.dll. Still matches future variants like
    # "Lenovo AI Now Plus", "Lenovo AI Solution", etc.
    param([string]$DllPath)
    if (-not $DllPath) { return $false }
    $leaf = [IO.Path]::GetFileName($DllPath)
    if (-not ($lenovoAIDllFileNames -contains $leaf)) { return $false }
    if ($DllPath -notmatch '(?i)\\Lenovo\\Lenovo AI') { return $false }
    return $true
}

function Get-LenovoAIClsidsFromHive {
    # Enumerate one CLSID hive and return GUIDs whose InprocServer32
    # default value resolves to a Lenovo AI DLL under a Lenovo AI*
    # product directory.
    #
    # Uses the .NET Microsoft.Win32.Registry API rather than Get-ChildItem
    # because the cmdlet path adds ~40s per 7k-key hive of PS provider
    # overhead, while the .NET path completes in ~200ms on the same data.
    #
    # $ClsidRoot is a relative HKLM path (e.g. 'SOFTWARE\Classes\CLSID'),
    # not a PS provider path.
    param([Parameter(Mandatory)][string]$ClsidRoot)

    $found = New-Object System.Collections.Generic.List[string]
    $root = $null
    try {
        $root = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($ClsidRoot, $false)
    } catch {
        Write-Log "Failed to open registry $ClsidRoot : $($_.Exception.Message)" "DEBUG"
        return $found
    }
    if ($null -eq $root) { return $found }

    try {
        foreach ($name in $root.GetSubKeyNames()) {
            $sub = $null
            try {
                $sub = $root.OpenSubKey("$name\InprocServer32", $false)
                if ($null -ne $sub) {
                    $dll = $sub.GetValue($null)
                    if ($dll -and (Test-IsLenovoAIDllPath -DllPath $dll)) {
                        $found.Add($name) | Out-Null
                    }
                }
            } catch {
                # individual subkey failures ignored
            } finally {
                if ($null -ne $sub) { $sub.Close() }
            }
        }
    } finally {
        $root.Close()
    }
    return $found
}

function Unregister-LenovoAIShellExtensions {
    Write-Log 'Unregistering Lenovo AI Now shell extensions.'

    # Build the union of: hardcoded known CLSIDs + filename-discovered
    # CLSIDs from both 64-bit and 32-bit hives. Discovery is via the .NET
    # registry API (~200ms per hive) and anchored by Test-IsLenovoAIDllPath
    # to a Lenovo AI* product directory, so it can't pick up DLLs from
    # other Lenovo products or unrelated vendors.
    $allClsids = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($g in $knownLenovoAIClsids) {
        [void]$allClsids.Add($g)
    }

    foreach ($hive in @('SOFTWARE\Classes\CLSID',
                        'SOFTWARE\Classes\Wow6432Node\CLSID')) {
        foreach ($g in Get-LenovoAIClsidsFromHive -ClsidRoot $hive) {
            if ($allClsids.Add($g)) {
                Write-Log "Discovered additional Lenovo AI CLSID: $g (hive: $hive)"
            }
        }
    }

    # 1) Remove ShellIconOverlayIdentifiers subkeys that point to a Lenovo
    #    CLSID. Subkey names may have leading whitespace (Lenovo prefixes
    #    with spaces so its overlay sorts before the 15-slot limit).
    $overlayRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers'
    )
    foreach ($root in $overlayRoots) {
        if (-not (Test-Path -Path $root)) { continue }
        foreach ($entry in Get-ChildItem -Path $root -ErrorAction SilentlyContinue) {
            try {
                $clsidValue = $null
                try {
                    $clsidValue = Get-ItemPropertyValue -Path $entry.PSPath -Name '(default)' -ErrorAction Stop
                } catch { }
                $nameLooksLenovo = ($entry.PSChildName -match '(?i)lenovo' -or $entry.PSChildName -match '(?i)ainow')
                if (($clsidValue -and $allClsids.Contains($clsidValue)) -or $nameLooksLenovo) {
                    Write-Log "Removing ShellIconOverlayIdentifiers entry: $($entry.PSChildName) (CLSID $clsidValue)"
                    Remove-Item -Path $entry.PSPath -Recurse -Force -ErrorAction Stop
                }
            } catch {
                Write-Log "Failed to inspect overlay identifier $($entry.PSChildName): $($_.Exception.Message)"
            }
        }
    }

    # 2) Remove value names matching Lenovo CLSIDs from the Approved list.
    foreach ($approvedKey in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved',
                                'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved')) {
        if (-not (Test-Path -Path $approvedKey)) { continue }
        try {
            $approved = Get-Item -Path $approvedKey -ErrorAction Stop
            foreach ($valueName in $approved.GetValueNames()) {
                if ($allClsids.Contains($valueName)) {
                    try {
                        Write-Log "Removing Approved shell extension value: $valueName"
                        Remove-ItemProperty -Path $approvedKey -Name $valueName -ErrorAction Stop
                    } catch {
                        Write-Log "Failed to remove Approved value $valueName : $($_.Exception.Message)"
                    }
                }
            }
        } catch {
            Write-Log "Failed to enumerate Approved key $approvedKey : $($_.Exception.Message)"
        }
    }

    # 3) Remove shellex ContextMenuHandlers / DragDropHandlers under each
    #    file-type root. Hardcoded list covers the known surface; we also
    #    sweep dynamically for any subkey whose value matches a Lenovo CLSID.
    #
    # CRITICAL: many of these paths include the literal `*` file-type root
    # (the registration for "all files"). PowerShell's -Path parameter
    # treats * as a wildcard and would expand it across hundreds of
    # HKCR subkeys, taking minutes. Use -LiteralPath throughout.
    foreach ($key in $knownLenovoAIShellexKeys) {
        if (Test-Path -LiteralPath $key) {
            try {
                Write-Log "Removing shellex handler $key"
                Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction Stop
            } catch {
                Write-Log "Failed to remove $key : $($_.Exception.Message)"
            }
        }
    }

    foreach ($fileType in @('*', 'AllFilesystemObjects', 'Directory', 'Drive', 'Folder', 'lnkfile')) {
        foreach ($handlerType in @('ContextMenuHandlers', 'DragDropHandlers', 'PropertySheetHandlers')) {
            $handlerRoot = "HKLM:\SOFTWARE\Classes\$fileType\shellex\$handlerType"
            if (-not (Test-Path -LiteralPath $handlerRoot)) { continue }
            foreach ($entry in Get-ChildItem -LiteralPath $handlerRoot -ErrorAction SilentlyContinue) {
                try {
                    $clsidValue = $null
                    try {
                        $clsidValue = Get-ItemPropertyValue -LiteralPath $entry.PSPath -Name '(default)' -ErrorAction Stop
                    } catch { }
                    if ($clsidValue -and $allClsids.Contains($clsidValue)) {
                        Write-Log "Removing shellex handler $($entry.PSPath) -> $clsidValue"
                        Remove-Item -LiteralPath $entry.PSPath -Recurse -Force -ErrorAction Stop
                    }
                } catch {
                    Write-Log "Failed to inspect shellex entry $($entry.PSChildName): $($_.Exception.Message)"
                }
            }
        }
    }

    # 4) Remove the CLSID subtrees themselves (both hives), plus AppID,
    #    TypeLib, ProgID satellites.
    foreach ($clsid in $allClsids) {
        foreach ($hive in @('HKLM:\SOFTWARE\Classes\CLSID',
                            'HKLM:\SOFTWARE\Classes\Wow6432Node\CLSID')) {
            $path = Join-Path $hive $clsid
            if (Test-Path -Path $path) {
                try {
                    Write-Log "Removing CLSID subtree $path"
                    Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                } catch {
                    Write-Log "Failed to remove $path : $($_.Exception.Message)"
                }
            }
        }
    }

    foreach ($satellite in $knownLenovoAISatelliteKeys) {
        if (Test-Path -Path $satellite) {
            try {
                Write-Log "Removing satellite COM key $satellite"
                Remove-Item -Path $satellite -Recurse -Force -ErrorAction Stop
            } catch {
                Write-Log "Failed to remove $satellite : $($_.Exception.Message)"
            }
        }
    }
}

function Invoke-LenovoAiNowRemediation {
    Write-Log 'Starting Lenovo AI Now remediation.'

    $entries = @(Get-LenovoAiNowEntries)
    $installPaths = @()
    if ($entries) {
        foreach ($e in $entries) {
            if ($e.PSObject.Properties['InstallLocation'] -and $e.InstallLocation) {
                $installPaths += $e.InstallLocation
            }
        }
    }
    $installPaths += $defaultInstallPaths
    $installPaths = @($installPaths | Where-Object { $_ } | Select-Object -Unique)

    foreach ($path in $installPaths) {
        Write-Log "Detected potential install path: $path"
    }

    $pathExists = $false
    foreach ($path in $installPaths) {
        if (Test-Path -Path $path) { $pathExists = $true; break }
    }

    $appxPresent = $false
    try {
        $appxPresent = $null -ne (Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like '*AINow*' -or $_.Name -like '*LenovoAI*' } |
            Select-Object -First 1)
    } catch { }

    if (-not $pathExists -and -not $entries -and -not $appxPresent) {
        Write-Log "Lenovo AI Now is already absent from the system."
        # Belt-and-braces: still scrub user-profile leftovers, straggling
        # shortcuts, and any orphaned AppX repository stubs.
        Remove-UserData
        Remove-StartMenuShortcuts
        Remove-LenovoAINowAppxRepositoryStubs
        Clear-PhaseACompleteSentinel
        return 0
    }

    if ($entries) { Write-Log 'Registry entries detected for Lenovo AI Now.' }

    # Stop processes (path + executable name) and services across the install
    # paths. Then remove the MSIX (which also terminates any of its own
    # processes including AINow.Service.exe under WindowsApps).
    Stop-ServicesUnderPaths -Paths $installPaths
    Stop-ProcessesUnderPaths -Paths $installPaths -ExecutableNames $processExecutables
    Stop-ProcessesUnderPaths -Paths @() -ExecutableNames $processExecutables

    Remove-LenovoAIServices
    Remove-LenovoAINowAppxPackages
    Remove-LenovoAINowAppxRepositoryStubs

    Unregister-LenovoAIShellExtensions
    Remove-UserData
    Remove-StartMenuShortcuts
    Remove-ScheduledTasks

    $registryPaths = @()
    if ($entries) { $registryPaths += $entries | ForEach-Object { $_.RegistryPath } }
    $registryPaths += @(
        'HKLM:\SOFTWARE\Lenovo\AI Now',
        'HKLM:\SOFTWARE\Lenovo\Lenovo AI Now',
        'HKLM:\SOFTWARE\WOW6432Node\Lenovo\AI Now',
        'HKLM:\SOFTWARE\WOW6432Node\Lenovo\Lenovo AI Now',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Lenovo AI Now',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\LenovoAINow'
    )
    $registryPaths = $registryPaths | Where-Object { $_ } | Select-Object -Unique

    Remove-Residuals -InstallPaths $installPaths -RegistryPaths $registryPaths

    # Final stop pass -- anything that respawned during cleanup gets caught.
    Stop-ServicesUnderPaths -Paths $installPaths
    Stop-ProcessesUnderPaths -Paths $installPaths -ExecutableNames $processExecutables

    # Verify what's left.
    $remainingEntries = @(Get-LenovoAiNowEntries)
    $remainingPaths = @($installPaths | Where-Object { Test-Path -Path $_ })

    if ($remainingEntries.Count -eq 0 -and $remainingPaths.Count -eq 0) {
        Write-Log "REMEDIATION COMPLETELY SUCCESSFUL: All Lenovo AI Now components removed."
        Clear-PhaseACompleteSentinel
        return 0
    }

    foreach ($entry in $remainingEntries) {
        Write-Log "Residual registry entry still present: $($entry.RegistryPath)" "WARNING"
    }
    foreach ($p in $remainingPaths) {
        Write-Log "Residual directory still present: $p" "WARNING"
    }

    # Queue remaining files + dirs for boot-time deletion. Bottom-up order
    # so SMSS deletes children before parents.
    $allFiles = @()
    $allDirs = @()
    foreach ($p in $remainingPaths) {
        $candidates = Get-PendingDeleteCandidates -Path $p
        $allFiles += $candidates.Files
        $allDirs += $candidates.Directories
    }

    # Rename files to *.tobedeleted so detect.ps1 can exclude them from its
    # file count and not retrigger remediation between Phase A and reboot.
    $renamedFiles = @()
    foreach ($file in $allFiles) {
        $renamed = $file
        if ($file -notmatch '\.tobedeleted$') {
            $candidate = "$file.tobedeleted"
            try {
                Move-Item -Path $file -Destination $candidate -Force -ErrorAction Stop
                $renamed = $candidate
            } catch {
                # Can't rename (locked) -- queue under original name.
            }
        }
        $renamedFiles += $renamed
    }

    $queued = Add-PendingFileDeleteBatch -FilePaths $renamedFiles -DirectoryPaths $allDirs

    if ($queued -gt 0) {
        Set-PhaseACompleteSentinel
        Write-Log "REMEDIATION SUCCESSFUL: pending reboot to complete removal of $queued items."
        return 3010
    }

    # Nothing got queued (write failed) and residuals remain -- true partial.
    Write-Log "REMEDIATION PARTIALLY SUCCESSFUL: residuals remain and PFRO queue failed." "ERROR"
    return 1603
}

$exitCode = 0
$intuneExitCode = 0
try {
    $remediationResult = Invoke-LenovoAiNowRemediation
    if ($null -ne $remediationResult -and $remediationResult -is [int]) {
        $exitCode = $remediationResult
    }

    switch ($exitCode) {
        0 {
            Write-Log "Script completed successfully with exit code 0" "INFO"
            $intuneExitCode = 0
        }
        3010 {
            Write-Log "Script completed with exit code 3010 (reboot required to finish removal)" "INFO"
            $intuneExitCode = 0
        }
        1603 {
            Write-Log "Script completed with exit code 1603 (partial failure)" "WARNING"
            $intuneExitCode = 1
        }
        default {
            Write-Log "Script completed with unexpected exit code $exitCode" "ERROR"
            $intuneExitCode = 1
        }
    }
} catch {
    $exitCode = 1
    $intuneExitCode = 1
    Write-Log "REMEDIATION FAILED: Unhandled exception during remediation: $($_.Exception.Message)" "ERROR"
    if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) {
        Write-Log $_.InvocationInfo.PositionMessage "ERROR"
    }
}

if ($intuneExitCode -ne $exitCode) {
    Write-Log "Reporting Intune-compatible exit code $intuneExitCode (actual remediation result $exitCode)" "DEBUG"
}

exit $intuneExitCode
