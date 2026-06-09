[CmdletBinding()]
param()

# Re-launch under native 64-bit PowerShell if Intune started us in 32-bit
# (the default for Proactive Remediation scripts). Without this, registry
# reads against HKLM:\SOFTWARE are silently WOW64-redirected to
# HKLM:\SOFTWARE\Wow6432Node, which on Lenovo AI Now devices misses both
# the uninstall key and the CLSID registrations -- they all live in the
# 64-bit hive.
if ($env:PROCESSOR_ARCHITECTURE -eq 'x86' -and (Test-Path "$env:WINDIR\SysNative\WindowsPowerShell\v1.0\powershell.exe")) {
    & "$env:WINDIR\SysNative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @args
    exit $LASTEXITCODE
}

$ErrorActionPreference = "SilentlyContinue"
$fileThreshold = 5

Write-Host "=== Lenovo AI Now Detection Script ==="

# Sentinel suppression: if remediate.ps1 already queued cleanup via
# PendingFileRenameOperations, suppress retrigger until reboot completes
# so we don't loop and bloat the PFRO registry value.
$sentinelKey = 'HKLM:\SOFTWARE\LenovoAINowRemediation'
$sentinelValueName = 'PhaseAComplete'
$sentinelStaleAfterDays = 7

$suppressForReboot = $false
if (Test-Path -Path $sentinelKey) {
    try {
        $sentinelStamp = Get-ItemPropertyValue -Path $sentinelKey -Name $sentinelValueName -ErrorAction Stop
        $sentinelTime = [datetime]::Parse(
            $sentinelStamp,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AssumeUniversal)
        $ageDays = ((Get-Date).ToUniversalTime() - $sentinelTime.ToUniversalTime()).TotalDays
        if ($ageDays -le $sentinelStaleAfterDays) {
            $pfroEntries = @()
            try {
                $pfroEntries = @(Get-ItemPropertyValue `
                    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
                    -Name 'PendingFileRenameOperations' -ErrorAction Stop)
            } catch {
                $pfroEntries = @()
            }
            if ($pfroEntries | Where-Object { $_ -match '(?i)lenovo' }) {
                $suppressForReboot = $true
                Write-Host "Phase A complete (queued $sentinelStamp, $([math]::Round($ageDays,1)) days ago). Pending reboot to finish cleanup."
            } else {
                Write-Host "Sentinel present but PFRO no longer references Lenovo; treating as cleared."
            }
        } else {
            Write-Host "Sentinel is stale (>$sentinelStaleAfterDays days). Ignoring."
        }
    } catch {
        Write-Host "Sentinel value unreadable: $($_.Exception.Message)"
    }
}

if ($suppressForReboot) {
    Write-Host "Suppressing remediation trigger; cleanup is queued for next boot."
    Write-Host "Exit Code 0"
    exit 0
}

$foundRegistry = $false
$totalFiles = 0
$binaryMatches = @()
$processMatches = @()
$serviceMatches = @()
$appxMatches = @()

$targetNamePattern = '*Lenovo AI Now*'
$registryRoots = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

Write-Host "Checking registry entries..."
foreach ($root in $registryRoots) {
    if (-not (Test-Path $root)) {
        Write-Host "Registry path not found: $root"
        continue
    }

    Get-ChildItem -Path $root -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $displayName = $_.GetValue('DisplayName')
            if ($displayName -and ($displayName -like $targetNamePattern)) {
                Write-Host "Detected registry entry: $displayName"
                $foundRegistry = $true
            }
        } catch {
            # ignore entries that cannot be read
        }
    }
}

$installRoots = @(
    "C:\Program Files\Lenovo\Lenovo AI Now",
    "C:\Program Files (x86)\Lenovo\Lenovo AI Now",
    "C:\ProgramData\Lenovo\Lenovo AI Now"
)

# Actual on-disk filenames per the Lenovo AI Now 1.3 install manifest.
# "AINow" is one word; an earlier list used "Lenovo AI Now X.exe" with a
# space and matched nothing.
$candidateExecutables = @(
    'Lenovo AINow.exe',
    'Lenovo AINow Helper.exe',
    'Lenovo AINow Launcher.exe',
    'Lenovo AINow Mini.exe',
    'Lenovo AINow OOBE.exe',
    'Lenovo AINow SafetyChecker.exe',
    'Lenovo AINow Service.exe',
    'Lenovo AINow Utility.exe',
    'Lenovo AINow Uninstall.exe',
    'AINow.TostNotification.exe'
)

Write-Host "Checking installation directories..."
foreach ($root in $installRoots) {
    if (Test-Path $root) {
        # Exclude *.tobedeleted (queued by Phase A) so they don't keep
        # retriggering remediation between phases.
        $files = Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notlike '*.tobedeleted' }
        $fileCount = @($files).Count
        Write-Host "Directory found: $root - File count: $fileCount"
        $totalFiles += $fileCount

        foreach ($exe in $candidateExecutables) {
            $exePath = Join-Path $root $exe
            if (Test-Path $exePath) {
                Write-Host "Detected Lenovo AI Now binary: $exePath"
                $binaryMatches += $exePath
            }
        }
    } else {
        Write-Host "Directory not found: $root"
    }
}

Write-Host "Checking for Lenovo AI Now processes..."
$processNamesLower = $candidateExecutables |
    ForEach-Object { ([IO.Path]::GetFileNameWithoutExtension($_)).ToLowerInvariant() }
try {
    foreach ($proc in Get-Process -ErrorAction SilentlyContinue) {
        $name = $proc.Name
        if (-not $name) { continue }
        if ($processNamesLower -contains $name.ToLowerInvariant()) {
            Write-Host "Detected running process: $name (PID $($proc.Id))"
            $processMatches += $name
        }
    }
} catch {
    Write-Host "Could not enumerate processes: $($_.Exception.Message)"
}

Write-Host "Checking for Lenovo AI Now services..."
try {
    $services = Get-CimInstance Win32_Service -ErrorAction Stop
    foreach ($svc in $services) {
        $displayName = $svc.DisplayName
        $serviceName = $svc.Name
        $pathName = $svc.PathName

        $nameMatch = ($displayName -and ($displayName -like '*Lenovo AI*')) -or
                     ($serviceName -and ($serviceName -like 'LenovoAI*'))

        $pathMatch = $false
        if (-not $nameMatch -and $pathName) {
            $exePath = $null
            if ($pathName -match '^\s*"(?<p>[^\"]+)"') {
                $exePath = $matches.p
            } else {
                $exePath = ($pathName -split '\s+',2)[0]
            }

            if ($exePath) {
                foreach ($root in $installRoots) {
                    if ($exePath.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $pathMatch = $true
                        break
                    }
                }
            }
        }

        if ($nameMatch -or $pathMatch) {
            Write-Host "Detected Lenovo AI Now service: $serviceName ($displayName)"
            $serviceMatches += $serviceName
        }
    }
} catch {
    Write-Host "Could not enumerate services: $($_.Exception.Message)"
}

Write-Host "Checking for AppX/MSIX packages..."
try {
    $installed = @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like '*AINow*' -or $_.Name -like '*LenovoAI*' })
    foreach ($pkg in $installed) {
        Write-Host "Detected AppX package: $($pkg.Name) $($pkg.Version)"
        $appxMatches += $pkg.PackageFullName
    }
    try {
        $provisioned = @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
            Where-Object { $_.PackageName -like '*AINow*' -or $_.DisplayName -like '*Lenovo*AI*' })
        foreach ($pkg in $provisioned) {
            Write-Host "Detected provisioned AppX package: $($pkg.PackageName)"
            $appxMatches += $pkg.PackageName
        }
    } catch {
        # Get-AppxProvisionedPackage can throw on PS that lacks the DISM module
    }
} catch {
    Write-Host "Could not enumerate AppX packages: $($_.Exception.Message)"
}

# Orphaned AppX repository stubs. Get-AppxPackage doesn't enumerate them,
# but they live on in HKU\<sid>\...\AppModel\Repository\Packages and in
# HKLM:\...\Appx\AppxAllUserStore\* after a partial Remove-AppxPackage.
Write-Host "Checking for orphaned AppX repository stubs..."
$appxStubMatches = @()
try {
    $userKeys = Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
        Where-Object {
            $_.PSChildName -match '^S-1-\d+(-\d+)+$' -and
            $_.PSChildName -notmatch '_Classes$'
        }
    foreach ($userKey in $userKeys) {
        $repoPath = "$($userKey.PSPath)\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages"
        if (-not (Test-Path -LiteralPath $repoPath)) { continue }
        $stubs = Get-ChildItem -LiteralPath $repoPath -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -like '*AINow*' -or $_.PSChildName -like '*LenovoAI*' }
        foreach ($s in $stubs) {
            Write-Host "Detected orphaned AppX repository stub: $($s.PSChildName) (SID: $($userKey.PSChildName))"
            $appxStubMatches += $s.PSChildName
        }
    }
} catch {
    Write-Host "Could not enumerate HKU AppX repository: $($_.Exception.Message)"
}
foreach ($root in @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications'
)) {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    $stubs = Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -like '*AINow*' -or $_.PSChildName -like '*LenovoAI*' }
    foreach ($s in $stubs) {
        Write-Host "Detected HKLM AppX stub: $($s.PSChildName) (root: $root)"
        $appxStubMatches += $s.PSChildName
    }
}

Write-Host "Total Lenovo AI Now file count (excluding *.tobedeleted): $totalFiles"

$shouldRemediate = $false
if ($foundRegistry) { Write-Host "Registry traces detected."; $shouldRemediate = $true }
if ($binaryMatches.Count -gt 0) { Write-Host "Lenovo AI Now binaries detected."; $shouldRemediate = $true }
if ($processMatches.Count -gt 0) { Write-Host "Lenovo AI Now processes are running."; $shouldRemediate = $true }
if ($serviceMatches.Count -gt 0) { Write-Host "Lenovo AI Now services detected."; $shouldRemediate = $true }
if ($appxMatches.Count -gt 0) { Write-Host "Lenovo AI Now AppX packages detected."; $shouldRemediate = $true }
if ($appxStubMatches.Count -gt 0) { Write-Host "Orphaned AppX repository stubs detected."; $shouldRemediate = $true }
if ($totalFiles -gt $fileThreshold) { Write-Host "File count exceeds threshold ($fileThreshold)."; $shouldRemediate = $true }

if ($shouldRemediate) {
    Write-Host "Lenovo AI Now detected - remediation required."
    Write-Host "Exit Code 1"
    exit 1
}

if ($totalFiles -gt 0) {
    Write-Host "Residual Lenovo AI Now files detected ($totalFiles files), but below threshold."
    Write-Host "Exit Code 0"
    exit 0
}

Write-Host "No Lenovo AI Now detected."
Write-Host "Exit Code 0"
exit 0
