# Diagnostic: measure how long the CLSID hive walk takes on this device.
# Compares the old PowerShell cmdlet approach against direct .NET registry
# API calls. If the cmdlet walk is multiple minutes here, we know that was
# the hang in Unregister-LenovoAIShellExtensions on this machine.
#
# Read-only. Does not modify the registry.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

Write-Host "=== CLSID walk diagnostic ===" -ForegroundColor Cyan
Write-Host "Host: $env:COMPUTERNAME    PowerShell: $($PSVersionTable.PSVersion)"
Write-Host ""

# --- 1. Count CLSIDs ---
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$total = (Get-ChildItem 'HKLM:\SOFTWARE\Classes\CLSID' -ErrorAction SilentlyContinue | Measure-Object).Count
$sw.Stop()
Write-Host ("Get-ChildItem on HKLM:\SOFTWARE\Classes\CLSID  ->  {0} subkeys in {1:N2}s" -f $total, $sw.Elapsed.TotalSeconds)

# --- 2. Time the per-key inspection that the old function did, on a 200-key sample ---
$sample = 200
$sw.Restart()
$matchCount = 0
foreach ($clsid in Get-ChildItem 'HKLM:\SOFTWARE\Classes\CLSID' -ErrorAction SilentlyContinue | Select-Object -First $sample) {
    try {
        $serverPath = Join-Path $clsid.PSPath 'InprocServer32'
        if (-not (Test-Path -Path $serverPath)) { continue }
        try {
            $dll = Get-ItemPropertyValue -Path $serverPath -Name '(default)' -ErrorAction Stop
            if ($dll -and ($dll -like '*Lenovo*AI*Now*')) { $matchCount++ }
        } catch { continue }
    } catch { }
}
$sw.Stop()
$cmdletMsPerKey = $sw.Elapsed.TotalMilliseconds / $sample
$cmdletExtrapMin = ($cmdletMsPerKey * $total) / 60000.0
Write-Host ("Cmdlet path:  {0} sample keys in {1:N2}s  ->  {2:N1} ms/key  ->  extrapolated full walk {3:N1} min" -f $sample, $sw.Elapsed.TotalSeconds, $cmdletMsPerKey, $cmdletExtrapMin)

# --- 3. Same scan via direct .NET RegistryKey API (no PS provider overhead) ---
$sw.Restart()
$dotnetMatches = New-Object System.Collections.Generic.List[string]
$root = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Classes\CLSID', $false)
try {
    foreach ($name in $root.GetSubKeyNames()) {
        try {
            $sub = $root.OpenSubKey("$name\InprocServer32", $false)
            if ($null -ne $sub) {
                try {
                    $dll = $sub.GetValue($null)
                    if ($dll -and ($dll -like '*Lenovo*AI*Now*')) { $dotnetMatches.Add($name) | Out-Null }
                } finally { $sub.Close() }
            }
        } catch { }
    }
} finally { $root.Close() }
$sw.Stop()
Write-Host ("DotNet path:  full walk of {0} keys in {1:N2}s  ({2} matches)" -f $total, $sw.Elapsed.TotalSeconds, $dotnetMatches.Count)
foreach ($m in $dotnetMatches) { Write-Host "    matched CLSID: $m" }

Write-Host ""
Write-Host "Verdict:" -ForegroundColor Cyan
if ($cmdletExtrapMin -gt 5) {
    Write-Host "  Cmdlet walk would take >5 min on this device. Hardcoded-CLSIDs-only path is the right fix." -ForegroundColor Yellow
} else {
    Write-Host "  Cmdlet walk would finish in $([math]::Round($cmdletExtrapMin,1)) min on this device. If the script still hung, the bottleneck is elsewhere." -ForegroundColor Yellow
}
