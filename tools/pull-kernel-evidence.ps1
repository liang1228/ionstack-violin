param(
  [string]$Adb = 'C:\Users\zeooon3\AppData\Local\Android\Sdk\platform-tools\adb.exe',
  [string]$OutputRoot = 'E:\workspace\projects\xiaomi-root\analysis_outputs\device_evidence'
)
$ErrorActionPreference = 'Stop'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$out = Join-Path $OutputRoot $stamp
New-Item -ItemType Directory -Force $out | Out-Null

& $Adb push "$PSScriptRoot\collect-rooted-baseline.sh" /data/local/tmp/collect-rooted-baseline.sh
& $Adb shell su -c 'chmod 0755 /data/local/tmp/collect-rooted-baseline.sh && /data/local/tmp/collect-rooted-baseline.sh'
if ($LASTEXITCODE -ne 0) { throw 'Rooted-device collection failed' }
& $Adb pull /sdcard/Download/violin-kernel-evidence.tar.gz $out
if ($LASTEXITCODE -ne 0) { throw 'Evidence pull failed' }

$archive = Join-Path $out 'violin-kernel-evidence.tar.gz'
Get-FileHash $archive -Algorithm SHA256 | Format-List | Out-File (Join-Path $out 'archive-sha256.txt')
& tar -xzf $archive -C $out
Write-Host "Evidence saved to $out"
