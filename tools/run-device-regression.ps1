[CmdletBinding()]
param(
  [string]$ConfigPath = "E:\workspace\projects\xiaomi-root\tools\device-regression.example.json",
  [int]$MaxRoundsOverride = 0,
  [string]$LaunchUrlOverride = "",
  [switch]$NoReboot,
  [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-OptionalPropertyValue {
  param(
    [Parameter(Mandatory = $false)][object]$Object,
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $false)][object]$Default = $null
  )

  if ($null -eq $Object) {
    return $Default
  }
  $prop = $Object.PSObject.Properties[$Name]
  if ($null -eq $prop) {
    return $Default
  }
  if ($null -eq $prop.Value) {
    return $Default
  }
  return $prop.Value
}

function Ensure-Directory {
  param([Parameter(Mandatory = $true)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
}

function New-SafeName {
  param([Parameter(Mandatory = $true)][string]$Value)
  $safe = [regex]::Replace($Value, '[^A-Za-z0-9._-]+', '_').Trim('_')
  if ([string]::IsNullOrWhiteSpace($safe)) {
    return "artifact"
  }
  return $safe
}

function Read-TextFileSafe {
  param([Parameter(Mandatory = $true)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    return ""
  }
  try {
    return [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
  } catch {
    return (Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue)
  }
}

function Get-FileLineCount {
  param([Parameter(Mandatory = $true)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    return 0
  }
  return (Get-Content -LiteralPath $Path | Measure-Object -Line).Lines
}

function Get-ServerLogSlice {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][int]$StartLine
  )
  if (-not (Test-Path -LiteralPath $Path)) {
    return ""
  }
  $lines = Get-Content -LiteralPath $Path
  if ($StartLine -ge $lines.Count) {
    return ""
  }
  return (($lines | Select-Object -Skip $StartLine) -join [Environment]::NewLine)
}

function Snapshot-LocalArtifacts {
  param([Parameter(Mandatory = $true)][object[]]$Artifacts)
  $snapshot = @{}
  foreach ($artifact in $Artifacts) {
    $path = [string](Get-OptionalPropertyValue -Object $artifact -Name "path" -Default "")
    if ([string]::IsNullOrWhiteSpace($path)) {
      continue
    }
    if (Test-Path -LiteralPath $path) {
      $snapshot[$path] = (Get-Item -LiteralPath $path).LastWriteTimeUtc
    } else {
      $snapshot[$path] = $null
    }
  }
  return $snapshot
}

function Capture-LocalArtifacts {
  param(
    [Parameter(Mandatory = $true)][object[]]$Artifacts,
    [Parameter(Mandatory = $true)][hashtable]$Snapshot,
    [Parameter(Mandatory = $true)][string]$DestinationDir
  )
  Ensure-Directory -Path $DestinationDir
  $captured = [System.Collections.Generic.List[object]]::new()
  foreach ($artifact in $Artifacts) {
    $path = [string](Get-OptionalPropertyValue -Object $artifact -Name "path" -Default "")
    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path)) {
      continue
    }
    $name = [string](Get-OptionalPropertyValue -Object $artifact -Name "name" -Default ([System.IO.Path]::GetFileNameWithoutExtension($path)))
    $current = Get-Item -LiteralPath $path
    $previous = $Snapshot[$path]
    $changed = $false
    if ($null -eq $previous) {
      $changed = $true
    } elseif ($current.LastWriteTimeUtc -gt $previous) {
      $changed = $true
    }
    if (-not $changed) {
      continue
    }
    $safeName = New-SafeName -Value $name
    $dest = Join-Path $DestinationDir ("local-{0}{1}" -f $safeName, $current.Extension)
    Copy-Item -LiteralPath $path -Destination $dest -Force
    $captured.Add([pscustomobject]@{
        Name = $name
        Path = $path
        CopyPath = $dest
        Text = Read-TextFileSafe -Path $dest
      })
  }
  return $captured
}

function Resolve-LaunchUrl {
  param(
    [Parameter(Mandatory = $true)][string]$Url,
    [Parameter(Mandatory = $true)][int]$Round,
    [Parameter(Mandatory = $true)][bool]$AppendRoundToken
  )
  if (-not $AppendRoundToken) {
    return $Url
  }
  $parts = $Url -split '#', 2
  $base = $parts[0]
  $hash = if ($parts.Count -gt 1) { "#" + $parts[1] } else { "" }
  $sep = if ($base.Contains('?')) { '&' } else { '?' }
  $token = "rr={0:D2}&ts={1}" -f $Round, ([DateTimeOffset]::Now.ToUnixTimeSeconds())
  return "$base$sep$token$hash"
}

function Quote-RemoteShellArg {
  param([Parameter(Mandatory = $true)][string]$Value)
  return "'" + ($Value -replace "'", "'\''") + "'"
}

function Invoke-AdbCapture {
  param(
    [Parameter(Mandatory = $true)][string]$AdbPath,
    [Parameter(Mandatory = $true)][string[]]$Args,
    [switch]$IgnoreExitCode
  )
  $output = & $AdbPath @Args 2>&1 | Out-String
  $exitCode = $LASTEXITCODE
  if (-not $IgnoreExitCode -and $exitCode -ne 0) {
    throw "adb $($Args -join ' ') failed with exit code $exitCode`n$output"
  }
  return [pscustomobject]@{
    ExitCode = $exitCode
    Output = $output.Trim()
  }
}

function Get-AdbText {
  param(
    [Parameter(Mandatory = $true)][string]$AdbPath,
    [Parameter(Mandatory = $true)][string[]]$Args
  )
  $result = Invoke-AdbCapture -AdbPath $AdbPath -Args $Args -IgnoreExitCode
  if ($result.ExitCode -ne 0) {
    return ""
  }
  return $result.Output
}

function Test-DeviceOnline {
  param([Parameter(Mandatory = $true)][string]$AdbPath)
  $state = Get-AdbText -AdbPath $AdbPath -Args @("get-state")
  return ($state -match '\bdevice\b')
}

function Get-BootId {
  param([Parameter(Mandatory = $true)][string]$AdbPath)
  return (Get-AdbText -AdbPath $AdbPath -Args @("shell", "cat", "/proc/sys/kernel/random/boot_id")).Trim()
}

function Get-BootCompleted {
  param([Parameter(Mandatory = $true)][string]$AdbPath)
  return (Get-AdbText -AdbPath $AdbPath -Args @("shell", "getprop", "sys.boot_completed")).Trim()
}

function Wait-ForDeviceOnline {
  param(
    [Parameter(Mandatory = $true)][string]$AdbPath,
    [Parameter(Mandatory = $true)][int]$TimeoutSec,
    [Parameter(Mandatory = $true)][int]$PollIntervalMs,
    [Parameter(Mandatory = $true)][string]$TimelinePath
  )
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  while ((Get-Date) -lt $deadline) {
    if (Test-DeviceOnline -AdbPath $AdbPath) {
      ("[{0}] DEVICE_ONLINE" -f (Get-Date -Format "HH:mm:ss.fff")) | Add-Content -LiteralPath $TimelinePath -Encoding UTF8
      return $true
    }
    ("[{0}] WAIT_DEVICE_ONLINE" -f (Get-Date -Format "HH:mm:ss.fff")) | Add-Content -LiteralPath $TimelinePath -Encoding UTF8
    Start-Sleep -Milliseconds $PollIntervalMs
  }
  return $false
}

function Wait-ForBootCompleted {
  param(
    [Parameter(Mandatory = $true)][string]$AdbPath,
    [Parameter(Mandatory = $true)][int]$TimeoutSec,
    [Parameter(Mandatory = $true)][int]$PollIntervalMs,
    [Parameter(Mandatory = $true)][string]$TimelinePath
  )
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  while ((Get-Date) -lt $deadline) {
    if (Test-DeviceOnline -AdbPath $AdbPath) {
      $bootCompleted = Get-BootCompleted -AdbPath $AdbPath
      $bootId = Get-BootId -AdbPath $AdbPath
      ("[{0}] WAIT_BOOT_COMPLETED boot_id={1} boot_completed={2}" -f (Get-Date -Format "HH:mm:ss.fff"), $bootId, $bootCompleted) | Add-Content -LiteralPath $TimelinePath -Encoding UTF8
      if ($bootCompleted -eq "1") {
        return $true
      }
    }
    Start-Sleep -Milliseconds $PollIntervalMs
  }
  return $false
}

function Test-PatternSet {
  param(
    [Parameter(Mandatory = $true)][string]$Text,
    [Parameter(Mandatory = $true)][string[]]$Patterns,
    [Parameter(Mandatory = $true)][bool]$RequireAll
  )
  $hits = [System.Collections.Generic.List[string]]::new()
  foreach ($pattern in $Patterns) {
    if ($Text -match $pattern) {
      $hits.Add($pattern)
    }
  }
  $matched = if ($RequireAll) { $hits.Count -eq $Patterns.Count -and $Patterns.Count -gt 0 } else { $hits.Count -gt 0 }
  return [pscustomobject]@{
    Matched = $matched
    Hits = @($hits)
  }
}

function Evaluate-Stages {
  param(
    [Parameter(Mandatory = $true)][string]$Text,
    [Parameter(Mandatory = $true)][object[]]$Stages
  )
  $details = [System.Collections.Generic.List[object]]::new()
  $lastReached = ""
  foreach ($stage in $Stages) {
    $name = [string](Get-OptionalPropertyValue -Object $stage -Name "name" -Default "stage")
    $patterns = @((Get-OptionalPropertyValue -Object $stage -Name "patterns" -Default @()))
    $requireAll = [bool](Get-OptionalPropertyValue -Object $stage -Name "requireAll" -Default $true)
    $result = Test-PatternSet -Text $Text -Patterns $patterns -RequireAll $requireAll
    if ($result.Matched) {
      $lastReached = $name
    }
    $details.Add([pscustomobject]@{
        Name = $name
        Matched = $result.Matched
        Patterns = $patterns
        Hits = $result.Hits
      })
  }
  return [pscustomobject]@{
    LastReached = $lastReached
    Details = @($details)
  }
}

function Evaluate-Failures {
  param(
    [Parameter(Mandatory = $true)][string]$Text,
    [Parameter(Mandatory = $true)][object[]]$FailureRules
  )
  foreach ($rule in $FailureRules) {
    $name = [string](Get-OptionalPropertyValue -Object $rule -Name "name" -Default "failure")
    $patterns = @((Get-OptionalPropertyValue -Object $rule -Name "patterns" -Default @()))
    $requireAll = [bool](Get-OptionalPropertyValue -Object $rule -Name "requireAll" -Default $false)
    $result = Test-PatternSet -Text $Text -Patterns $patterns -RequireAll $requireAll
    if ($result.Matched) {
      return [pscustomobject]@{
        Name = $name
        Hits = $result.Hits
      }
    }
  }
  return $null
}

function Pull-RemoteGlobs {
  param(
    [Parameter(Mandatory = $true)][string]$AdbPath,
    [Parameter(Mandatory = $true)][string[]]$Globs,
    [Parameter(Mandatory = $true)][string]$DestinationDir
  )
  Ensure-Directory -Path $DestinationDir
  $pulled = [System.Collections.Generic.List[object]]::new()
  foreach ($glob in $Globs) {
    $listing = Get-AdbText -AdbPath $AdbPath -Args @("shell", "ls -1t $glob 2>/dev/null || true")
    if ([string]::IsNullOrWhiteSpace($listing)) {
      continue
    }
    foreach ($line in ($listing -split "`r?`n")) {
      $remotePath = $line.Trim()
      if ([string]::IsNullOrWhiteSpace($remotePath) -or $remotePath.Contains('*')) {
        continue
      }
      $leaf = New-SafeName -Value ([System.IO.Path]::GetFileName($remotePath))
      $dest = Join-Path $DestinationDir $leaf
      $pull = Invoke-AdbCapture -AdbPath $AdbPath -Args @("pull", $remotePath, $dest) -IgnoreExitCode
      if ($pull.ExitCode -eq 0 -and (Test-Path -LiteralPath $dest)) {
        $pulled.Add([pscustomobject]@{
            RemotePath = $remotePath
            LocalPath = $dest
            Text = Read-TextFileSafe -Path $dest
          })
      }
    }
  }
  return $pulled
}

function Export-MarkdownSummary {
  param(
    [Parameter(Mandatory = $true)][object[]]$Rows,
    [Parameter(Mandatory = $true)][string]$Path
  )
  $lines = [System.Collections.Generic.List[string]]::new()
  $lines.Add("# Device regression summary")
  $lines.Add("")
  $lines.Add("| Round | Success | LastStage | FailureReason | BootChanged | WentOffline | RebootIssued | RoundDir |")
  $lines.Add("| --- | --- | --- | --- | --- | --- | --- | --- |")
  foreach ($row in $Rows) {
    $lines.Add("| $($row.Round) | $($row.Success) | $($row.LastStage) | $($row.FailureReason) | $($row.BootChanged) | $($row.WentOffline) | $($row.RebootIssued) | $($row.RoundDir) |")
  }
  [System.IO.File]::WriteAllLines($Path, $lines, [System.Text.Encoding]::UTF8)
}

$skillNote = "已选技能：debugging-and-error-recovery、minimal-run-and-audit（用来做设备回归编排、证据抓取、失败归因）。"
Write-Host $skillNote

if (-not (Test-Path -LiteralPath $ConfigPath)) {
  throw "配置文件不存在：$ConfigPath"
}

$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json

$launchUrl = [string](Get-OptionalPropertyValue -Object $config -Name "launchUrl" -Default "")
if (-not [string]::IsNullOrWhiteSpace($LaunchUrlOverride)) {
  $launchUrl = $LaunchUrlOverride
}
if ([string]::IsNullOrWhiteSpace($launchUrl)) {
  throw "launchUrl 不能为空。"
}

$outputRoot = [string](Get-OptionalPropertyValue -Object $config -Name "outputRoot" -Default "E:\workspace\projects\xiaomi-root\outputs\device-regression")
$packageName = [string](Get-OptionalPropertyValue -Object $config -Name "packageName" -Default "org.mozilla.firefox")
$actionName = [string](Get-OptionalPropertyValue -Object $config -Name "action" -Default "android.intent.action.VIEW")
$roundTimeoutSec = [int](Get-OptionalPropertyValue -Object $config -Name "roundTimeoutSec" -Default 90)
$pollIntervalMs = [int](Get-OptionalPropertyValue -Object $config -Name "pollIntervalMs" -Default 2000)
$recoverTimeoutSec = [int](Get-OptionalPropertyValue -Object $config -Name "recoverTimeoutSec" -Default 240)
$bootCompletedTimeoutSec = [int](Get-OptionalPropertyValue -Object $config -Name "bootCompletedTimeoutSec" -Default 240)
$appendRoundToken = [bool](Get-OptionalPropertyValue -Object $config -Name "appendRoundToken" -Default $true)
$rebootBetweenRounds = [bool](Get-OptionalPropertyValue -Object $config -Name "rebootBetweenRounds" -Default $true)
$stopOnSuccess = [bool](Get-OptionalPropertyValue -Object $config -Name "stopOnSuccess" -Default $true)
$serverLogPath = [string](Get-OptionalPropertyValue -Object $config -Name "serverLogPath" -Default "")
$maxRounds = [int](Get-OptionalPropertyValue -Object $config -Name "maxRounds" -Default 3)
if ($MaxRoundsOverride -gt 0) {
  $maxRounds = $MaxRoundsOverride
}

$adbReverseRules = @((Get-OptionalPropertyValue -Object $config -Name "adbReverse" -Default @()))
$localTextArtifacts = @((Get-OptionalPropertyValue -Object $config -Name "localTextArtifacts" -Default @()))
$remotePullGlobs = @((Get-OptionalPropertyValue -Object $config -Name "remotePullGlobs" -Default @()))
$stages = @((Get-OptionalPropertyValue -Object $config -Name "stages" -Default @()))
$successConfig = Get-OptionalPropertyValue -Object $config -Name "success" -Default ([pscustomobject]@{})
$successPatterns = @((Get-OptionalPropertyValue -Object $successConfig -Name "patterns" -Default @()))
$successRequireAll = [bool](Get-OptionalPropertyValue -Object $successConfig -Name "requireAll" -Default $false)
$failureRules = @((Get-OptionalPropertyValue -Object $config -Name "failures" -Default @()))

$adbCommand = Get-Command adb -ErrorAction Stop
$adbPath = $adbCommand.Source

Ensure-Directory -Path $outputRoot
$sessionId = "run-{0}" -f (Get-Date -Format "yyyyMMdd-HHmmss")
$sessionDir = Join-Path $outputRoot $sessionId
Ensure-Directory -Path $sessionDir

$resolved = [ordered]@{
  ConfigPath = $ConfigPath
  OutputRoot = $outputRoot
  SessionDir = $sessionDir
  LaunchUrl = $launchUrl
  MaxRounds = $maxRounds
  RoundTimeoutSec = $roundTimeoutSec
  PollIntervalMs = $pollIntervalMs
  RecoverTimeoutSec = $recoverTimeoutSec
  BootCompletedTimeoutSec = $bootCompletedTimeoutSec
  PackageName = $packageName
  Action = $actionName
  AppendRoundToken = $appendRoundToken
  RebootBetweenRounds = $rebootBetweenRounds
  StopOnSuccess = $stopOnSuccess
  ServerLogPath = $serverLogPath
}
$resolvedPath = Join-Path $sessionDir "resolved-config.json"
$resolved | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $resolvedPath -Encoding UTF8

Write-Host "会话输出目录：$sessionDir"
Write-Host "解析后的配置已写入：$resolvedPath"

if ($DryRun) {
  Write-Host "DryRun=ON，只做配置解析，不发起 ADB/浏览器/重启动作。"
  exit 0
}

if (-not (Test-DeviceOnline -AdbPath $adbPath)) {
  throw "ADB 当前没有在线设备，请先确认平板已连接。"
}

$summaryRows = [System.Collections.Generic.List[object]]::new()
$successReached = $false

for ($round = 1; $round -le $maxRounds; $round++) {
  $roundDir = Join-Path $sessionDir ("round-{0:D2}" -f $round)
  Ensure-Directory -Path $roundDir
  $timelinePath = Join-Path $roundDir "timeline.txt"
  $serverSlicePath = Join-Path $roundDir "server-log-slice.txt"
  $logcatPath = Join-Path $roundDir "logcat.txt"
  $stagePath = Join-Path $roundDir "stage-eval.json"
  $summaryPath = Join-Path $roundDir "summary.json"
  $localArtifactsDir = Join-Path $roundDir "local-artifacts"
  $remoteArtifactsDir = Join-Path $roundDir "remote-artifacts"
  Ensure-Directory -Path $localArtifactsDir
  Ensure-Directory -Path $remoteArtifactsDir

  $roundStart = Get-Date
  "round=$round" | Set-Content -LiteralPath $timelinePath -Encoding UTF8
  "start_time=$($roundStart.ToString('o'))" | Add-Content -LiteralPath $timelinePath -Encoding UTF8

  $bootBefore = Get-BootId -AdbPath $adbPath
  "boot_before=$bootBefore" | Add-Content -LiteralPath $timelinePath -Encoding UTF8

  foreach ($rule in $adbReverseRules) {
    $devicePort = [string](Get-OptionalPropertyValue -Object $rule -Name "device" -Default "")
    $hostPort = [string](Get-OptionalPropertyValue -Object $rule -Name "host" -Default "")
    if (-not [string]::IsNullOrWhiteSpace($devicePort) -and -not [string]::IsNullOrWhiteSpace($hostPort)) {
      Invoke-AdbCapture -AdbPath $adbPath -Args @("reverse", $devicePort, $hostPort) -IgnoreExitCode | Out-Null
      "adb_reverse=$devicePort->$hostPort" | Add-Content -LiteralPath $timelinePath -Encoding UTF8
    }
  }

  Invoke-AdbCapture -AdbPath $adbPath -Args @("logcat", "-c") -IgnoreExitCode | Out-Null
  "logcat_cleared=1" | Add-Content -LiteralPath $timelinePath -Encoding UTF8

  $serverStartLine = if ([string]::IsNullOrWhiteSpace($serverLogPath)) { 0 } else { Get-FileLineCount -Path $serverLogPath }
  $artifactSnapshot = Snapshot-LocalArtifacts -Artifacts $localTextArtifacts
  $resolvedLaunchUrl = Resolve-LaunchUrl -Url $launchUrl -Round $round -AppendRoundToken $appendRoundToken
  "launch_url=$resolvedLaunchUrl" | Add-Content -LiteralPath $timelinePath -Encoding UTF8

  $remoteStartCommand = "am start -W -a $actionName -d $(Quote-RemoteShellArg -Value $resolvedLaunchUrl) $packageName"
  $startResult = Invoke-AdbCapture -AdbPath $adbPath -Args @("shell", $remoteStartCommand) -IgnoreExitCode
  $startResult.Output | Set-Content -LiteralPath (Join-Path $roundDir "am-start.txt") -Encoding UTF8

  $wentOffline = $false
  $bootChanged = $false
  $successObservedEarly = $false
  $recoveredAfterRound = $true
  $roundTimedOut = $false
  $deadline = (Get-Date).AddSeconds($roundTimeoutSec)

  while ((Get-Date) -lt $deadline) {
    $ts = Get-Date -Format "HH:mm:ss.fff"
    if (Test-DeviceOnline -AdbPath $adbPath) {
      $bootNow = Get-BootId -AdbPath $adbPath
      $bootCompleted = Get-BootCompleted -AdbPath $adbPath
      ("[$ts] DEVICE_ONLINE boot_id=$bootNow boot_completed=$bootCompleted") | Add-Content -LiteralPath $timelinePath -Encoding UTF8
      if (-not [string]::IsNullOrWhiteSpace($bootBefore) -and -not [string]::IsNullOrWhiteSpace($bootNow) -and $bootNow -ne $bootBefore) {
        $bootChanged = $true
        break
      }
      $liveParts = [System.Collections.Generic.List[string]]::new()
      if (-not [string]::IsNullOrWhiteSpace($serverLogPath)) {
        $liveParts.Add((Get-ServerLogSlice -Path $serverLogPath -StartLine $serverStartLine))
      }
      foreach ($artifact in $localTextArtifacts) {
        $path = [string](Get-OptionalPropertyValue -Object $artifact -Name "path" -Default "")
        if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path)) {
          continue
        }
        $snapshotTime = $artifactSnapshot[$path]
        $current = Get-Item -LiteralPath $path
        if ($null -eq $snapshotTime -or $current.LastWriteTimeUtc -gt $snapshotTime) {
          $liveParts.Add((Read-TextFileSafe -Path $path))
        }
      }
      if ($successPatterns.Count -gt 0) {
        $liveText = ($liveParts -join [Environment]::NewLine)
        $liveEval = Test-PatternSet -Text $liveText -Patterns $successPatterns -RequireAll $successRequireAll
        if ($liveEval.Matched) {
          $successObservedEarly = $true
          ("[$ts] SUCCESS_PATTERN_EARLY hits=$($liveEval.Hits -join ';')") | Add-Content -LiteralPath $timelinePath -Encoding UTF8
          if ($stopOnSuccess) {
            break
          }
        }
      }
    } else {
      $wentOffline = $true
      ("[$ts] DEVICE_OFFLINE") | Add-Content -LiteralPath $timelinePath -Encoding UTF8
    }
    Start-Sleep -Milliseconds $pollIntervalMs
  }

  if ((Get-Date) -ge $deadline) {
    $roundTimedOut = $true
    "timeout=1" | Add-Content -LiteralPath $timelinePath -Encoding UTF8
  }

  if ($wentOffline -or $bootChanged) {
    $recoveredAfterRound = Wait-ForDeviceOnline -AdbPath $adbPath -TimeoutSec $recoverTimeoutSec -PollIntervalMs $pollIntervalMs -TimelinePath $timelinePath
    if ($recoveredAfterRound) {
      $null = Wait-ForBootCompleted -AdbPath $adbPath -TimeoutSec $bootCompletedTimeoutSec -PollIntervalMs $pollIntervalMs -TimelinePath $timelinePath
    }
  }

  $bootAfter = if (Test-DeviceOnline -AdbPath $adbPath) { Get-BootId -AdbPath $adbPath } else { "" }
  "boot_after=$bootAfter" | Add-Content -LiteralPath $timelinePath -Encoding UTF8

  $serverSlice = if ([string]::IsNullOrWhiteSpace($serverLogPath)) { "" } else { Get-ServerLogSlice -Path $serverLogPath -StartLine $serverStartLine }
  $serverSlice | Set-Content -LiteralPath $serverSlicePath -Encoding UTF8

  $logcatText = Get-AdbText -AdbPath $adbPath -Args @("logcat", "-d")
  $logcatText | Set-Content -LiteralPath $logcatPath -Encoding UTF8

  $capturedLocal = Capture-LocalArtifacts -Artifacts $localTextArtifacts -Snapshot $artifactSnapshot -DestinationDir $localArtifactsDir
  $pulledRemote = Pull-RemoteGlobs -AdbPath $adbPath -Globs $remotePullGlobs -DestinationDir $remoteArtifactsDir

  $combinedParts = [System.Collections.Generic.List[string]]::new()
  $combinedParts.Add((Read-TextFileSafe -Path $timelinePath))
  $combinedParts.Add($serverSlice)
  $combinedParts.Add($logcatText)
  if ($wentOffline) { $combinedParts.Add("DEVICE_WENT_OFFLINE") }
  if ($bootChanged) { $combinedParts.Add("BOOT_ID_CHANGED") }
  foreach ($item in $capturedLocal) { $combinedParts.Add($item.Text) }
  foreach ($item in $pulledRemote) { $combinedParts.Add($item.Text) }
  $combinedText = ($combinedParts -join [Environment]::NewLine)
  $combinedText | Set-Content -LiteralPath (Join-Path $roundDir "combined-evidence.txt") -Encoding UTF8

  $stageEval = Evaluate-Stages -Text $combinedText -Stages $stages
  $stageEval | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $stagePath -Encoding UTF8

  $successEval = if ($successPatterns.Count -gt 0) {
    Test-PatternSet -Text $combinedText -Patterns $successPatterns -RequireAll $successRequireAll
  } else {
    [pscustomobject]@{ Matched = $false; Hits = @() }
  }
  $failureEval = Evaluate-Failures -Text $combinedText -FailureRules $failureRules

  $failureReason = ""
  if ($successEval.Matched -or $successObservedEarly) {
    $successReached = $true
    $failureReason = "target_condition_met"
  } elseif ($null -ne $failureEval) {
    $failureReason = $failureEval.Name
  } elseif ($bootChanged -or $wentOffline) {
    $failureReason = "device_rebooted_before_target"
  } elseif ($roundTimedOut) {
    $failureReason = "timeout_before_target"
  } else {
    $failureReason = "target_not_observed"
  }

  $rebootIssued = $false
  if (-not $successReached -and $round -lt $maxRounds -and $rebootBetweenRounds -and -not $NoReboot) {
    if ((-not $bootChanged) -and (Test-DeviceOnline -AdbPath $adbPath)) {
      Invoke-AdbCapture -AdbPath $adbPath -Args @("reboot") -IgnoreExitCode | Out-Null
      $rebootIssued = $true
      "manual_reboot_issued=1" | Add-Content -LiteralPath $timelinePath -Encoding UTF8
      $null = Wait-ForDeviceOnline -AdbPath $adbPath -TimeoutSec $recoverTimeoutSec -PollIntervalMs $pollIntervalMs -TimelinePath $timelinePath
      $null = Wait-ForBootCompleted -AdbPath $adbPath -TimeoutSec $bootCompletedTimeoutSec -PollIntervalMs $pollIntervalMs -TimelinePath $timelinePath
    }
  }

  $roundEnd = Get-Date
  $summary = [ordered]@{
    Round = $round
    StartTime = $roundStart.ToString("o")
    EndTime = $roundEnd.ToString("o")
    DurationSec = [math]::Round(($roundEnd - $roundStart).TotalSeconds, 2)
    LaunchUrl = $resolvedLaunchUrl
    BootBefore = $bootBefore
    BootAfter = $bootAfter
    BootChanged = $bootChanged
    WentOffline = $wentOffline
    RecoveredAfterRound = $recoveredAfterRound
    Success = ($successEval.Matched -or $successObservedEarly)
    SuccessHits = @($successEval.Hits)
    LastStage = $stageEval.LastReached
    FailureReason = $failureReason
    FailureHits = if ($null -ne $failureEval) { @($failureEval.Hits) } else { @() }
    RebootIssued = $rebootIssued
    RoundDir = $roundDir
  }
  $summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
  $summaryRows.Add([pscustomobject]$summary)

  Write-Host ("[round {0}] success={1} stage={2} reason={3}" -f $round, $summary.Success, $summary.LastStage, $summary.FailureReason)

  if ($successReached) {
    break
  }
}

$csvPath = Join-Path $sessionDir "summary.csv"
$jsonPath = Join-Path $sessionDir "summary.json"
$mdPath = Join-Path $sessionDir "summary.md"
$summaryRows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
$summaryRows | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
Export-MarkdownSummary -Rows @($summaryRows) -Path $mdPath

Write-Host ""
Write-Host "完成。汇总文件："
Write-Host "  $csvPath"
Write-Host "  $jsonPath"
Write-Host "  $mdPath"
