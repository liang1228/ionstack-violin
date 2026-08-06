[CmdletBinding()]
param(
    [string]$Source = (Join-Path $PSScriptRoot 'collect-current-boot-ktext-root1.sh'),
    [string]$Output = (Join-Path $PSScriptRoot 'collect-current-boot-ktext-root1-lf.zip')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
    throw "Source script not found: $Source"
}

# Android /system/bin/sh treats CRLF as a literal carriage-return token.  Normalize
# immediately before archiving so the ZIP is safe to transfer through chat/file apps.
$text = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $Source))
$text = $text -replace "`r`n", "`n" -replace "`r", "`n"
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$stagingDir = Join-Path ([System.IO.Path]::GetTempPath()) ("ionstack-ktext-" + [guid]::NewGuid().ToString('N'))
$stagedScript = Join-Path $stagingDir 'collect-current-boot-ktext-root1.sh'

try {
    New-Item -ItemType Directory -Path $stagingDir | Out-Null
    [System.IO.File]::WriteAllText($stagedScript, $text, $utf8NoBom)
    if (Test-Path -LiteralPath $Output) { Remove-Item -LiteralPath $Output -Force }
    Compress-Archive -LiteralPath $stagedScript -DestinationPath $Output -CompressionLevel Optimal

    $bytes = [System.IO.File]::ReadAllBytes($stagedScript)
    if ([Array]::IndexOf($bytes, [byte]13) -ge 0) { throw 'LF normalization failed: staged script still contains CR bytes.' }
    $zip = Get-Item -LiteralPath $Output
    Write-Output "ZIP=$($zip.FullName)"
    Write-Output "SHA256=$((Get-FileHash -LiteralPath $Output -Algorithm SHA256).Hash)"
    Write-Output "STAGED_SCRIPT_BYTES=$($bytes.Length)"
    Write-Output 'LINE_ENDINGS=LF-only'
}
finally {
    if (Test-Path -LiteralPath $stagingDir) { Remove-Item -LiteralPath $stagingDir -Recurse -Force }
}
