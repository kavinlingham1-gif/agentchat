# Installs or updates Agentchat under %USERPROFILE%\.agentchat from this unpacked package, then joins with the invite and flags passed in.
# The pasted line verifies the package's SHA-256 before this runs; this script pins Node the same way, then hands over to the package's own install step.
# Keep this file ASCII and free of a param() block: Windows PowerShell 5.1 reads it as ANSI, and every argument goes straight to agentchat.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$NodeVersion = '24.22.0'
$NodeSha256 = @{
  'x64' = 'f9683a19877e12a9b167305c8db71040d812876359de21f0d2e97c3f321f80c3'
  'arm64' = '3a5c209a5bc59e65b3bc0fa13ed5e166a26bd3d55332847f498b76b037408d61'
}

# Reads the raw value so entries like %USERPROFILE%\AppData\Local\Microsoft\WindowsApps stay unexpanded, and writes it back as REG_EXPAND_SZ.
function Add-AgentchatPath([string]$Dir, [string]$Key = 'HKCU:\Environment') {
  if (-not (Test-Path $Key)) { New-Item -Path $Key -Force | Out-Null }
  $raw = (Get-Item -Path $Key).GetValue('Path', $null, 'DoNotExpandEnvironmentNames')
  $entries = @()
  if ($raw) { $entries = @($raw -split ';' | Where-Object { $_ -ne '' }) }
  foreach ($entry in $entries) { if ($entry.TrimEnd('\') -ieq $Dir.TrimEnd('\')) { return $false } }
  New-ItemProperty -Path $Key -Name 'Path' -Value (($entries + $Dir) -join ';') -PropertyType ExpandString -Force | Out-Null
  return $true
}

function Move-Retry([string]$From, [string]$To) {
  for ($i = 0; ; $i++) {
    try { Move-Item -LiteralPath $From -Destination $To; return } catch {
      if ($i -ge 40) { throw }
      Start-Sleep -Milliseconds 250
    }
  }
}

if ($MyInvocation.InvocationName -eq '.') { return }

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$tar = Join-Path $env:SystemRoot 'System32\tar.exe'
if (-not (Test-Path $tar)) { throw 'Agentchat needs Windows 10 (version 1803) or newer, which includes tar.exe.' }
$arch = 'x64'
if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') { $arch = 'arm64' }
$root = Join-Path $env:USERPROFILE '.agentchat'
$nodeName = "node-v$NodeVersion-win-$arch"
$nodeDir = Join-Path $root "node\v$NodeVersion-win-$arch"
$node = Join-Path $nodeDir 'node.exe'

if (-not (Test-Path $node)) {
  Write-Host "Downloading Node $NodeVersion for this PC..."
  $tmp = Join-Path $root "node\.tmp-$PID"
  if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
  New-Item -ItemType Directory -Force -Path $tmp | Out-Null
  $zip = Join-Path $tmp "$nodeName.zip"
  Invoke-WebRequest -Uri "https://nodejs.org/dist/v$NodeVersion/$nodeName.zip" -OutFile $zip -UseBasicParsing
  if ((Get-FileHash -Path $zip -Algorithm SHA256).Hash -ne $NodeSha256[$arch]) { throw "The Node download didn't match its pinned SHA-256, so nothing was installed. Paste the same line again." }
  & $tar -xf $zip -C $tmp "$nodeName/node.exe" "$nodeName/LICENSE"
  if ($LASTEXITCODE -ne 0) { throw "Couldn't unpack Node." }
  & (Join-Path $tmp "$nodeName\node.exe") -v | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "This PC can't run Node $NodeVersion." }
  if (Test-Path $nodeDir) { Remove-Item -Recurse -Force $nodeDir }
  Move-Retry (Join-Path $tmp $nodeName) $nodeDir
  Remove-Item -Recurse -Force $tmp
}

# An automatic update leaves PATH alone, so an entry someone removed stays removed.
if (($args -notcontains '--update') -and (Add-AgentchatPath (Join-Path $root 'bin'))) {
  # Setting and clearing a throwaway variable makes Windows tell running programs that the user PATH changed.
  [Environment]::SetEnvironmentVariable('AGENTCHAT_PATH_REFRESH', '1', 'User')
  [Environment]::SetEnvironmentVariable('AGENTCHAT_PATH_REFRESH', $null, 'User')
}

& $node (Join-Path $PSScriptRoot 'bin\agentchat.js') install @args
exit $LASTEXITCODE
