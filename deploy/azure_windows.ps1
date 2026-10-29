<#
  One-time setup of the live demo on an Azure Windows VM with Trusted Launch (a virtual TPM 2.0): online at a
  fixed HTTPS address around the clock, with every checkpoint signed by the VM's TPM.

  Before running it, in the Azure portal:
    1. Create a VM: image "Windows Server 2022 Datacenter", Security type "Trusted launch virtual machines"
       (vTPM and Secure Boot ticked), size B2ms.
    2. Networking: allow inbound HTTP (80) and HTTPS (443) from anywhere; allow RDP (3389) only from your own IP.
    3. The VM's public IP > Configuration > DNS name label, e.g. "novexa-demo". The address becomes
       novexa-demo.<region>.cloudapp.azure.com.
    4. Copy this project folder, including your .env, to C:\novexa over Remote Desktop (no .venv needed).

  Then, in an Administrator PowerShell on the VM:
    powershell -ExecutionPolicy Bypass -File C:\novexa\deploy\azure_windows.ps1 -Domain novexa-demo.<region>.cloudapp.azure.com

  It installs uv (and Python through uv) and Caddy, installs the project, opens 80/443 in Windows Firewall, and
  registers two startup tasks run as SYSTEM: the demo on 127.0.0.1:8090, and Caddy in front of it with an
  automatic Let's Encrypt certificate. Both restart on failure and on every reboot. Logs: C:\novexa\*.log.
#>
param(
    [Parameter(Mandatory)][string]$Domain,
    [string]$AppDir = "C:\novexa",
    [string]$Tools = "C:\tools"
)
$ErrorActionPreference = "Stop"
$UvVersion, $CaddyVersion = "0.12.3", "2.8.4"

if (-not (Test-Path "$AppDir\.env")) { throw "$AppDir\.env is missing: copy your .env next to the project first" }
if (-not (Get-Tpm).TpmPresent) { throw "this VM has no TPM: recreate it with Security type 'Trusted launch' and vTPM on" }
if (-not (Select-String -Path "$AppDir\.env" -Pattern "^DEMO_ACCESS_CODE=.{12,}" -Quiet)) {
    throw ".env needs DEMO_ACCESS_CODE (12+ characters)"
}

# A pinned release archive, checked against the checksum its release publishes, then unpacked; any mismatch stops.
function Install-Verified([string]$Url, [string]$SumsUrl, [string]$Algorithm, [string]$Exe, [string]$Dir) {
    if (Test-Path "$Dir\$Exe") { return }
    New-Item -ItemType Directory -Force $Dir | Out-Null
    $name = Split-Path $Url -Leaf
    $zip, $sums = "$env:TEMP\$name", "$env:TEMP\$name.sums"
    Invoke-WebRequest $Url -OutFile $zip -UseBasicParsing
    Invoke-WebRequest $SumsUrl -OutFile $sums -UseBasicParsing
    $line = Get-Content $sums | Where-Object { $_ -match [regex]::Escape($name) -or $_ -match '^[0-9a-fA-F]+\s*$' } | Select-Object -First 1
    $expected = "$line".Trim().Split(" ", [StringSplitOptions]::RemoveEmptyEntries)[0]
    if (-not $expected -or $expected -ne (Get-FileHash $zip -Algorithm $Algorithm).Hash) {
        Remove-Item $zip -Force
        throw "$name does not match its published $Algorithm checksum: not installing it"
    }
    Expand-Archive $zip -DestinationPath $Dir -Force
    $found = Get-ChildItem $Dir -Recurse -Filter $Exe | Select-Object -First 1
    if ($found.DirectoryName -ne $Dir) { Get-ChildItem $found.DirectoryName | Move-Item -Destination $Dir -Force }
}

# uv and the Python it installs live in one machine-wide folder the SYSTEM startup task can read.
$uvRelease = "https://github.com/astral-sh/uv/releases/download/$UvVersion/uv-x86_64-pc-windows-msvc.zip"
Install-Verified $uvRelease "$uvRelease.sha256" "SHA256" "uv.exe" "$Tools\uv"
$env:UV_PYTHON_INSTALL_DIR = "$Tools\uv\python"
Push-Location $AppDir
& "$Tools\uv\uv.exe" sync --frozen
if ($LASTEXITCODE -ne 0) { throw "uv sync failed" }
Pop-Location

$caddyRelease = "https://github.com/caddyserver/caddy/releases/download/v$CaddyVersion"
Install-Verified "$caddyRelease/caddy_${CaddyVersion}_windows_amd64.zip" "$caddyRelease/caddy_${CaddyVersion}_checksums.txt" `
    "SHA512" "caddy.exe" "$Tools\caddy"
Set-Content "$Tools\caddy\Caddyfile" -Encoding ascii -Value "$Domain {`n`treverse_proxy 127.0.0.1:8090`n}"

if (-not (Get-NetFirewallRule -DisplayName "novexa web" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName "novexa web" -Direction Inbound -Protocol TCP -LocalPort 80, 443 -Action Allow | Out-Null
}

function Register-Startup([string]$Name, [string]$Command, [string]$Dir) {
    $log = "$AppDir\$Name.log"
    $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$Command >> `"$log`" 2>&1`"" -WorkingDirectory $Dir
    $settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries
    Register-ScheduledTask -TaskName $Name -Action $action -Trigger (New-ScheduledTaskTrigger -AtStartup) `
        -Settings $settings -User "SYSTEM" -RunLevel Highest -Force | Out-Null
    Start-ScheduledTask -TaskName $Name
}
Register-Startup "novexa-demo" "`"$AppDir\.venv\Scripts\python.exe`" -m uvicorn --factory purpleteam.live_demo:app --host 127.0.0.1 --port 8090" $AppDir
Register-Startup "novexa-https" "`"$Tools\caddy\caddy.exe`" run --config `"$Tools\caddy\Caddyfile`"" "$Tools\caddy"

Write-Host "Waiting for the demo to start..."
foreach ($attempt in 1..60) {
    try { Invoke-WebRequest "http://127.0.0.1:8090/login" -UseBasicParsing -TimeoutSec 5 | Out-Null; break }
    catch { if ($attempt -eq 60) { throw "the demo did not start: see $AppDir\novexa-demo.log" }; Start-Sleep 5 }
}
Write-Host "Live at https://$Domain  (the certificate can take a minute on first start; sign in with DEMO_ACCESS_CODE)"
Write-Host "Check the TPM: run one Full run, then Audit ledger should show 'TPM 2.0 signature verified'."
