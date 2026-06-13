#Requires -Version 5.1
<#
  install-docker.ps1  --  Install Docker Desktop (WSL2 backend) on Windows 11.

  RE-RUNNABLE: run it; if it says "REBOOT REQUIRED", reboot, then run it again.
  It detects how far it got and continues. Must run as Administrator (it will
  offer to self-elevate via a UAC prompt).

  Usage (from an elevated PowerShell, or just double-run and accept UAC):
      powershell -ExecutionPolicy Bypass -File install-docker.ps1
      powershell -ExecutionPolicy Bypass -File install-docker.ps1 -DockerUser "sky\RosyB"
#>
[CmdletBinding()]
param(
    [string]$DockerUser = "$env:USERDOMAIN\$env:USERNAME"   # account that will USE docker
)

$ErrorActionPreference = 'Stop'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

# ---- Self-elevate (forwarding the ORIGINAL user so docker-users is correct) ----
if (-not (Test-Admin)) {
    Write-Host "Not elevated. Relaunching as Administrator -- ACCEPT the UAC prompt..." -ForegroundColor Yellow
    Start-Process powershell.exe -Verb RunAs -ArgumentList @(
        '-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"",'-DockerUser',"`"$DockerUser`""
    )
    return
}

Write-Host "==== Docker Desktop installer (elevated) ====" -ForegroundColor Cyan
Write-Host ("Docker will be enabled for user: {0}" -f $DockerUser)

function Get-FeatureState($name) {
    try { (Get-WindowsOptionalFeature -Online -FeatureName $name).State } catch { 'Unknown' }
}
$wsl = Get-FeatureState 'Microsoft-Windows-Subsystem-Linux'
$vmp = Get-FeatureState 'VirtualMachinePlatform'
Write-Host ("WSL feature            : {0}" -f $wsl)
Write-Host ("VirtualMachinePlatform : {0}" -f $vmp)

# ---- Stage 1: enable Windows features (local, no download) -> reboot ----
if (($wsl -ne 'Enabled') -or ($vmp -ne 'Enabled')) {
    Write-Host "Enabling WSL + VirtualMachinePlatform ..." -ForegroundColor Yellow
    dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart | Out-Null
    dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart | Out-Null
    Write-Host ""
    Write-Host "*** REBOOT REQUIRED ***" -ForegroundColor Red
    Write-Host "  1) Reboot the machine now."
    Write-Host "  2) After reboot, run THIS SCRIPT AGAIN (as admin). It will continue."
    return
}

# ---- Stage 2: WSL2 kernel + default version ----
Write-Host "Updating WSL kernel + setting default version 2 ..." -ForegroundColor Yellow
try { wsl.exe --update } catch { Write-Host ("  wsl --update skipped: {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow }
try { wsl.exe --set-default-version 2 } catch { Write-Host ("  set-default-version skipped: {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow }

# ---- Stage 3: install Docker Desktop if absent ----
$dockerExe = "C:\Program Files\Docker\Docker\Docker Desktop.exe"
if (Test-Path $dockerExe) {
    Write-Host ("Docker Desktop already installed: {0}" -f $dockerExe) -ForegroundColor Green
} else {
    $url = "https://desktop.docker.com/win/main/amd64/Docker Desktop Installer.exe"
    $dst = Join-Path $env:TEMP "DockerDesktopInstaller.exe"
    if (-not (Test-Path $dst)) {
        Write-Host "Downloading Docker Desktop installer (proxy may need retries)..." -ForegroundColor Yellow
        $ok = $false
        for ($i = 1; $i -le 4; $i++) {
            try {
                Invoke-WebRequest -Uri $url -OutFile $dst -UseBasicParsing
                $ok = $true; break
            } catch {
                Write-Host ("  attempt {0}/4 failed: {1}" -f $i, $_.Exception.Message) -ForegroundColor DarkYellow
                Start-Sleep -Seconds 5
            }
        }
        if (-not $ok) {
            Write-Host "Download failed. Manually download this URL in a browser:" -ForegroundColor Red
            Write-Host ("  {0}" -f $url)
            Write-Host ("save it as: {0}" -f $dst)
            Write-Host "then re-run this script."
            return
        }
    }
    Write-Host "Running silent install (wsl-2 backend)..." -ForegroundColor Yellow
    $p = Start-Process -FilePath $dst -ArgumentList 'install','--quiet','--accept-license','--backend=wsl-2' -Wait -PassThru
    Write-Host ("Installer exit code: {0}" -f $p.ExitCode)
    if ($p.ExitCode -ne 0) {
        Write-Host "Installer returned non-zero. If it asked for a reboot, reboot and re-run." -ForegroundColor DarkYellow
    }
}

# ---- Stage 4: add the using account to the docker-users group ----
try {
    $exists = $false
    try { net localgroup docker-users | Out-String | Set-Variable members; if ($members -match [Regex]::Escape($DockerUser.Split('\')[-1])) { $exists = $true } } catch {}
    if (-not $exists) {
        net localgroup docker-users "$DockerUser" /add | Out-Null
        Write-Host ("Added '{0}' to docker-users." -f $DockerUser) -ForegroundColor Green
    } else {
        Write-Host ("'{0}' already in docker-users." -f $DockerUser)
    }
} catch {
    Write-Host ("Could not edit docker-users group: {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow
    Write-Host "If 'docker' later says access denied, run:  net localgroup docker-users `"$DockerUser`" /add"
}

Write-Host ""
Write-Host "==== NEXT STEPS (do these as the normal user) ====" -ForegroundColor Cyan
Write-Host "  1) Reboot (or sign out/in) so docker-users membership takes effect."
Write-Host "  2) Launch 'Docker Desktop' from the Start Menu; wait until the whale icon is steady."
Write-Host "  3) In a NORMAL PowerShell, verify:   docker version"
Write-Host "  4) Build + push the image:"
Write-Host "       powershell -ExecutionPolicy Bypass -File `"$PSScriptRoot\build-and-push.ps1`" -Registry <registry>/<user>"
Write-Host ""
Write-Host "Done." -ForegroundColor Green
