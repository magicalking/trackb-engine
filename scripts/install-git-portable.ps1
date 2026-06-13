#Requires -Version 5.1
<#
  install-git-portable.ps1 -- Install Git for Windows (Portable, NO admin/UAC).

  Downloads the latest PortableGit 64-bit self-extractor, unpacks it to
  %LOCALAPPDATA%\Programs\PortableGit, adds it to the USER PATH (HKCU, no admin),
  and verifies. Re-runnable: skips download/extract if already present.
#>
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$dest = Join-Path $env:LOCALAPPDATA 'Programs\PortableGit'
$gitExe = Join-Path $dest 'cmd\git.exe'

if (Test-Path $gitExe) {
    Write-Host "PortableGit already present: $gitExe" -ForegroundColor Green
} else {
    # ---- Resolve the latest PortableGit 64-bit asset URL (fallback if API fails) ----
    $url = $null
    try {
        $rel = Invoke-RestMethod -Uri 'https://api.github.com/repos/git-for-windows/git/releases/latest' `
                                 -Headers @{ 'User-Agent' = 'ps' } -UseBasicParsing
        $asset = $rel.assets | Where-Object { $_.name -like 'PortableGit-*-64-bit.7z.exe' } | Select-Object -First 1
        if ($asset) { $url = $asset.browser_download_url }
    } catch {
        Write-Host "GitHub API lookup failed ($($_.Exception.Message)); using pinned fallback." -ForegroundColor DarkYellow
    }
    if (-not $url) {
        $url = 'https://github.com/git-for-windows/git/releases/download/v2.47.1.windows.1/PortableGit-2.47.1-64-bit.7z.exe'
    }
    Write-Host "Asset: $url"

    $sfx = Join-Path $env:TEMP 'PortableGit-64.7z.exe'
    if (-not (Test-Path $sfx)) {
        $ok = $false
        for ($i = 1; $i -le 5; $i++) {
            try {
                Write-Host "Downloading PortableGit (attempt $i/5)..." -ForegroundColor Yellow
                Invoke-WebRequest -Uri $url -OutFile $sfx -UseBasicParsing
                $ok = $true; break
            } catch {
                Write-Host "  failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
                Start-Sleep -Seconds 4
            }
        }
        if (-not $ok) { throw "Download failed after 5 attempts. Check proxy/network and re-run." }
    }

    Write-Host "Extracting to $dest ..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    # 7-Zip SFX silent extract: -o<dir> -y
    $p = Start-Process -FilePath $sfx -ArgumentList "-o`"$dest`"", '-y' -Wait -PassThru
    if (-not (Test-Path $gitExe)) { throw "Extraction finished (exit $($p.ExitCode)) but git.exe not found at $gitExe" }
    Remove-Item $sfx -ErrorAction SilentlyContinue
}

# ---- Add to USER PATH (HKCU, no admin) if not already there ----
$cmdDir = Join-Path $dest 'cmd'
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath -notlike "*$cmdDir*") {
    $newPath = if ([string]::IsNullOrEmpty($userPath)) { $cmdDir } else { "$userPath;$cmdDir" }
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    Write-Host "Added to USER PATH: $cmdDir" -ForegroundColor Green
} else {
    Write-Host "Already on USER PATH: $cmdDir"
}
# Make it available in THIS process too.
$env:Path = "$env:Path;$cmdDir"

Write-Host "--- git version ---" -ForegroundColor Cyan
& $gitExe --version
Write-Host ""
Write-Host "Git installed. Open a NEW terminal to use 'git' directly." -ForegroundColor Green
