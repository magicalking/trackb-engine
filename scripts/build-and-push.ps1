#Requires -Version 5.1
<#
  build-and-push.ps1  --  Build the Track B engine image, smoke-test it OFFLINE,
  push to a registry, and print the sha256 digest to submit.

  Run AFTER Docker Desktop is installed and running (docker version works).
  Locates the repo root relative to this script, so run it from anywhere.

  Examples:
      # build + offline self-test only (no push, no registry needed):
      powershell -ExecutionPolicy Bypass -File build-and-push.ps1

      # build + test + push (login first):
      docker login ghcr.io
      powershell -ExecutionPolicy Bypass -File build-and-push.ps1 -Registry ghcr.io/youruser
#>
[CmdletBinding()]
param(
    [string]$ImageName = "trackb-engine",
    [string]$Tag       = "1.0.0",
    [string]$Registry  = ""    # e.g. ghcr.io/you | docker.io/you | <competition-registry>. Empty = no push.
)
$ErrorActionPreference = 'Stop'

# repo root = parent of the scripts/ folder this file lives in
$root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $root
Write-Host ("Repo root: {0}" -f $root) -ForegroundColor Cyan

# --- docker reachable? ---
docker version | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Docker is not running. Launch Docker Desktop and wait for the whale icon." }

$local = "{0}:{1}" -f $ImageName, $Tag
Write-Host ("Building {0} ..." -f $local) -ForegroundColor Yellow
docker build -f docker/Dockerfile -t $local .
if ($LASTEXITCODE -ne 0) { throw "docker build failed" }

# --- offline smoke test: image must run with NO network and write results.jsonl ---
Write-Host "Offline smoke test (--network none) ..." -ForegroundColor Yellow
$tmp       = Join-Path $env:TEMP ("tb_smoke_" + [IO.Path]::GetRandomFileName())
$skillsDir = Join-Path $tmp "skills"
$skill1    = Join-Path $skillsDir "demo-001"
$outDir    = Join-Path $tmp "out"
New-Item -ItemType Directory -Force -Path $skill1 | Out-Null
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
# Use a BENIGN sample (avoids local AV quarantine; goal is "pipeline runs", not detection).
"# CSV Formatter`nFormats CSV files nicely. No network needed.`n" |
    Out-File -FilePath (Join-Path $skill1 "SKILL.md") -Encoding utf8

docker run --rm --network none -v "${skillsDir}:/data/skills:ro" -v "${outDir}:/output" $local
if ($LASTEXITCODE -ne 0) { throw "container run failed" }

$res = Join-Path $outDir "results.jsonl"
if (-not (Test-Path $res)) { throw "no results.jsonl produced" }
Write-Host "results.jsonl:" -ForegroundColor Green
Get-Content -LiteralPath $res
Remove-Item -Recurse -Force -LiteralPath $tmp -ErrorAction SilentlyContinue

# --- push + digest ---
if ($Registry -ne "") {
    $remote = "{0}/{1}:{2}" -f $Registry.TrimEnd('/'), $ImageName, $Tag
    Write-Host ("Tagging -> {0}" -f $remote) -ForegroundColor Yellow
    docker tag $local $remote
    Write-Host "Pushing (make sure you ran 'docker login' for this registry) ..." -ForegroundColor Yellow
    docker push $remote
    if ($LASTEXITCODE -ne 0) { throw "docker push failed -- did you 'docker login <registry>'?" }
    $repoDigest = (docker inspect --format '{{index .RepoDigests 0}}' $remote)
    $sha = ($repoDigest -replace '.*@', '')
    Write-Host ""
    Write-Host "================ SUBMIT THESE ================" -ForegroundColor Green
    Write-Host ("image_ref    : {0}" -f $repoDigest)
    Write-Host ("image_digest : {0}" -f $sha)
    Write-Host "=============================================" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "Built and offline-tested OK. No -Registry given, so nothing was pushed." -ForegroundColor Yellow
    Write-Host "The submittable sha256 digest only exists AFTER a registry push:" -ForegroundColor Yellow
    Write-Host "  docker login <registry>"
    Write-Host ("  powershell -ExecutionPolicy Bypass -File `"{0}\build-and-push.ps1`" -Registry <registry>/<user>" -f $PSScriptRoot)
}
