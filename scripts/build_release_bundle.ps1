Param(
  [string]$ArtifactsDir = "artifacts",
  [string]$DistDir = "dist"
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path $DistDir)) { New-Item -ItemType Directory -Path $DistDir | Out-Null }

Write-Host "[1/3] Collect assessment artifacts"
$dirs = Get-ChildItem -Path $ArtifactsDir -Filter 'assessment-*' -Directory -ErrorAction SilentlyContinue
if (-not $dirs) {
  Write-Warning "No assessment-* directories found under $ArtifactsDir. Run scripts/run_assessment.sh (requires bash) or generate artifacts first."
} else {
  foreach ($d in $dirs) {
    $zipName = Join-Path $DistDir ($d.BaseName + '.zip')
    Write-Host "  Zipping $($d.FullName) -> $zipName"
    if (Test-Path $zipName) { Remove-Item $zipName }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($d.FullName, $zipName)
  }
}

Write-Host "[2/3] Create manifest"
$manifest = @()
Get-ChildItem -Path $DistDir -Filter 'assessment-*.zip' -File | ForEach-Object {
  $manifest += [pscustomobject]@{
    file       = $_.Name
    size_bytes = $_.Length
    timestamp  = (Get-Date).ToUniversalTime().ToString('o')
  }
}
$manifestPath = Join-Path $DistDir 'assessments_manifest.json'
$manifest | ConvertTo-Json | Out-File -FilePath $manifestPath -Encoding UTF8

Write-Host "[3/3] Done. Dist contents:" (Get-ChildItem -Path $DistDir | Select-Object -ExpandProperty Name)
