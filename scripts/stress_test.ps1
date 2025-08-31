Param(
  [string]$Target = "https://example.org",
  [int]$DurationSeconds = 10,
  [string]$OutMetrics = "metrics.json"
)

Write-Host "[stress-pwsh] Target=$Target Duration=$DurationSeconds" -ForegroundColor Cyan
$stopAt = (Get-Date).AddSeconds($DurationSeconds)
$latencies = New-Object System.Collections.Generic.List[double]
$reqs = 0
$errors = 0

while((Get-Date) -lt $stopAt){
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  try { Invoke-WebRequest -Uri $Target -UseBasicParsing -TimeoutSec 10 | Out-Null } catch { $errors++ }
  $sw.Stop()
  $latencies.Add($sw.Elapsed.TotalMilliseconds)
  $reqs++
}

if($latencies.Count -eq 0){ $latencies.Add(0) }
$sorted = $latencies.ToArray() | Sort-Object
function Percentile([double[]]$arr, [double]$p){
  if($arr.Length -eq 0){ return $null }
  $rank = [math]::Ceiling(($p/100.0)*$arr.Length)-1
  if($rank -lt 0){ $rank = 0 }
  if($rank -ge $arr.Length){ $rank = $arr.Length-1 }
  return [math]::Round($arr[$rank],3)
}
$p95 = Percentile $sorted 95
$p99 = Percentile $sorted 99
$durationActual = ($latencies | Measure-Object -Sum).Count # not used
$elapsedSec = ($latencies | Measure-Object -Sum).Sum / 1000.0 # approx sequential, but we'll use wall clock
$wallElapsed = ($DurationSeconds) # approximate
$reqsPerSec = if($wallElapsed -gt 0){ [math]::Round($reqs / $wallElapsed,2) } else { 0 }

$metrics = [ordered]@{
  target = $Target
  start = (Get-Date).AddSeconds(-$DurationSeconds).ToString("o")
  end   = (Get-Date).ToString("o")
  duration_s = $DurationSeconds
  tool = "pwsh-curl"
  requests = $reqs
  requests_per_sec = $reqsPerSec
  errors = $errors
  latency_p95_ms = $p95
  latency_p99_ms = $p99
  loader_mode = "disabled-windows"
  handshake_p95_ms = $null
  handshake_p99_ms = $null
  events_received = 0
  handshakes_emitted = 0
  correlation_timeouts = 0
  kernel_drops = 0
  correlation_failure_rate = 0
  kernel_drop_rate = 0
}

$metrics | ConvertTo-Json -Depth 4 | Out-File -FilePath $OutMetrics -Encoding UTF8
Write-Host "[stress-pwsh] Wrote $OutMetrics" -ForegroundColor Green

$docPath = "docs/OVERHEAD_RESULTS.md"
if(!(Test-Path docs)){ New-Item -ItemType Directory docs | Out-Null }
@("# Overhead & Stress Test Results (Windows Placeholder)", "", "| Metric | Value |", "|--------|-------|", "| Target | $Target |", "| Duration (s) | $DurationSeconds |", "| Tool | pwsh-curl |", "| Requests/sec | $reqsPerSec |", "| HTTP p95 (ms) | $p95 |", "| HTTP p99 (ms) | $p99 |", "| Loader Mode | disabled-windows |", "", "> Runtime handshake metrics require Linux + eBPF loader.") | Out-File -FilePath $docPath -Encoding UTF8
Write-Host "[stress-pwsh] Updated $docPath" -ForegroundColor Green
