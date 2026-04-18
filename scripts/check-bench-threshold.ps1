# check-bench-threshold.ps1 — assert a Criterion bench's mean is below max_ns.
#
# Usage: pwsh ./scripts/check-bench-threshold.ps1 <bench_name> <max_ns>
#
# Mirrors check-bench-threshold.sh: reads
# target/criterion/<bench_name>/base/estimates.json, parses
# mean.point_estimate, exits 0 if mean <= max_ns else 1.

param(
    [Parameter(Mandatory=$true)][string]$BenchName,
    [Parameter(Mandatory=$true)][double]$MaxNs
)

$ErrorActionPreference = 'Stop'
$estimates = Join-Path -Path 'target' -ChildPath "criterion/$BenchName/base/estimates.json"

if (-not (Test-Path -LiteralPath $estimates)) {
    Write-Error "ERROR: $estimates not found. Did 'cargo bench --bench $($BenchName -replace '/.*$','')' run?"
    exit 1
}

$json = Get-Content -LiteralPath $estimates -Raw | ConvertFrom-Json
$meanNs = [double]$json.mean.point_estimate

if ($meanNs -le $MaxNs) {
    Write-Output ("PASS: {0} mean={1:N1} ns <= threshold={2} ns" -f $BenchName, $meanNs, $MaxNs)
    exit 0
} else {
    Write-Error ("FAIL: {0} mean={1:N1} ns > threshold={2} ns" -f $BenchName, $meanNs, $MaxNs)
    exit 1
}
