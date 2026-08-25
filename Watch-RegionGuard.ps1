[CmdletBinding()]
param([int]$IntervalMilliseconds = 250)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ManorLordsRegionGuard.psm1') -Force
$path = Watch-MLRegionGuard -IntervalMilliseconds $IntervalMilliseconds
Write-Host "Guard telemetry: $path"
