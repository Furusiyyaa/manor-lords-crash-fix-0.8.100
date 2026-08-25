[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ManorLordsRegionGuard.psm1') -Force
Get-MLRegionGuardStatus | Format-List
