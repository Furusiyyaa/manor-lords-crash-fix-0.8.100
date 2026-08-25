[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ManorLordsRegionGuard.psm1') -Force
Enable-MLRegionGuard | Format-List
