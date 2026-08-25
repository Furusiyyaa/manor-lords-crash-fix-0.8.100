[CmdletBinding()]
param([string]$ExecutablePath)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ManorLordsRegionGuard.psm1') -Force
if ([string]::IsNullOrWhiteSpace($ExecutablePath)) {
    Test-MLRegionGuardBuild | Format-List
}
else {
    Test-MLRegionGuardBuild -ExecutablePath $ExecutablePath | Format-List
}
