[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ManorLordsRegionGuard.psm1') -Force

& (Get-Module ManorLordsRegionGuard) {
    Initialize-MLGuardNativeApi
    $handle = Open-MLGameProcess -ProcessId $PID
    $allocation = [IntPtr]::Zero
    $syntheticEntry = [IntPtr]::Zero
    $pawn = [IntPtr]::Zero
    try {
        $allocation = [MLRegionGuard.NativeMethods]::VirtualAllocEx(
            $handle, [IntPtr]::Zero, [UIntPtr]::new([UInt64]64), 0x3000, 0x40)
        if ($allocation -eq [IntPtr]::Zero) {
            throw 'Synthetic VirtualAllocEx failed.'
        }

        $syntheticEntry = [MLRegionGuard.NativeMethods]::VirtualAllocEx(
            $handle, [IntPtr]::Zero, [UIntPtr]::new([UInt64]256), 0x3000, 0x40)
        if ($syntheticEntry -eq [IntPtr]::Zero) {
            throw 'Synthetic entry VirtualAllocEx failed.'
        }

        $stubAddress = [UInt64]$allocation.ToInt64()
        $entryAddress = [UInt64]$syntheticEntry.ToInt64()
        $stub = New-MLGuardStub -StubAddress $stubAddress -ReturnAddress ($entryAddress + 15)
        Write-RemoteBytes -Handle $handle -Address $stubAddress -Bytes $stub.Bytes
        $entryPatch = New-MLGuardEntryPatch -StubAddress $stubAddress
        Write-RemoteBytes -Handle $handle -Address $entryAddress -Bytes $entryPatch
        # Synthetic continuation reverses the four displaced pushes, restores
        # RBP, and returns. This exercises the trampoline without game code.
        Write-RemoteBytes -Handle $handle -Address ($entryAddress + 15) -Bytes ([byte[]](0x41,0x5F,0x41,0x5E,0x5B,0x5D,0xC3))
        [void][MLRegionGuard.NativeMethods]::FlushInstructionCache(
            $handle, $allocation, [UIntPtr]::new([UInt64]$stub.Bytes.Length))
        [void][MLRegionGuard.NativeMethods]::FlushInstructionCache(
            $handle, $syntheticEntry, [UIntPtr]::new([UInt64]256))

        $pawn = [Runtime.InteropServices.Marshal]::AllocHGlobal(0xA54)
        [Runtime.InteropServices.Marshal]::Copy([byte[]]::new(0xA54), 0, $pawn, 0xA54)
        [Runtime.InteropServices.Marshal]::WriteInt32($pawn, 0xA50, 0)

        $guard = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
            $syntheticEntry, [type][MLRegionGuard.NativeMethods+GuardStubDelegate])
        $guard.Invoke($pawn)

        $counterBytes = Read-RemoteBytes -Handle $handle -Address $stub.CounterAddress -Length 8
        $counter = [BitConverter]::ToUInt64($counterBytes, 0)
        if ($counter -ne 1) {
            throw "Synthetic guard counter was $counter instead of 1."
        }

        [Runtime.InteropServices.Marshal]::WriteInt32($pawn, 0xA50, 1)
        $guard.Invoke($pawn)
        $counterBytes = Read-RemoteBytes -Handle $handle -Address $stub.CounterAddress -Length 8
        $counterAfterOriginalPath = [BitConverter]::ToUInt64($counterBytes, 0)
        if ($counterAfterOriginalPath -ne 1) {
            throw "Original-path test unexpectedly changed the counter to $counterAfterOriginalPath."
        }
        [PSCustomObject]@{
            SyntheticSuppressionPath = 'Passed'
            SyntheticOriginalPath = 'Passed'
            Counter = $counter
            StubLength = $stub.Bytes.Length
            CounterAligned = (($stub.CounterAddress % 8) -eq 0)
        } | Format-List
    }
    finally {
        if ($pawn -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::FreeHGlobal($pawn)
        }
        if ($allocation -ne [IntPtr]::Zero) {
            [void][MLRegionGuard.NativeMethods]::VirtualFreeEx(
                $handle, $allocation, [UIntPtr]::Zero, 0x8000)
        }
        if ($syntheticEntry -ne [IntPtr]::Zero) {
            [void][MLRegionGuard.NativeMethods]::VirtualFreeEx(
                $handle, $syntheticEntry, [UIntPtr]::Zero, 0x8000)
        }
        [void][MLRegionGuard.NativeMethods]::CloseHandle($handle)
    }
}
