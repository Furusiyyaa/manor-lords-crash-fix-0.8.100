Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ExpectedExeHash = '37BEF06C94E4FCD93FDA77227BB2A88265CE1FBCB8862F98E75A720C923F2F29'
$script:TargetRva = [UInt64]0x4AD6750
$script:CandidateCountOffset = [UInt32]0xA50
$script:ExpectedEntryBytes = [byte[]](0x40,0x55,0x53,0x41,0x56,0x41,0x57,0x48,0x8D,0xAC,0x24,0x68,0xFF,0xFF,0xFF)
$script:ProjectRoot = Split-Path -Parent $PSScriptRoot
$script:StatePath = Join-Path $script:ProjectRoot 'state\region-guard.json'
$script:LogRoot = Join-Path $script:ProjectRoot 'logs\region-guard'

function Initialize-MLGuardNativeApi {
    if ('MLRegionGuard.NativeMethods' -as [type]) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace MLRegionGuard
{
    public static class NativeMethods
    {
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate void GuardStubDelegate(IntPtr pawn);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ReadProcessMemory(
            IntPtr process,
            IntPtr address,
            [Out] byte[] buffer,
            UIntPtr size,
            out UIntPtr bytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WriteProcessMemory(
            IntPtr process,
            IntPtr address,
            byte[] buffer,
            UIntPtr size,
            out UIntPtr bytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(
            IntPtr process,
            IntPtr address,
            UIntPtr size,
            uint allocationType,
            uint protection);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualFreeEx(
            IntPtr process,
            IntPtr address,
            UIntPtr size,
            uint freeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualProtectEx(
            IntPtr process,
            IntPtr address,
            UIntPtr size,
            uint newProtection,
            out uint oldProtection);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FlushInstructionCache(
            IntPtr process,
            IntPtr address,
            UIntPtr size);

        [DllImport("ntdll.dll")]
        public static extern int NtSuspendProcess(IntPtr process);

        [DllImport("ntdll.dll")]
        public static extern int NtResumeProcess(IntPtr process);
    }
}
'@
}

function ConvertTo-HexString {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    return (($Bytes | ForEach-Object { $_.ToString('X2') }) -join '')
}

function ConvertFrom-HexString {
    param([Parameter(Mandatory)][string]$Hex)
    if (($Hex.Length % 2) -ne 0) {
        throw 'Invalid odd-length hexadecimal string.'
    }
    $bytes = [byte[]]::new($Hex.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16)
    }
    return $bytes
}

function Test-ByteArrayEqual {
    param([byte[]]$Left, [byte[]]$Right)
    if ($null -eq $Left -or $null -eq $Right -or $Left.Length -ne $Right.Length) {
        return $false
    }
    for ($i = 0; $i -lt $Left.Length; $i++) {
        if ($Left[$i] -ne $Right[$i]) {
            return $false
        }
    }
    return $true
}

function Get-FileBytesAtRva {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][UInt64]$Rva,
        [Parameter(Mandatory)][int]$Length
    )

    $bytes = [IO.File]::ReadAllBytes($Path)
    $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
    if ([Text.Encoding]::ASCII.GetString($bytes, $peOffset, 4) -ne "PE`0`0") {
        throw "Not a PE image: $Path"
    }

    $sectionCount = [BitConverter]::ToUInt16($bytes, $peOffset + 6)
    $optionalHeaderSize = [BitConverter]::ToUInt16($bytes, $peOffset + 20)
    $sectionTable = $peOffset + 24 + $optionalHeaderSize

    for ($i = 0; $i -lt $sectionCount; $i++) {
        $section = $sectionTable + (40 * $i)
        $virtualSize = [BitConverter]::ToUInt32($bytes, $section + 8)
        $virtualAddress = [BitConverter]::ToUInt32($bytes, $section + 12)
        $rawSize = [BitConverter]::ToUInt32($bytes, $section + 16)
        $rawAddress = [BitConverter]::ToUInt32($bytes, $section + 20)
        $mappedSize = [Math]::Max([UInt64]$virtualSize, [UInt64]$rawSize)

        if ($Rva -ge $virtualAddress -and ($Rva + $Length) -le ($virtualAddress + $mappedSize)) {
            $fileOffset = [UInt64]$rawAddress + ($Rva - [UInt64]$virtualAddress)
            $result = [byte[]]::new($Length)
            [Array]::Copy($bytes, [Int64]$fileOffset, $result, 0, $Length)
            return $result
        }
    }

    throw ('RVA 0x{0:X} was not mapped by a PE section.' -f $Rva)
}

function Get-MLGameProcess {
    $processes = @(Get-Process -Name 'ManorLords-Win64-Shipping' -ErrorAction SilentlyContinue)
    if ($processes.Count -eq 0) {
        throw 'Manor Lords is not running.'
    }
    if ($processes.Count -ne 1) {
        throw "Expected one Manor Lords process, found $($processes.Count)."
    }
    return $processes[0]
}

function Open-MLGameProcess {
    param([Parameter(Mandatory)][int]$ProcessId)
    Initialize-MLGuardNativeApi
    $access = [UInt32](0x0008 -bor 0x0010 -bor 0x0020 -bor 0x0400 -bor 0x0800)
    $handle = [MLRegionGuard.NativeMethods]::OpenProcess($access, $false, $ProcessId)
    if ($handle -eq [IntPtr]::Zero) {
        throw "OpenProcess failed: Win32 $([Runtime.InteropServices.Marshal]::GetLastWin32Error())."
    }
    return $handle
}

function Read-RemoteBytes {
    param(
        [Parameter(Mandatory)][IntPtr]$Handle,
        [Parameter(Mandatory)][UInt64]$Address,
        [Parameter(Mandatory)][int]$Length
    )
    $buffer = [byte[]]::new($Length)
    $read = [UIntPtr]::Zero
    $ok = [MLRegionGuard.NativeMethods]::ReadProcessMemory(
        $Handle, [IntPtr]::new([Int64]$Address), $buffer, [UIntPtr]::new([UInt64]$Length), [ref]$read)
    if (-not $ok -or $read.ToUInt64() -ne [UInt64]$Length) {
        throw "ReadProcessMemory failed at 0x$($Address.ToString('X')): Win32 $([Runtime.InteropServices.Marshal]::GetLastWin32Error())."
    }
    return $buffer
}

function Write-RemoteBytes {
    param(
        [Parameter(Mandatory)][IntPtr]$Handle,
        [Parameter(Mandatory)][UInt64]$Address,
        [Parameter(Mandatory)][byte[]]$Bytes
    )
    $written = [UIntPtr]::Zero
    $ok = [MLRegionGuard.NativeMethods]::WriteProcessMemory(
        $Handle, [IntPtr]::new([Int64]$Address), $Bytes, [UIntPtr]::new([UInt64]$Bytes.Length), [ref]$written)
    if (-not $ok -or $written.ToUInt64() -ne [UInt64]$Bytes.Length) {
        throw "WriteProcessMemory failed at 0x$($Address.ToString('X')): Win32 $([Runtime.InteropServices.Marshal]::GetLastWin32Error())."
    }
}

function Set-RemoteCodeBytes {
    param(
        [Parameter(Mandatory)][IntPtr]$Handle,
        [Parameter(Mandatory)][UInt64]$Address,
        [Parameter(Mandatory)][byte[]]$Bytes
    )
    $oldProtection = [UInt32]0
    if (-not [MLRegionGuard.NativeMethods]::VirtualProtectEx(
        $Handle, [IntPtr]::new([Int64]$Address), [UIntPtr]::new([UInt64]$Bytes.Length), 0x40, [ref]$oldProtection)) {
        throw "VirtualProtectEx failed: Win32 $([Runtime.InteropServices.Marshal]::GetLastWin32Error())."
    }
    try {
        Write-RemoteBytes -Handle $Handle -Address $Address -Bytes $Bytes
        if (-not [MLRegionGuard.NativeMethods]::FlushInstructionCache(
            $Handle, [IntPtr]::new([Int64]$Address), [UIntPtr]::new([UInt64]$Bytes.Length))) {
            throw "FlushInstructionCache failed: Win32 $([Runtime.InteropServices.Marshal]::GetLastWin32Error())."
        }
    }
    finally {
        $ignoredProtection = [UInt32]0
        [void][MLRegionGuard.NativeMethods]::VirtualProtectEx(
            $Handle, [IntPtr]::new([Int64]$Address), [UIntPtr]::new([UInt64]$Bytes.Length), $oldProtection, [ref]$ignoredProtection)
    }
}

function Add-Bytes {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[byte]]$List,
        [Parameter(Mandatory)][byte[]]$Bytes
    )
    foreach ($byte in $Bytes) {
        $List.Add($byte)
    }
}

function New-MLGuardStub {
    param(
        [Parameter(Mandatory)][UInt64]$StubAddress,
        [Parameter(Mandatory)][UInt64]$ReturnAddress
    )

    $stub = [System.Collections.Generic.List[byte]]::new()

    # test rcx,rcx; je suppress
    Add-Bytes $stub ([byte[]](0x48,0x85,0xC9,0x74,0x09))
    # cmp dword ptr [rcx+0xA50],0; jg original
    Add-Bytes $stub ([byte[]](0x83,0xB9,0x50,0x0A,0x00,0x00,0x00,0x7F,0x09))
    # suppress: lock inc qword ptr [rip+0x22]; ret
    Add-Bytes $stub ([byte[]](0xF0,0x48,0xFF,0x05,0x22,0x00,0x00,0x00,0xC3))
    # original entry bytes
    Add-Bytes $stub $script:ExpectedEntryBytes
    # jmp qword ptr [rip+0]; absolute return address
    Add-Bytes $stub ([byte[]](0xFF,0x25,0x00,0x00,0x00,0x00))
    Add-Bytes $stub ([BitConverter]::GetBytes($ReturnAddress))
    # Align the process-local suppression counter to eight bytes.
    Add-Bytes $stub ([byte[]](0x90,0x90,0x90,0x90))
    Add-Bytes $stub ([BitConverter]::GetBytes([UInt64]0))

    if ($stub.Count -ne 64) {
        throw "Internal stub-length error: expected 64, got $($stub.Count)."
    }

    return [PSCustomObject]@{
        Bytes = $stub.ToArray()
        CounterAddress = $StubAddress + 56
        OriginalPathOffset = 23
    }
}

function New-MLGuardEntryPatch {
    param([Parameter(Mandatory)][UInt64]$StubAddress)
    $patch = [System.Collections.Generic.List[byte]]::new()
    Add-Bytes $patch ([byte[]](0xFF,0x25,0x00,0x00,0x00,0x00))
    Add-Bytes $patch ([BitConverter]::GetBytes($StubAddress))
    $patch.Add(0x90)
    return $patch.ToArray()
}

function Test-MLRegionGuardBuild {
    [CmdletBinding()]
    param(
        [string]$ExecutablePath
    )

    if ([string]::IsNullOrWhiteSpace($ExecutablePath)) {
        $ExecutablePath = (Get-MLGameProcess).MainModule.FileName
    }

    $resolved = (Resolve-Path -LiteralPath $ExecutablePath).Path
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $resolved).Hash
    $entry = Get-FileBytesAtRva -Path $resolved -Rva $script:TargetRva -Length $script:ExpectedEntryBytes.Length
    $hashMatch = $hash -eq $script:ExpectedExeHash
    $bytesMatch = Test-ByteArrayEqual $entry $script:ExpectedEntryBytes

    $testStub = New-MLGuardStub -StubAddress 0x0000010000000000 -ReturnAddress (0x0000000140000000 + $script:TargetRva + $script:ExpectedEntryBytes.Length)
    $stubValid = $testStub.Bytes.Length -eq 64 -and $testStub.CounterAddress -eq 0x0000010000000038

    [PSCustomObject]@{
        ExecutablePath = $resolved
        ActualSHA256 = $hash
        ExpectedSHA256 = $script:ExpectedExeHash
        HashMatch = $hashMatch
        TargetRva = ('0x{0:X}' -f $script:TargetRva)
        ActualEntryBytes = ConvertTo-HexString $entry
        ExpectedEntryBytes = ConvertTo-HexString $script:ExpectedEntryBytes
        EntryBytesMatch = $bytesMatch
        StubLayoutValid = $stubValid
        Ready = $hashMatch -and $bytesMatch -and $stubValid
    }
}

function Enable-MLRegionGuard {
    [CmdletBinding()]
    param()

    if (Test-Path -LiteralPath $script:StatePath) {
        throw "Guard state already exists at $script:StatePath. Check status before enabling again."
    }

    $process = Get-MLGameProcess
    $exePath = $process.MainModule.FileName
    $verification = Test-MLRegionGuardBuild -ExecutablePath $exePath
    if (-not $verification.Ready) {
        throw 'Build verification failed. The guard was not applied.'
    }

    $moduleBase = [UInt64]$process.MainModule.BaseAddress.ToInt64()
    $targetAddress = $moduleBase + $script:TargetRva
    $handle = Open-MLGameProcess -ProcessId $process.Id
    $suspended = $false
    $stubAddress = [UInt64]0
    $patchWritten = $false
    $original = $null

    try {
        $status = [MLRegionGuard.NativeMethods]::NtSuspendProcess($handle)
        if ($status -ne 0) {
            throw ('NtSuspendProcess failed: NTSTATUS 0x{0:X8}.' -f [UInt32]$status)
        }
        $suspended = $true

        $original = Read-RemoteBytes -Handle $handle -Address $targetAddress -Length $script:ExpectedEntryBytes.Length
        if (-not (Test-ByteArrayEqual $original $script:ExpectedEntryBytes)) {
            throw "Live target bytes do not match the verified build. Nothing was changed."
        }

        $allocation = [MLRegionGuard.NativeMethods]::VirtualAllocEx(
            $handle, [IntPtr]::Zero, [UIntPtr]::new([UInt64]64), 0x3000, 0x40)
        if ($allocation -eq [IntPtr]::Zero) {
            throw "VirtualAllocEx failed: Win32 $([Runtime.InteropServices.Marshal]::GetLastWin32Error())."
        }
        $stubAddress = [UInt64]$allocation.ToInt64()

        $stub = New-MLGuardStub -StubAddress $stubAddress -ReturnAddress ($targetAddress + $original.Length)
        Write-RemoteBytes -Handle $handle -Address $stubAddress -Bytes $stub.Bytes
        if (-not [MLRegionGuard.NativeMethods]::FlushInstructionCache(
            $handle, $allocation, [UIntPtr]::new([UInt64]$stub.Bytes.Length))) {
            throw "FlushInstructionCache failed for the guard stub."
        }

        $entryPatch = New-MLGuardEntryPatch -StubAddress $stubAddress
        Set-RemoteCodeBytes -Handle $handle -Address $targetAddress -Bytes $entryPatch
        $patchWritten = $true

        $state = [ordered]@{
            schema = 1
            enabled_at = [DateTimeOffset]::Now.ToString('o')
            process_id = $process.Id
            process_start_time = $process.StartTime.ToUniversalTime().ToString('o')
            executable_path = $exePath
            executable_sha256 = $verification.ActualSHA256
            module_base = ('0x{0:X}' -f $moduleBase)
            target_rva = ('0x{0:X}' -f $script:TargetRva)
            target_address = ('0x{0:X}' -f $targetAddress)
            candidate_count_offset = ('0x{0:X}' -f $script:CandidateCountOffset)
            original_bytes = ConvertTo-HexString $original
            patch_bytes = ConvertTo-HexString $entryPatch
            stub_address = ('0x{0:X}' -f $stubAddress)
            stub_size = $stub.Bytes.Length
            counter_address = ('0x{0:X}' -f $stub.CounterAddress)
        }
        $stateDirectory = Split-Path -Parent $script:StatePath
        [IO.Directory]::CreateDirectory($stateDirectory) | Out-Null
        [IO.File]::WriteAllText($script:StatePath, ($state | ConvertTo-Json -Depth 4), [Text.UTF8Encoding]::new($false))
    }
    catch {
        if ($patchWritten -and $null -ne $original) {
            try { Set-RemoteCodeBytes -Handle $handle -Address $targetAddress -Bytes $original } catch {}
        }
        if ($stubAddress -ne 0) {
            [void][MLRegionGuard.NativeMethods]::VirtualFreeEx(
                $handle, [IntPtr]::new([Int64]$stubAddress), [UIntPtr]::Zero, 0x8000)
        }
        throw
    }
    finally {
        if ($suspended) {
            [void][MLRegionGuard.NativeMethods]::NtResumeProcess($handle)
        }
        [void][MLRegionGuard.NativeMethods]::CloseHandle($handle)
    }

    return Get-MLRegionGuardStatus
}

function Get-MLRegionGuardStatus {
    [CmdletBinding()]
    param()

    if (-not (Test-Path -LiteralPath $script:StatePath)) {
        return [PSCustomObject]@{ Active = $false; Reason = 'No guard state file exists.' }
    }

    $state = Get-Content -Raw -LiteralPath $script:StatePath | ConvertFrom-Json
    $process = Get-Process -Id ([int]$state.process_id) -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        return [PSCustomObject]@{ Active = $false; Reason = 'The recorded game process has exited; the process-local patch is gone.'; StaleState = $true }
    }

    $recordedStart = ([DateTimeOffset]$state.process_start_time).UtcDateTime
    $currentStart = $process.StartTime.ToUniversalTime()
    if ($recordedStart.Ticks -ne $currentStart.Ticks) {
        return [PSCustomObject]@{ Active = $false; Reason = 'PID was reused by another process.'; StaleState = $true }
    }

    $handle = Open-MLGameProcess -ProcessId $process.Id
    try {
        $target = [Convert]::ToUInt64(([string]$state.target_address).Substring(2), 16)
        $counter = [Convert]::ToUInt64(([string]$state.counter_address).Substring(2), 16)
        $expectedPatch = ConvertFrom-HexString ([string]$state.patch_bytes)
        $livePatch = Read-RemoteBytes -Handle $handle -Address $target -Length $expectedPatch.Length
        $counterBytes = Read-RemoteBytes -Handle $handle -Address $counter -Length 8
        $suppressed = [BitConverter]::ToUInt64($counterBytes, 0)
        $active = Test-ByteArrayEqual $livePatch $expectedPatch
        return [PSCustomObject]@{
            Active = $active
            ProcessId = $process.Id
            Target = [string]$state.target_address
            SuppressedRefreshes = $suppressed
            PatchBytesMatch = $active
            EnabledAt = [string]$state.enabled_at
        }
    }
    finally {
        [void][MLRegionGuard.NativeMethods]::CloseHandle($handle)
    }
}

function Disable-MLRegionGuard {
    [CmdletBinding()]
    param()

    if (-not (Test-Path -LiteralPath $script:StatePath)) {
        throw 'No guard state file exists.'
    }
    $state = Get-Content -Raw -LiteralPath $script:StatePath | ConvertFrom-Json
    $process = Get-Process -Id ([int]$state.process_id) -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        [IO.File]::Delete($script:StatePath)
        return [PSCustomObject]@{ Restored = $false; Reason = 'The game had exited, so the process-local patch was already gone. Stale state was removed.' }
    }
    $recordedStart = ([DateTimeOffset]$state.process_start_time).UtcDateTime
    $currentStart = $process.StartTime.ToUniversalTime()
    if ($recordedStart.Ticks -ne $currentStart.Ticks) {
        throw 'The recorded PID now belongs to another process. Refusing to touch it.'
    }

    $target = [Convert]::ToUInt64(([string]$state.target_address).Substring(2), 16)
    $stub = [Convert]::ToUInt64(([string]$state.stub_address).Substring(2), 16)
    $original = ConvertFrom-HexString ([string]$state.original_bytes)
    $expectedPatch = ConvertFrom-HexString ([string]$state.patch_bytes)
    $handle = Open-MLGameProcess -ProcessId $process.Id
    $suspended = $false

    try {
        $status = [MLRegionGuard.NativeMethods]::NtSuspendProcess($handle)
        if ($status -ne 0) {
            throw ('NtSuspendProcess failed: NTSTATUS 0x{0:X8}.' -f [UInt32]$status)
        }
        $suspended = $true
        $live = Read-RemoteBytes -Handle $handle -Address $target -Length $expectedPatch.Length
        if (-not (Test-ByteArrayEqual $live $expectedPatch)) {
            throw 'Live target bytes do not match this guard. Refusing to overwrite them.'
        }
        Set-RemoteCodeBytes -Handle $handle -Address $target -Bytes $original
        [void][MLRegionGuard.NativeMethods]::VirtualFreeEx(
            $handle, [IntPtr]::new([Int64]$stub), [UIntPtr]::Zero, 0x8000)
        [IO.File]::Delete($script:StatePath)
    }
    finally {
        if ($suspended) {
            [void][MLRegionGuard.NativeMethods]::NtResumeProcess($handle)
        }
        [void][MLRegionGuard.NativeMethods]::CloseHandle($handle)
    }

    [PSCustomObject]@{ Restored = $true; ProcessId = $process.Id; Target = ('0x{0:X}' -f $target) }
}

function Watch-MLRegionGuard {
    [CmdletBinding()]
    param([int]$IntervalMilliseconds = 250)

    [IO.Directory]::CreateDirectory($script:LogRoot) | Out-Null
    $logPath = Join-Path $script:LogRoot ('guard-{0}.jsonl' -f [DateTimeOffset]::Now.ToString('yyyyMMdd-HHmmss'))
    $lastCount = [UInt64]0
    while ($true) {
        $status = Get-MLRegionGuardStatus
        $record = [ordered]@{
            ts = [DateTimeOffset]::Now.ToString('o')
            active = [bool]$status.Active
            suppressed_refreshes = if ($status.PSObject.Properties.Name -contains 'SuppressedRefreshes') { [UInt64]$status.SuppressedRefreshes } else { $null }
            delta = if ($status.PSObject.Properties.Name -contains 'SuppressedRefreshes') { [UInt64]$status.SuppressedRefreshes - $lastCount } else { $null }
            reason = if ($status.PSObject.Properties.Name -contains 'Reason') { [string]$status.Reason } else { $null }
        }
        [IO.File]::AppendAllText($logPath, (($record | ConvertTo-Json -Compress) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
        if ($status.PSObject.Properties.Name -contains 'SuppressedRefreshes') {
            if ([UInt64]$status.SuppressedRefreshes -ne $lastCount) {
                $record | Format-List
            }
            $lastCount = [UInt64]$status.SuppressedRefreshes
        }
        if (-not $status.Active) {
            break
        }
        Start-Sleep -Milliseconds $IntervalMilliseconds
    }
    return $logPath
}

Export-ModuleMember -Function Test-MLRegionGuardBuild, Enable-MLRegionGuard, Get-MLRegionGuardStatus, Disable-MLRegionGuard, Watch-MLRegionGuard
