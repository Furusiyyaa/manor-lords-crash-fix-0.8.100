# Manor Lords 0.8.100 region-refresh guard (experimental)

This is a build-specific, process-local runtime workaround for an observed
`EXCEPTION_ACCESS_VIOLATION` at `0x538` in Manor Lords 0.8.100. It adds an
early return when the native region-refresh routine is called with an empty
candidate-region list. It does not modify the game executable or save files
on disk and disappears when the game exits.

This is not an official fix and is not guaranteed to work for other builds.
Use it only for controlled testing and keep backups of important saves.

## Safety checks

The guard refuses to install unless both checks pass:

- Executable SHA-256:
  `37BEF06C94E4FCD93FDA77227BB2A88265CE1FBCB8862F98E75A720C923F2F29`
- Expected 15 entry bytes at routine RVA `0x4AD6750`

If the game updates, do not bypass these checks. Revalidate the new build
before using the guard.

## Use

Open PowerShell in this folder. Start Manor Lords and leave it at the main
menu, then run:

```powershell
.\Test-RegionGuard.ps1
.\Enable-RegionGuard.ps1
```

Load a test save only after the status reports that the guard is active. To
watch the process-local counter from a second PowerShell window, run:

```powershell
.\Watch-RegionGuard.ps1
```

The watcher writes JSONL files under `logs\region-guard`. Check status with:

```powershell
.\Get-RegionGuardStatus.ps1
```

Normally the in-memory patch disappears when the game exits. If the game is
still running and you want to restore the original bytes, run:

```powershell
.\Disable-RegionGuard.ps1
```

Do not force-close the game while another debugger or dump capture is
attached. The guard has only been validated against the executable hash above.

## Files

`ManorLordsRegionGuard.psm1` contains the native runtime implementation.
The `.ps1` files are small enable, disable, status, watch, and synthetic-test
wrappers. UE4SS telemetry and ProcDump are separate diagnostic tools and are
not required for the guard itself.
