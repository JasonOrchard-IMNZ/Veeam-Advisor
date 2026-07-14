# Worked example — HV-B capture

These are the real artifacts from a MapCapture run on server HV-B (VBR 13.0.1.2067,
PowerShell 7.6.0), kept as a reference for what the capture produces and how it
pairs with a VMC.log.

- `VeeamAdvisor-MapCapture-HV-B-20260713-170518.txt` — the capture file output.
- `hv-b-powershell_screen_output.txt` — the console transcript of the run.
- Pair the capture with `hv-b-agent-VMC-v2.log` (same server) to see the map
  enriched: 8 of its jobs match, both replicas resolve — `hv-a pull repl` to host
  **hv-b** (`C:\Replicas`), and `Replication Job 2` is flagged as targeting a
  **deleted host** (`5ec1506e…`, "not found").

## What the run confirmed
- `88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec` is the built-in **Default Backup
  Repository** (WinLocal) — the same GUID on every VBR install.
- `Info.TargetRepositoryId` is the property behind VMC.log's `BackupRepository`.
- VMC.log records **no** replica target host; PowerShell resolves it via
  `GetTargetHost()` / `TargetHostId`.
- The Cloud Connect sections warn "service provider license required" because HV-B
  is a Cloud Connect **tenant**, not a provider — expected, not an error.

## Note on the console warnings
The earlier build's helper functions `H`/`W` collided with the PowerShell `h`
alias (`Get-History`), producing "Cannot bind parameter 'Id'" noise on the console.
The file output was unaffected. The current script renames them to
`Section`/`Emit` and unions `Get-VBRComputerBackupJob` to pre-empt the
`Get-VBRJob` computer-backup deprecation warning.
