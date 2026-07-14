# PowerShell Review — v2.0 (findings only, no code changes)

Scope: `VeeamAdvisor-PowerShell.ps1` (1,240 lines) and `VeeamAdvisor-PowerShell-QA.ps1`
(1,687 lines). Reviewed against the repository-parsing work done in v2.0.

**Outcome: no changes made in v2.0.** Two findings are recorded for a future release.
Neither is a defect in the current release; both are gaps that mirror the log-parser gap
this release corrected.

---

## PS-1 (Major) — Repository enumeration misses scale-out and external repositories

`VeeamAdvisor-PowerShell.ps1`, block **B-4** (line 625):

```powershell
$repos = @(Get-VBRBackupRepository)
```

`Get-VBRBackupRepository` with no parameters returns **simple repositories only**. It does
not return:

- **Scale-out backup repositories** — these require `Get-VBRBackupRepository -ScaleOut`.
  The script's own comment block at line 619 documents this parameter as a known app
  pattern, but the enumeration at line 625 never uses it.
- **External repositories** — these require `Get-VBRExternalRepository`. The cmdlet does
  not appear anywhere in either script.

This is the same class of blind spot corrected in the log parser this release: an
enumeration that silently returns a subset, with no error and no warning, so the omission
is invisible in the output. A customer running the collector against an environment with a
SOBR and an Azure external repository would see neither in the inventory.

**Suggested remediation (future release):**

```powershell
$repos  = @(Get-VBRBackupRepository)
$repos += @(Get-VBRBackupRepository -ScaleOut)
$repos += @(Get-VBRExternalRepository)
```

with the external-repository call wrapped in `try/catch` — it is not present on all VBR
editions, and an unguarded call will terminate the block.

## PS-2 (Minor) — Capacity readout is silently empty for object and offline repositories

Line 649:

```powershell
try { $cont = $r.GetContainer(); $capGB = ...; $freeGB = ... } catch { }
```

`GetContainer()` returns no meaningful `CachedTotalSpace` for object-storage repositories
(which report used space, not capacity) or for repositories that are offline at collection
time. The `catch` leaves both values as an em dash, which is correct behaviour, but the
output does not distinguish *"this repository type has no capacity"* from *"this
repository was unreachable"* — the same distinction v2.0 now draws in the tool
(`n/a` versus `offline`).

**Suggested remediation (future release):** branch on `$r.Type` and label the two cases
distinctly rather than collapsing both to `—`.

---

## Verified as correct — no action

| Check | Result |
|---|---|
| Fleet View references | **None.** Neither script references the removed tool. |
| `#Requires -Version 5.1` | Correct — minimum for VBR v12. |
| `VeeamDataCloudObjStgVersion2` handling in QA | Present (4 assertions), including the immutability-by-design assertion that matches the tool's logic. |
| Cmdlet surface | 21 `Get-VBRJob`, 12 `Get-VBRBackupRepository`, 10 `Get-VBRComputerBackupJob`, 10 `Get-VBRCloudTenant` and others — all current for v12/v13. |
| Syntax | Both scripts unchanged from the previous release and previously validated. |

---

## Note on scope

PS-1 is a genuine collector gap, and it is tempting to fix it in the same release that
fixes the equivalent parser gap. It was deliberately not fixed here: the roadmap scoped
the PowerShell work as *"review all PowerShell scripts, confirm whether any updates are
required, document findings and recommended actions"* — a read-only phase. Changing
repository enumeration would alter collector output and require re-validation against a
live VBR server, which is not possible from the log corpus alone.
