# Veeam Advisor v2.0 — Release Package

**Release deadline:** 20 July 2026 · **Prepared:** 9 July 2026
**Previous commit:** `b58ac8b` · **Previous version:** `1.1`

---

## Version summary

| | |
|---|---|
| Version | **2.0** |
| Type | Major release |
| Tag | `v2.0` |
| Files changed | 8 modified, 2 added, 2 deleted |
| Repository parse accuracy | 9/22 → **17/22** exact matches against the log's own type summary |
| New tabs | Backup Map (tab 15) |
| Repositories recovered across the 22-log corpus | **58** (zero lost) |
| WCAG AA failures | **0** (light and dark) |
| CI | `confirm-bp-findings.js` — 30 assertions, all pass |

### Changed
- `index.html` — repository parser rebuild, arcade theme, PDF print-mode fix, version, feedback link
- `user-guide.html` — arcade theme, print-mode fix, Fleet section removed, sections renumbered, feedback link
- `README.md` — Fleet removed, file table corrected
- `CHANGELOG.md` — v2.0 entry prepended
- `staticwebapp.config.json` — phantom `Veeam_Advisor_v1.0.html` exclusion corrected
- `Veeam_Advisor_v1.0_Calculations.txt` — Fleet references removed

### Added
- `Veeam_Advisor_v2.0.html` — locked snapshot, byte-identical to `index.html`
- `POWERSHELL-REVIEW-v2.0.md` — read-only PowerShell findings

### Deleted
- `Veeam_Advisor_Fleet.html`
- `confirm-outputs.js` — existed solely to `eval` the Fleet codebase; not part of CI

### Unchanged (deliberately)
- `Veeam_Advisor_v1.1.0.html`, `Veeam_Advisor_v1.0.3.html`, `Veeam_Advisor_v1.0.2.html` — historical snapshots. `confirm-bp-findings.js` asserts against the v1.1.0 snapshot; restyling it would break CI.
- `VeeamAdvisor-PowerShell.ps1`, `VeeamAdvisor-PowerShell-QA.ps1` — review was scoped read-only.

---

## Release notes (user-facing)

**Veeam Advisor v2.0** is a major release built on a forensic audit of 22 production
`VMC.log` files.

**Repositories that were silently missing are now shown.** The repository parser previously
required optional fields that some repository types legitimately omit, and dropped those
repositories without an error or a warning. Veeam Data Cloud (v2), every External repository
type, and repositories that were offline when the log was captured are now listed. In one
audited environment this recovered roughly 106 TiB of previously invisible capacity.

Storage-snapshot-only repositories are now listed with `n/a` capacity, because they hold no
backup files. Repositories under 0.1 TB show GB/MB instead of `0.0 TB`. Where the log's own
type summary counts a repository the log never enumerates, the tool reports the gap rather
than hiding it.

**Fewer false alarms.** The "immutability disabled" finding no longer fires on offline,
capacity-less or External repositories — Veeam does not manage immutability on any of them.

**A new look.** A retro arcade theme: cabinet-black header with a neon accent, monospace
headings, heavier borders. Every colour is now a token, and the whole palette clears WCAG AA
contrast in both light and dark mode. Three pre-existing contrast failures were fixed along
the way, including retention-table headers that had been rendering at 2.2:1.

**PDF export.** Reports now carry the tool version and a feedback contact. A defect where a
dark-mode operating system could produce pale, unreadable text in the exported PDF has been
fixed; print output is now always light.

**A new Backup Map tab** draws where every job writes and how backup copy jobs move data
between repositories. It reads linkage the log already carried (`BackupRepository` on backup
jobs; `RepositoryID` plus `SourceBackupJobs` on backup copy jobs) — 496 of 512 storage-bearing
jobs declare a target, and every real target resolves. The diagram is repository-centric because
one production environment has 147 jobs against 24 repositories. It surfaces idle repositories
(12 of 24 in one estate), missing backup copy flows, and return-copy cycles. Job names are not
recorded in `VMC.log`, so nodes are labelled by repository.

**Fleet View has been removed** from the package.

**Feedback & Bug Fix Requests** — a contact link now appears in the tool header, the User
Guide, and every exported PDF.

---

## Known limitations (declared, not defects)

Three of the 22 audited logs count repositories in their type summary that the log never
enumerates anywhere — no definition line, no `ExtentsIDs` membership, no job reference
(`WinLocal` ×4 and `ExternalPlatform` ×1). No row can be constructed for these. The parser is
correct; the source data is incomplete.

Two items remain designed but unbuilt, pending approval:
- the on-screen reconciliation notice for the unenumerated repositories above
- dedicated Scale-Out and External Repository breakout panels

---

## Git commit message

```text
Release v2.0 - Retro theme update, PDF enhancements, documentation refresh, Fleet feature removal, bug fixes and validation updates
```

### Extended body (recommended)

```text
Release v2.0 - Retro theme update, PDF enhancements, documentation refresh,
Fleet feature removal, bug fixes and validation updates

Repository parser rebuilt on a definition-line anchor rather than optional
companion fields. Recovers VeeamDataCloudObjStgVersion2 (which carries
RepositoryGroupType but no ConcurrentTaskLimit), all *External types, offline
repositories (TotalSpace: null/-1) and SanSnapshotOnly. Reconciliation against
the log's authoritative type summary improves from 9/22 to 17/22 across the
production corpus; 58 repositories recovered, zero lost.

LimitStorageConsumption is now read only when Enabled is True -- it carries a
Value/Unit even when disabled, and applying it blindly would cap a 106 TiB
repository at 10 TB. Used space on object repositories is read from UsedSpace
rather than derived from (total - free), which under-reported consumption once a
repository exceeded its quota.

Type-count summary now reads the last collection pass, not the first. Rows are
scoped to the final completed enumeration pass. Escaped-brace summary lines are
tolerated. Sub-terabyte repositories display GB/MB.

Immutability findings no longer fire on offline, capacity-less or External
repositories.

Retro arcade colour scheme applied. All 22 hardcoded hex colours replaced with
tokens; semantic tokens resolve to text-safe stops. Zero WCAG AA failures in
light or dark mode. Fixes pre-existing contrast failures in the retention table
headers and the DR job category.

Fixes PDF/print output inheriting dark-mode token values, which produced pale
text on a white page for dark-mode users. Applies the same reset to the guide.

Adds a Backup Map tab: repository-centric job -> repository -> repository
topology with backup copy flows, cycle-safe lane assignment (Kahn plus cycle
breaking), idle-repository findings and a PDF page. GUID case is normalised and
the 00000000-... sentinel is excluded, without which copy edges silently fail to
resolve. Edge totals count distinct copy jobs, and copy volume is reported
separately from primary data to avoid double-counting the estate.

Adds MTU to the Network Interfaces panel, read from each interface's own block.

Fleet View and its confirm-outputs.js harness removed; all references stripped
from documentation. PowerShell reviewed read-only; findings in
POWERSHELL-REVIEW-v2.0.md.
```

## Git tag recommendation

Annotated tag, matching the existing `v1.x` convention:

```text
v2.0
```

Tag message:

```text
Version 2.0 Release
```

## Git commands

```bash
git add .
git commit -m "Release v2.0 - Retro theme update, PDF enhancements, documentation refresh, Fleet feature removal, bug fixes and validation updates"
git tag -a v2.0 -m "Version 2.0 Release"
git push origin main
git push origin v2.0
```

Note that `git add .` will stage the two deletions (`Veeam_Advisor_Fleet.html`,
`confirm-outputs.js`) only if they were removed from the working tree with `rm`. If they were
deleted outside git, confirm with `git status` before committing, or use `git add -A`.

---

## Final release validation

| Criterion | Status |
|---|---|
| Repository integrity maintained | Pass — 16 files, README file table reconciled against disk |
| Documentation aligned with code | Pass — no doc references a non-existent file |
| PDF exports validated | Pass — `exportPDF()` executes clean; print forced light |
| PowerShell review completed | Pass — findings recorded, no code changes |
| Veeam Advisor Fleet fully removed | Pass — zero references repo-wide |
| Feedback/Bug Fix mailto operational | Pass — header, guide, PDF |
| Colour scheme approved and implemented | Pass — approved, zero AA failures |
| No functionality removed | Pass — 62→66 functions, 50→52 ids, 94→94 labels, 18→19 PDF sections, 15→16 tabs; nothing removed |
| Parser strictly additive | Pass — 0 lost, 58 gained, 0 exceptions across 22 logs |
| CI green | Pass — 30 assertions |
| Snapshot byte-identical | Pass |
| Ready on or before 20 July 2026 | Yes — 11 days early |
