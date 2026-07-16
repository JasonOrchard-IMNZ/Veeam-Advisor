# Veeam Advisor — Changelog

Notable changes to the tool are recorded here. Newest first.


## v2.0 — 2026-07-09

### Added

#### MapCapture.ps1 remote server & credential support
The capture script now accepts `-VBRServer <host>`, `-Port <n>` and `-Credential` so it can be run
from a management workstation against a remote VBR server, instead of only locally. With no
`-VBRServer` it behaves exactly as before (local-first: cert-bound machine name on 443, then
localhost:443, then localhost:9392). When a remote host is given on the default port 443 it also
falls back to 9392 for a v12 remote. Still read-only (zero write cmdlets).

#### Cloud Connect provider relationship panel on the map
When a PowerShell capture shows the server hosts Cloud Connect tenants, the Resiliency map now
renders a provider panel: each tenant and the provider repository its data lands in (e.g. tenant
"end" -> SP repository), plus the cloud gateway. It states plainly that the tenant's backup jobs run
on the tenant's own VBR and are not in this server's data, so it shows the tenant->repository
relationship rather than implying job-level topology it cannot see. The panel appears only for a
server that actually hosts tenants.

#### capture Sections 2 and 4 now enrich the map
Previously only Sections 1, 3 and 5 of a PowerShell capture were consumed. Now:
- **Section 2 (job -> repository, ground truth):** each job's real IncludedSize replaces the
  log-inferred size, and where the log's target repository disagrees with the server's
  TargetRepositoryId the map flags it (per-job and as a summary warning).
- **Section 4b (configuration backup):** the config-backup job is enriched with its real name,
  encryption state and last result.
- **Sections 4c/4d (Cloud Connect provider):** when the captured server hosts tenants, the map
  notes it as a Cloud Connect provider with its tenant and gateway counts.
All parsing is block-scoped to its section and degrades gracefully on older captures that predate
these sections. Without a capture, behaviour is unchanged.

#### Backup Map tab
A new tab renders the job → repository → repository topology as a diagram, plus a matching
table and a PDF page.

**The linkage was already in the log**, under asymmetric field names that are easy to miss:

| Job type | Target field | Source field |
|---|---|---|
| `Type: Backup` | `BackupRepository: <guid>` | — |
| `Type: BCSMPolicy` (backup copy) | `RepositoryID: <guid>` | `SourceBackupJobs: [<guid>…]` |

There is no `BackupRepositoryID` or `TargetRepositoryID` field anywhere in the reference logs. Across
the 22 logs, 496 of 512 storage-bearing jobs declare a target repository, and **every target
that is a real GUID resolves to a parsed repository**.

Three defects in the source data that the parser has to survive:

- **GUID case is inconsistent.** Some logs write `SourceBackupJobs` in upper case while `JobID`
  is lower case. A raw string comparison resolved zero of one environment's 54 copy edges.
  Every id is normalised.
- **`00000000-0000-0000-0000-000000000000` is a sentinel** meaning "no destination configured",
  not a missing repository. It never becomes a node.
- **A job's fields are spread across collection passes.** The pass carrying the repository
  reference wins. `jobRecords` deliberately keeps its existing first-occurrence-wins semantics,
  so the map uses a separate parser rather than altering values the job tables depend on.

**The diagram shows job flow.** Every job that writes to a repository is drawn as its own node,
in a column immediately left of its target — so each arrow is a short hop rather than a long
diagonal. Backup copy relationships then run between the repository columns.

Job nodes are drawn only while they stay legible. Above 40 jobs the job column is dropped and
the repository boxes carry aggregate counts instead; a large production log can carry well over a hundred jobs, and those
chips is not a diagram. The threshold is reported on the tab and in the PDF rather than being
silent.

**Replica destinations are drawn as an explicit unknown.** A replica's `BackupRepository` is the
metadata repository, not the destination. Pointing an arrow from a replica job at that
repository implied the replicated VM landed there, which it does not. `VMC.log` records **no
target host, datastore or cluster** for a replica job — only `TargetHVPlatform`, `IsCloudTarget`,
`ReplicaType` and `TargetProxy`. Replicas therefore draw a dashed *metadata* edge into the
repository and a solid edge into a destination node labelled "not named in VMC.log", grouped by
Cloud Connect vs on-premises and by platform.

Also worth recording: in every reference log that has replicas, the metadata repository is
`88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec` — Veeam's built-in Default Backup Repository GUID, byte-identical across every environment. That
is the built-in Default Backup Repository, present on every VBR install. The tool now says so
rather than presenting it as a deliberate placement.

**Replica jobs are on the map.** They were initially excluded on the assumption that a replica
targets a host rather than a repository. That assumption was wrong: all 216 replica jobs in the
reference set carry `BackupRepository`, and every one resolves. A replica writes its metadata and
digests there — the VM data lands on the target host — so replicas are drawn with a dashed
border and their `IncludedSize` is excluded from the repository's primary data, alongside the
existing exclusion of copy-job size. `FailoverPlan` and `SureBackup` genuinely carry no
repository and remain excluded.

**Canvas height fits the content.** Width stays fixed at 1080; height starts at a 360 px
minimum and grows with the diagram (a large estate reaches ~1740 px). The
earlier fixed 1600 px floor left a three-repository map floating in a mostly empty canvas.

Accounting decisions that materially change the numbers:

- **Edges count distinct copy jobs, not job references.** A copy job may name many source jobs
  on the same edge; incrementing per pair multiplied both the job count and the byte total by
  the fan-out, reporting more data on one arrow than the whole estate holds.
- **A copy job's `IncludedSize` is the same data its source job already counted.** Copy volume
  is reported separately as *Copied in* rather than added to the repository's primary data.

**Backup copy topologies can contain cycles** — a repository that copies out and receives a
return copy. Lane assignment uses Kahn's algorithm over the acyclic part, then breaks each cycle
by promoting its entry node and resuming the sort. Relaxing through a cycle instead saturates,
and lane compaction then folds the whole component into one lane, which turns ordinary forward
edges into false "return copy" arrows. Return copies render as dashed amber arrows.

**The diagram is a 1080-wide canvas, expanding downward only.** Width is the fixed dimension.

*Width is fixed.* Lane width always divides the 1080. The arrow gutter is derived from the lane
rather than held constant, so the box width is `lane − gutter` and is strictly narrower than its
lane — adjacent lanes can never overlap, however many copy hops the estate has. Beyond about
seven lanes the boxes become too narrow to carry full labels; the map reports that it is
compressed, suppresses the right-aligned size (kept in the tooltip and the table), and clips the
remaining labels with an ellipsis.

*Height expands to fit.* Repository boxes are a fixed 64 px and job chips 40 px; each repository
is given a block tall enough for its own jobs and centred against it. The canvas grows to
whatever that needs, with a 360 px floor.

**The diagram is drawn on demand.** The tab renders its summary, table and findings
immediately, but the SVG is built only when the user presses *Draw map*. A large estate
produces roughly 21 KB of SVG at about 600×1600, and forcing the browser to lay that out on
every upload costs more than it is worth for a tab most sessions never open. The button yields
once before building so its state paints, and it recovers cleanly if the build throws.

Findings surfaced: idle repositories (configured but targeted by no job — 12 of 24 in one
environment, 14 of 38 in another), absence of any backup copy flow, return copy cycles,
unresolvable copy sources, jobs with no destination, and tape jobs excluded because they target
media pools rather than repositories.

Declared limits: `VMC.log` never records job names, so nodes are labelled by repository and job
GUIDs are shown as 8-character prefixes. In one environment 220 backup copy source references
name jobs the log never enumerates; those arrows cannot be drawn and the count is reported.

#### expandable per-repository job detail
The Backup map's repository table is now interactive: click any repository row to expand the
individual jobs writing to it, each with full detail — job ID or captured name, type, platform,
source data, retention, encryption, schedule and last result. This is independent of the diagram's
40-job threshold, so on a large estate where the diagram shows aggregate counts,
you can still drill into any one repository's jobs. The PDF export now lists jobs grouped by
repository the same way, replacing the previous flat table that was suppressed above 40 jobs.

#### optional PowerShell capture enrichment for the Backup Map
`VMC.log` cannot record three things the Backup Map wants: job names (it stores GUIDs only),
replica target hosts (it stores nothing), and whether a replica points at a host that still
exists. The `VeeamAdvisor-MapCapture.ps1` companion collects exactly these from a live VBR
server. Uploading its output alongside the log now enriches the map.

Drop the capture `.txt` on the same drop zone as the log, in either order. The tool detects the
format, and:

- **Job nodes show real names** — "Backup Job 2", "Replication Job 1" — instead of GUID prefixes.
- **Replica destinations resolve to real hosts.** Where VMC.log could only say "not named in
  VMC.log", the capture supplies the real target host and path, drawn with a solid
  border instead of dashed.
- **Replica jobs targeting a deleted host are flagged.** If the capture resolved a job's target
  host id to "not found", the destination is drawn in red and a finding warns that the job is
  configured against infrastructure that no longer exists and would fail to run.

On the Backup map tab, a panel now offers a one-click **Download MapCapture.ps1** and an **Upload capture output** control, so the whole round-trip happens from the tab itself; the script is served by the deployment (staticwebapp.config.json already excludes .ps1 from the SPA fallback). The User Guide gains a dedicated Backup map section (9a) covering the diagram and the capture workflow.

The enrichment is safe by construction. It is entirely optional — the map is unchanged without
it. Job IDs are the join key, so a capture from a different server (no IDs in common) is detected
and ignored with a notice rather than applied. Nothing is fabricated: a field the capture did not
resolve falls back to the log-only rendering.

#### MTU on the Network Interfaces panel
`VMC.log` records `MTU` on an indented continuation line inside each `Network Interface`
block. It is now parsed and shown as a column alongside adapter, status and inferred speed.

The value is read only from the interface's **own** block — bounded by the next
`Network Interface,` header — so an adapter that omits `MTU` cannot inherit the value from
the interface that follows it. Interfaces with no recorded MTU show an em dash; an adapter
reporting `MTU: -1` shows *unknown*.

Findings added:

- **Reduced MTU** (below 1500) — normally a VPN or overlay tunnel; backup traffic across the
  path fragments and throughput drops.
- **Jumbo frames** (9000+) — informational, with the caveat that every device in the path must
  use the same MTU or a single 1500-byte hop silently fragments the traffic.
- **Mixed MTU** across interfaces — prompts a check that backup and storage paths are
  consistent end-to-end.
- **Consistent MTU** — confirmation when all interfaces agree.

Across the reference logs, 23 of 35 detected interfaces record an MTU; all are 1500.

#### Feedback & Bug Fix Requests
A `mailto:` link is added to the tool header, the User Guide header, and the PDF export header.


### Changed

#### "Backup map" tab renamed to "Resiliency map"
The tab is now called **Resiliency map**, reflecting what it is really for: seeing how well
protected the estate is — idle repositories, jobs with no second copy, 3-2-1 gaps, copy loops —
rather than just its structure. Only the user-facing label changed (tab, headings, PDF page,
guide); the underlying data, capture format, and behaviour are unchanged.

Major release. A repository-parsing rebuild grounded in a forensic audit of 22 production
`VMC.log` files, a full retro arcade re-theme, removal of Fleet View, and a set of
accessibility fixes. Reconciliation of the repository list against the log's own
authoritative type summary improved from **9/22 to 17/22 exact matches**.

#### PDF export now includes the diagram without drawing it first
Previously the PDF's Backup map page only carried the drawn diagram if the user had opened the
Backup map tab and pressed Draw; otherwise it fell back to tables only. Export now rasterises the
map itself (off-screen) before building the PDF, so the diagram image is always present. If the
map is already drawn, the cached image is reused with no re-render; if there is no map, or the
browser blocks the canvas, it falls back to the tables as before.

#### Retro arcade colour scheme
The palette is drawn from a supplied 1990s arcade reference. Cabinet-black header with a neon
accent rule, monospace display font on headings, and borders lifted from 0.5px to 1px.

- All **22 hardcoded hex colours** across the tool are replaced with tokens.
- Semantic tokens (`--green`, `--amber`, `--red`, `--purple`, `--blue`) resolve to the
  **text-safe** stop. An audit showed they are used overwhelmingly as `color:` (amber 24 of 27
  sites; red 25 of 28), and every `background:` site pairs them with white text — which the
  deep stops serve at 6.4:1 or better. Bright arcade hues remain available as `--arcade-*`
  for chrome where contrast is not load-bearing.
- Four tint backgrounds (`--gl`, `--al`, `--rl`, `--pl`) have no equivalent in the supplied
  palette and are lightened from their source hue. Each is validated against its paired text
  stop. `--bl` uses the supplied `#e8f8ff`.
- **Zero WCAG AA failures** in light or dark mode. Dark mode is retained and retuned.

#### Sub-terabyte repositories
Repositories under 0.1 TB displayed `0.0 TB`. They now display GB / MB. Empty object-storage
repositories display *empty* rather than an em dash.

#### PDF export
The report header now carries the tool version and the feedback contact. The disclaimer banner
is restyled to the arcade palette. PDF output remains light mode.


### Fixed

#### MapCapture.ps1 ignored -VBRServer when a local session existed
When run with `-VBRServer <remote>` while a local VBR session was already active (e.g. the Veeam
console open on the workstation), the script reused that local session — capturing localhost
instead of the requested remote host. An explicit `-VBRServer` now takes precedence: the existing
session is reused only if it is already to the requested host; otherwise the script disconnects it
and connects to the host you asked for. Without `-VBRServer`, any local session is reused as before.

#### provider panel now uses the log's authoritative tenant data; capture replica undercount
Two related fixes after comparing the map against the VBR console:
- The Cloud Connect provider panel drew its tenant detail from the PowerShell capture, which
  under-reported replica resources (showed 0 while the console and the VMC.log both show 1). The
  panel now reads the VMC.log's [Tenants] line as the authoritative source for each tenant's
  backup, replica, server and workstation counts and type, and enriches with the capture's
  friendly repository name where available. It also renders regardless of whether a capture was
  loaded, so a provider log alone (including STARTLOGSEXPORT exports that carry the [Tenants] line)
  now shows the panel with backup/replica counts, hardware-plan counts and the gateway.
- The capture script's tenant "Replica resources" count read a property that returned 0 on this
  Veeam version. It now probes the ReplicaResources / ReplicaResource collections and falls back
  to Get-VBRCloudTenantResource, and lists the assigned hardware-plan names — matching the
  console's Replica Resources view. Still read-only (zero write cmdlets).

#### Cloud Connect provider not detected in log-export files
A VMC.log produced by "Export Logs" (STARTLOGSEXPORT) stops after the license block and omits the
[Cloud Connect Infrastructure] line the Cloud Connect tab relied on to set provider status — so a
genuine provider was shown as "Cloud Connect is not configured". The license block's CCProvider: Yes
flag was parsed but never used for this. Provider status now falls back to that flag when the
infrastructure line is absent (promote-only, so an explicit infrastructure line still wins, and a
CCProvider: No / absent flag never promotes). The tab notes when detection came from the license
flag alone and points to a full VMC.log or MapCapture.ps1 for tenant and gateway detail.

#### repository boxes not enriched with real names from a capture
The capture's Section 1 lists each repository's real name (e.g. Default Backup Repository, Veeam
Vault), but the map only ever read job data from the capture — so repository boxes kept showing
their type (WinLocal, VeeamDataCloudObjStgVersion2) instead of the real name after an upload. The
capture parser now reads Section 1, scoped strictly to the REPOSITORIES block so it can't pick up
Section 2's similarly-shaped job lines, and the map matches those names to the repository nodes on
full GUID. When enriched, the box heading and the tables show the real name with the type kept as a
subtitle; without a capture, behaviour is unchanged (type shown as before).

#### Repository parser (major)
The repository-definition gate previously required optional companion fields
(`ConcurrentTaskLimit`, `RepositoryGroupType`, a numeric `TotalSpace`). Repository types that
legitimately omit them were silently dropped — no error, no warning, just missing rows.

The gate is rebuilt to anchor on the definition line's invariant shape,
`RepositoryID: <guid>, Type: <type>`, and to accept whatever space field is present. The
word-boundary anchor excludes `CacheRepositoryID` / `ObjectStorageID` / `GatewayHostID` and
job-line repository references, so the change is strictly more precise, not merely broader.

Recovered:

- **`VeeamDataCloudObjStgVersion2`** — reports `UsedSpace` and carries
  `RepositoryGroupType: ArchiveRepository`, but has no `ConcurrentTaskLimit`, which the old
  gate required. One production log was under-reporting ~106 TiB.
- **All `*External` types** (`AzureStorageExternal`, `ExternalPlatform`, …) — carry `UsedSpace`
  and `RepositoryGroupType: ExternalRepository` but no `ConcurrentTaskLimit`.
- **Offline repositories** — `TotalSpace: null` or `-1`. Now listed and labelled *offline*
  rather than dropped.
- **`SanSnapshotOnly`** — carries no space field at all, by design (storage snapshots hold no
  backup files). Now listed with *n/a* capacity. Guarded by `RepositoryGroupType` so
  Veeam Agent schema lines (`TotalBackupsSize`) are still correctly skipped.

#### `LimitStorageConsumption` quota handling on object/archive repositories
`LimitStorageConsumption` always carries a `Value` and `Unit`, **even when `Enabled: False`**.
Veeam Data Cloud v2 repositories emit `{ Enabled: False, Value: 10, Unit: TB }` on a
repository holding 106 TiB. Reading `Value` without first testing `Enabled` would cap a
106 TiB repository at 10 TB. The parser reads the quota only when it is enabled; otherwise the
repository is treated as having no declared capacity. Across the reference logs there are 155
disabled and 33 enabled quota declarations, so this distinction is load-bearing.

Where an enabled quota **is** present, `Used` is now read from `UsedSpace` directly rather than
derived as `total − free`. Because `free` clamps at zero, the derived figure would report the
quota rather than actual consumption once a repository exceeds its limit — a repository holding
106 TiB against a 10 TB quota would have displayed `10.0 TB`. Repositories over their configured
limit are now shown in red with an explanatory tooltip.

The quota regex also tolerates the escaped `\{` brace form for consistency with the summary-line
parser.

#### PDF map image missing on large estates unless redrawn; button wording
On a large estate (over ~120 jobs) the PDF's Backup map page came out tables-only unless
the user had pressed the map button first. Two causes: the map raster was never cached during the
on-screen draw (only an export-time off-screen rasterise existed, which could be tainted or race
the print), and `window.print()` fired before the embedded image data-URL had decoded. Now the
draw caches the PNG from the live on-screen SVG (the reliable path), a cold export triggers that
same draw and waits for it, and printing waits for the embedded image to finish loading (bounded
by a timeout). The map button now reads **Draw map** consistently rather than switching to
"Redraw map" after the first draw.

#### replica destination edges dropped after a capture upload
After a PowerShell capture enriched the map, the arrows from replica jobs to their destination
nodes disappeared (the destination boxes floated unconnected). The destination-node key was
derived in two places — the node builder and the edge drawer — with identical logic. Enrichment
re-keyed the nodes from the platform-based fallback (`onprem|WinServer…`) to a host-based key
(a host-based key, e.g. `host|<name>` or `deleted|<id>`), but the edge drawer still computed the old key, so its lookup
missed and the edges were silently skipped. Both now call a single shared `bmReplicaKey()`, so the
edges follow the nodes in every enrichment state. Verified: edge count preserved across upload on
both a tenant capture and a Cloud Connect provider capture.

#### PDF export did nothing; PNG export failed silently
Two defects in the map export path, both now fixed:

- **Export PDF button did nothing.** `exportPDF()` referenced `_bmMapPng` (the cached map image
  for the PDF page), but that global's declaration had been lost in an earlier edit — only its
  uses remained. Reading an undeclared variable throws a `ReferenceError` before `window.print()`
  is reached, so the button silently failed. The declaration is restored; all reference logs now
  export cleanly.
- **PNG export flashed an error and produced nothing.** The generated `<svg>` root carried no
  `xmlns` attribute. It renders on screen (the browser supplies the namespace implicitly) but a
  namespace-less SVG cannot be parsed by `new Image()`, so rasterising to PNG failed via
  `onerror`. The same defect would have left the PDF's embedded diagram and the SVG download
  malformed. `xmlns="http://www.w3.org/2000/svg"` is now emitted on the SVG root, with a
  serialisation guard in the export path. A PNG failure now shows a persistent, readable message
  (pointing to the SVG download) instead of a one-second toast.

#### MapCapture.ps1 console noise and agent-job coverage
A real capture run surfaced two script defects (the file output was correct throughout; these were
console-only or completeness issues). The helper functions `H` and `W` collided with PowerShell's
built-in `h` alias for `Get-History`, whose first parameter is `-Id [Int64]` — so `H "VERSION"`
emitted "Cannot bind parameter 'Id'" on the console. Renamed to `Section` and `Emit`. And
`Get-VBRJob` on v13 warns that it no longer returns computer/agent backup jobs; the script now
unions `Get-VBRComputerBackupJob` so agent jobs are captured and the warning is pre-empted. A
the capture format and workflow are documented in the user guide.

#### Repository type summary read the wrong collection pass
`VMC.log` repeats its `Repository types:` summary on every collection pass. The tool matched
the **first** occurrence, so a repository added between passes was under-counted. It now reads
the **last** summary, and repository rows are scoped to the final completed enumeration pass so
repositories removed between passes no longer linger.

#### Escaped-brace summary lines
Some exported logs escape the summary's opening brace as `\{`, which defeated the regex and
produced a zero repository-type count. The pattern now tolerates it.

#### False-positive immutability findings
The "immutability disabled" finding no longer fires on offline repositories, capacity-less
repositories, or External repositories. Immutability on an External repository is governed by
the native cloud tool that created the backups, not by Veeam.

#### Accessibility (pre-existing contrast failures)
- Retention table headers rendered *Monthly* in `var(--amber)` at **2.2:1** and *Yearly* in
  `var(--purple)`. Both now use text-safe stops.
- The `DR` job category was hardcoded to `#E24B4A`, byte-identical to the `--red` token it
  should always have used.

#### PDF/print output could inherit dark-mode colours
`exportPDF()` emits `var(--bdk)`, `var(--pdk)`, `var(--rd)`, `var(--bd)` and `var(--tx3)` into
the report body, and the `@media print` block forced a white background without resetting the
token values. A user whose operating system was set to dark mode would therefore export a PDF
with pale blue and salmon text on a white page (about 1.5:1) and near-invisible table borders.

`@media print` now re-asserts the full light-mode `:root` token set, so print output is light
regardless of OS preference. The same reset is applied to `user-guide.html`, where the defect
was pre-existing: printing the guide from a dark-mode OS produced dark code blocks and tint
backgrounds on a white page.


### Removed

#### Fleet View
`Veeam_Advisor_Fleet.html` is removed from the package, along with `confirm-outputs.js` (which
existed solely to load and assert against the Fleet codebase and was not part of CI). All
references are stripped from `README.md`, `user-guide.html` and
`Veeam_Advisor_v1.0_Calculations.txt`. The User Guide's section 12 is removed and sections 13
and 14 renumbered.

Changelog history above this entry is left intact: Fleet View was a real part of those releases.


### Known limitations

#### (unchanged, now reported rather than hidden)
Three of the 22 audited logs count repositories in the type summary that the log never
enumerates anywhere — no definition line, no `ExtentsIDs` membership, no job reference
(`WinLocal` ×4 and `ExternalPlatform` ×1 across DRGVMBKP1, Richo and procare). No row can be
constructed for these. The parser is correct; the source data is incomplete.

An earlier working theory held that scale-out repository **extents** lacked definition lines.
This was disproved during the audit: `ExtentsIDs` resolves cleanly to enumerated repository
rows in every case.


### Notes

#### PowerShell (review only, no code changes)
`VeeamAdvisor-PowerShell.ps1` enumerates repositories with a bare `Get-VBRBackupRepository`,
which returns neither scale-out repositories (`-ScaleOut`) nor external repositories
(`Get-VBRExternalRepository`). This is the same class of blind spot corrected in the log
parser this release. Recorded for a future release; no changes made in v2.0.

## v1.1.0 — 2026-06-26

Feature release: three enhancements (per-job-type breakout, agent licence reconciliation,
perpetual sockets), plus a coverage-accuracy correction that fell out of the agent work.
Validated against the same reference logs (VBR **12.1 / 12.2 / 12.3 and 13.x**, RTF and plain,
VMware / Hyper-V / agent / Cloud Connect, instance and perpetual licences).

### Added — Per-job-type breakout (All jobs + Retention tabs)

Every configured job in `CURRENT JOBS INFO` is classified by its `Type:` into a friendly common
name — **Backup Job, Backup copy job, Agent backup, Agent backup (mgmt), SureBackup (scan only),
SureBackup (virtual labs), Config backup, Other** — and **encryption, GFS and retention are broken
out per type**.

- The **All jobs** tab gains a *Jobs by type* table (count · encryption · GFS · retention) above
  the existing per-category detail.
- The **Retention** tab gains a *Retention by job type* table covering all job types, including
  copy and agent jobs that the per-job GFS table doesn't.
- Retention reads `RetentionPolicy` (VM backup) and `RetentionSettings` (replica / copy / agent),
  both `{ Value, Unit }`, with a brace-optional pattern so RTF-stripped logs match. Records are
  de-duped by `JobID` (definition line wins).

### Added — Agent licence reconciliation (Agents tab, rebuilt)

The Agents tab is rebuilt on a corrected agent model and now **cross-checks detected agents against
the licence**:

- **Managed agents** are counted from `AgentBackup` + `AgentPolicy` jobs by their `ComputerType`:
  a **Server** agent = 1 licence instance, a **Workstation** agent = 0.33 (three workstations = one
  instance, rounded up). These reconcile against the `AgentsServer` / `AgentsWorkstation` instances
  in the LICENSE block.
- **Standalone `EndpointBackup` agents are now correctly recognised as licence-consuming** — the
  previous build assumed they were free, which was wrong (an estate with zero managed agents but a
  consumed Workstation instance is accounted for by its standalone agent).
- **Perpetual (socket)** estates are shown as socket-covered; the per-instance agent check is
  skipped because sockets cover agents.
- **BP Review** gains a warning when more server agents are detected than licensed (instance
  licences only).

### Changed — Coverage accuracy (agent-protected machines)

The agent count feeding the **protection-coverage estimate** now uses the real agent machine count
(**managed Server + Workstation + standalone**) instead of the `[Agents] EpAgentBackup` figure,
which is an agent-backup **operation / session count** — e.g. **62** on an estate with ~1 real agent
— and wrongly excluded `EndpointBackup`. Coverage percentages on agent-heavy logs shift to more
accurate values, and the Agents tab badge now reflects machines, not operations.

### Added — Perpetual sockets (Licensing tab)

Socket-based (**Perpetual**) licences now display **socket consumption** — sockets licensed,
sockets in use, and a **per-platform breakdown** (sockets and workloads per hypervisor) —
alongside the existing instance and capacity views. The figures are read from the authoritative
per-platform `UsedSockets` structure (`"Name": "<plat>", "UsedSockets": N, "TotalWorkloadsNumber":
M`), which is keyed by platform name and therefore covers VMware / Hyper-V / Nutanix / Proxmox /
any hypervisor — unlike the flat `SocketsViInUse` / `SocketsHvInUse` summary fields, which exist
only for VMware and Hyper-V (a socket estate on a third platform would be undercounted by the flat
fields). The flat fields are retained as a fallback for heavily RTF-stripped logs. Validated across
all perpetual reference logs; the per-platform socket totals reconcile exactly with the flat
summary on every one.

### Changed — BP Review encryption finding is now per job type

The encryption finding is evaluated per job type, so unencrypted **Backup copy** jobs (and other
types) are surfaced, not only primary VM backup jobs. Critical for primary/copy data, warning for
the rest.

### Fixed — render-path field wiring (forensic audit)

A full audit of the render path — every `d.X` the renderer/tab functions read versus the object
`render()` actually receives — found and fixed all field-name mismatches, so every documented
feature now renders:

- **The v1.1.0 render features themselves** (per-job-type breakout, agent reconciliation,
  perpetual sockets) and the per-type encryption finding are now forwarded into the render
  object. They were computed on the data object but not passed to `render()`, so none of them
  displayed and unencrypted backups were no longer being flagged.
- **Tape capacity estimate** (Tape tab) now renders. It read `d.tb` / `d.retention` /
  `d.gfsWeekly|Monthly|Yearly`, which the render object provides as `dataTB` / `ret` /
  `gfsW|gfsM|gfsY`; the size gate therefore always failed and the tab always showed the
  "upload a log" prompt even with tape data present.
- **Infrastructure tab**: "Backup proxies" now shows the proxy count (`d.proxies` →
  `detectedProxies`) and "Replication" shows the job count (`d.replJobs` → `replicationJobs`).
- **BP Review**: the "WAN Accelerators deprecated" advisory now fires (`d.v13` → `vbrV13`).
- **Cloud Connect** provider label (`d.isProvider` → `d.cloudConnect.isProvider`) and the
  appliance "sized vCPU / RAM" suffix (`d.bsCPU` / `d.bsRAM` → `bsCPUact` / `bsRAMact`) now
  resolve to their correct fields.

Verified by a render-path audit that reports zero remaining field mismatches, and by rendering
every affected tab through the actual `render()` object across the reference logs.

### PDF export — v1.1.0 feature parity

The Export PDF report previously contained only the sizing sections and predated the v1.1.0
feature work. It now includes the v1.1.0 additions so the exported report matches the on-screen
tool:

- **Infrastructure** page — full inventory (backup server, proxies, repositories, SOBR,
  Enterprise Manager, tape, WAN accelerators, SureBackup, Cloud Connect, plug-ins, and
  **replication**) plus a security-posture summary (MFA, immutability, encryption), mirroring
  the on-screen Infrastructure tab.
- **Licensing** page — edition / type / state / expiry, plus perpetual **socket consumption**
  (per-platform sockets + workloads), **instance consumption**, and **capacity (VUL)** licensing.
- **Agents** — the licence cross-check (managed server / workstation + standalone, with the
  per-instance reconciliation table, or the perpetual-socket note).
- **Jobs by type** — per-type encryption / GFS / retention breakout.
- **Tape capacity estimate** — single GFS tape job (native LTO-9) with the full math table.

The Best Practice Review section already reflected v1.1.0, as it renders from the shared
findings. The export reads only fields present in the render object (verified by the same
render-path audit), and `exportPDF()` runs clean across the reference logs.

### Unchanged

Sizing constants and the infrastructure, immutability, backup-copy, CBT, MFA, config-backup, malware,
health-check, deleted-VM, and security / BPA checks are unchanged from v1.0.3.

---

## v1.0.3 — 2026-06-24

### Fixed — BP Review false positives

Five Best-Practice-Review findings shared one root-cause parsing fault: a value extracted
with a multi-colon regex and the `dom()` helper resolved to `"{ Enabled: X"` (it only strips
text up to the first colon), so a comparison like `c.encryption !== 'True'` was always true and
the finding fired regardless of the real setting. The single-server findings path was not
covered by the existing test harness (which exercises the fleet tool), which is why these
shipped. All five are corrected and validated against a reference logs spanning VBR
**12.1 / 12.2 / 12.3 and 13.x**, RTF and plain text, and VMware / Hyper-V / agent / Cloud Connect
deployments.

- **Backup encryption (critical) — false positive on fully-encrypted estates.** Encryption is
  now read only from VM/disk backup-job lines using a brace-*optional* pattern
  (`Encryption:\s*\{?\s*Enabled:\s*(True|False)`) so RTF-stripped logs — where `stripRTF` removes
  all braces — still match. Tape jobs (which use `IsEncryptionEnabled`) and repository-level
  encryption (on `RepositoryID` lines) are excluded by the job-line scoping. The finding now
  fires only when a job is genuinely unencrypted, reports **"N of M jobs"**, and stays silent
  when there are no backup jobs (Cloud Connect / replica-only / orchestrator logs).

- **Malware (critical) — false positive on benign extension noise.** Severity is now gated on
  infected / suspicious **restore points** (`OIBsInfectedCount` / `OIBsSuspiciousCount`, summed
  across ManuallyChecked + DetectedByVeeam) instead of raw event counters. Confirmed infection →
  critical; suspicious restore points → warning; scan events with no infected/suspicious restore
  point → informational. A reference log carried thousands of ransomware-extension events with **zero**
  infected restore points — previously a "thousands of confirmed threats" critical, now informational.

- **Large job (critical) — over-rated and misleading remediation.** Re-tiered by VM count:
  **>300 critical, 100–300 informational**. Removed the "enable per-VM backup files first"
  guidance — per-VM files are the modern default and are not reliably detectable from the log
  (only some reference logs expose the field).

- **Repository health check (warning)** and **Deleted-VM retention (warning) — always fired.**
  Both are now evaluated per backup job by majority (same brace-optional pattern; the colon
  anchor avoids matching `FullHealthCheckEnabled`). They fire only when most jobs have the
  feature disabled. This cleared false positives on logs where the feature was actually enabled
  (across several reference environments).

### Added

- **User Guide link** in the tool header and a **download link to the companion PowerShell
  script** (`VeeamAdvisor-PowerShell.ps1`) in the drop zone, so both are reachable directly
  from the tool. Links are relative paths that resolve on the Azure Static Web App deployment
  (where `staticwebapp.config.json` already serves `.ps1` as text and keeps `.html` addressable).

### Notes

- No change to sizing constants, infrastructure calculations, or the immutability, backup-copy,
  CBT, MFA, configuration-backup, or security/BPA checks — these were audited against the same
  reference set and confirmed correctly implemented (single-colon captures or sound multi-signal
  boolean logic, not the `dom()` fault).
- `index.html` is byte-identical to `Veeam_Advisor_v1.0.3.html` (deploy convention unchanged).

## v1.0.2 — 2026-06-21

### Security

- **Defense-in-depth XSS hardening.** A crafted VMC.log could inject HTML/JS into the
  rendered report through free-text fields parsed with permissive patterns (machine /
  host name, replication source / target, gateway type, NIC status, version strings).
  Closed on three layers:
  - *Source-side scrubber* — all log-parsed strings are neutralised at the parse
    boundary (angle brackets stripped from every string; quotes and backslash also
    stripped from GUID / ID fields) before any rendering, so every render path is safe
    independent of downstream escaping. Numbers, booleans, structure and legitimate
    values (names, versions, dates, GUIDs) are untouched.
  - *Output escaping* — every log-derived value written to `innerHTML` is now
    HTML-escaped at the point of render across the main report, the tape table, the PDF
    export and the details summary box. Clears the CodeQL `js/xss-through-dom` alerts.
  - *Handler-context fix* — the clickable "copy ID" cells embed an identifier inside an
    inline `onclick`; a crafted ID containing a quote could break out of the JS string.
    Fixed by stripping quotes from ID fields and tightening the `ComponentID` /
    `HostID` captures from `[^"]+` to a GUID-safe `[\w-]+`.

  Audit confirmed no `eval` / `Function` / `document.write` / `insertAdjacentHTML`
  code-execution sinks, no log-derived `href` / `src` URLs, and no exploitable
  prototype-pollution path. The tool continues to make zero network calls and carry
  zero external script dependencies.

### Fixed

- **Parse exception handling.** File loading now wraps the parser in `try / catch` and
  adds a FileReader `onerror` handler. A malformed or unreadable file previously threw
  an uncaught exception and left the UI silently half-loaded; it now surfaces a clear
  message and flags the drop zone, with no loss of state.

### Notes

- No changes to sizing constants, calculations or analysis logic — legitimate logs
  parse and render identically to v1.0.1. `index.html` and `Veeam_Advisor_v1.0.2.html`
  remain byte-identical.

## v1.0.1 — 2026-06-20

### Fixed

- **PDF export pagination.** Removed `page-break-after: always` from the four
  `.pdf-page` report sections. A section whose content overflowed a physical page
  still forced the break, leaving large blank gaps — most visibly ~75% of the page
  after the "Proxy sizing" table. The report now flows as a continuous document.
  Added `break-after: avoid` on section headings (kept with their tables) and
  `break-inside: avoid` on stat cards, findings, and table rows so atomic blocks no
  longer split across a page boundary. Long tables (per-job retention, BPA) still
  break cleanly between rows. Validated in Chrome: a large reference export
  dropped from 11 pages to 10 with no mid-document whitespace.

- **BPA label / URL gap.** Added four previously-unmapped Security & Compliance
  Analyzer parameters to the PDF export lookup. They had been rendering the raw
  camelCase key as the label and falling back to a bare `bp.veeam.com/vbr` link:
  - `SMB1ProtocolDisabled` → "SMBv1 disabled"
  - `BackupServicesUnderLocalSystem` → "Services run as LocalSystem"
  - `TrafficEncryptionEnabled` → "Network traffic encryption"
  - `JobsTargetingCloudRepositoriesEncrypted` → "Cloud-repo jobs encrypted"

  The lookup now resolves every BPA key present across the full set of reference logs —
  0 unmapped.

### Added

- **Server identity.** The machine / host name parsed from the VMC.log header is
  now surfaced in the report metadata line (e.g. "Server: FNLCHCA-VBR").

### Notes

- Image-only, oversized PDF output is a **print-destination artefact, not a tool
  bug**. "Microsoft Print to PDF" rasterises the page (no text layer, ~2.7 MB).
  Export via Chrome → **"Save as PDF"** for a vector, searchable, ~4× smaller file
  (~660 KB on the same report). Both methods produce an identical layout.
- Sizing constants are unchanged from v1.0; `Veeam_Advisor_v1.0_Calculations.txt`
  remains the current calculations reference.

## v1.0 — 2026-06-08

- Initial production release. VMC.log parser (114/114 parser assertions across 11
  real-world logs); sizing calculator for proxy / repository / backup server / VSA
  with named constants, NIC bandwidth modelling, GFS retention and storage growth
  projection; 11 analysis tabs; 30+ best-practice findings sourced from
  bp.veeam.com/security and bp.veeam.com/vbr; companion PowerShell cmdlet suite.
