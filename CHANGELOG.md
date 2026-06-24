# Veeam Advisor — Changelog

Notable changes to the tool are recorded here. Newest first.

## v1.0.3 — 2026-06-24

### Fixed — BP Review false positives

Five Best-Practice-Review findings shared one root-cause parsing fault: a value extracted
with a multi-colon regex and the `dom()` helper resolved to `"{ Enabled: X"` (it only strips
text up to the first colon), so a comparison like `c.encryption !== 'True'` was always true and
the finding fired regardless of the real setting. The single-server findings path was not
covered by the existing test harness (which exercises the fleet tool), which is why these
shipped. All five are corrected and validated against a 20-log corpus spanning VBR
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
  point → informational. A reference log carried 4529 ransomware-extension events with **zero**
  infected restore points — previously a "4529 confirmed threats" critical, now informational.

- **Large job (critical) — over-rated and misleading remediation.** Re-tiered by VM count:
  **>300 critical, 100–300 informational**. Removed the "enable per-VM backup files first"
  guidance — per-VM files are the modern default and are not reliably detectable from the log
  (only 4 of 20 corpus logs expose the field).

- **Repository health check (warning)** and **Deleted-VM retention (warning) — always fired.**
  Both are now evaluated per backup job by majority (same brace-optional pattern; the colon
  anchor avoids matching `FullHealthCheckEnabled`). They fire only when most jobs have the
  feature disabled. This cleared false positives on logs where the feature was actually enabled
  (MillBrook, may25-elive, wrhnbak01).

### Added

- **User Guide link** in the tool header and a **download link to the companion PowerShell
  script** (`VeeamAdvisor-PowerShell.ps1`) in the drop zone, so both are reachable directly
  from the tool. Links are relative paths that resolve on the Azure Static Web App deployment
  (where `staticwebapp.config.json` already serves `.ps1` as text and keeps `.html` addressable).

### Notes

- No change to sizing constants, infrastructure calculations, or the immutability, backup-copy,
  CBT, MFA, configuration-backup, or security/BPA checks — these were audited against the same
  corpus and confirmed correctly implemented (single-colon captures or sound multi-signal
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
  break cleanly between rows. Validated in Chrome: the CHC-PROD reference export
  dropped from 11 pages to 10 with no mid-document whitespace.

- **BPA label / URL gap.** Added four previously-unmapped Security & Compliance
  Analyzer parameters to the PDF export lookup. They had been rendering the raw
  camelCase key as the label and falling back to a bare `bp.veeam.com/vbr` link:
  - `SMB1ProtocolDisabled` → "SMBv1 disabled"
  - `BackupServicesUnderLocalSystem` → "Services run as LocalSystem"
  - `TrafficEncryptionEnabled` → "Network traffic encryption"
  - `JobsTargetingCloudRepositoriesEncrypted` → "Cloud-repo jobs encrypted"

  The lookup now resolves every BPA key present across the CHC-PROD (16-key),
  Enterprise (21), vbr-sp (22), hv-b-agent (12) and dafacom (18) reference logs —
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
