# Veeam Advisor — Changelog

Notable changes to the tool are recorded here. Newest first.

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
