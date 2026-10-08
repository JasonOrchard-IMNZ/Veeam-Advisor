# Veeam Advisor

Created by **Jason Orchard** · Copyright © 2026 · All Rights Reserved

> **This is an unofficial, community-built tool.** It is not an official Veeam
> product and is not supported by Veeam Support. Results are estimates derived
> from a parsed log and must be validated against the
> [official Veeam calculators](https://www.veeam.com/calculators.html), the
> [Veeam Help Center](https://helpcenter.veeam.com/), and Best Practices
> documentation. For final sizing decisions, consult a Veeam SE / Solution
> Architect. The application itself carries the same disclaimer in a load-time
> banner, a persistent footer, and on every PDF export.

A standalone, single-file HTML tool for analysing Veeam `VMC.log` files —
best-practice sizing recommendations and BP/security compliance review.
Everything runs **entirely client-side**: no server runtime, and no log file
is ever uploaded or transmitted.

## Tools

| Tool | File | Use it for |
|------|------|------------|
| **Veeam Advisor** | `index.html` | Deep analysis of a **single** VBR server / VSA from one VMC.log |

(The separate multi-server Fleet View tool was removed in v2.0; Veeam Advisor
is now the only tool in this package.)

## Veeam Advisor (single-server)

Drag-drop a VMC.log → parses the environment → sizing calculator + 50+ BP
findings across 16 tabs (VSA · VBR Windows · Proxy BP · Repository · Retention ·
Replication · All Jobs · Cloud Connect · Malware · Settings · BP Review · Agents ·
Tape · Infrastructure · Licensing · Resiliency map).

Auto-detects: VSA vs Windows VBR, platform (VMware / Hyper-V / Proxmox /
Nutanix AHV), Cloud Connect (VCSP / Tenant), proxies, repositories, all job
types, replication, agent jobs, failover plans, GFS/retention, malware events,
security BPA, MFA, config-backup encryption, Enterprise Manager, tape
infrastructure, and network adapters (VMC.log records the adapter name, not its
link speed — the tool suggests a speed from the adapter type, but you should set
Proxy NIC speed manually). If Veeam Backup for Azure is linked in
alongside VBR, also detects its protected VM/file-share counts and
repository capacity.

Highlights:
- **Protection coverage** — compares discovered infrastructure VMs against VMs
  covered by backup jobs, replica jobs **and Veeam Agents**, flagging an estimated
  unprotected count (severity-scaled). When per-job VM counts are ambiguous it
  shows a range instead of a percentage. Presented as an estimate; directs to the
  Veeam ONE Protected VMs report for the exact list.
- **Agents tab** — counts agent-protected machines from `AgentBackup` jobs
  (managed by the backup server) and `AgentPolicy` jobs (managed by the agent),
  split by `ComputerType` (Server = 1 licence instance, Workstation = 0.33), plus
  standalone agents (`EndpointBackup`), which also consume an instance. The
  `[Agents] EpAgentBackup` figure is a backup-session count, not a machine count,
  and is not used. Socket (Perpetual) licences are checked against their
  6-instance agent allowance.
- **Tape tab** — detects existing tape infrastructure (servers, drives,
  libraries, GFS vs regular media pools) and sizes a single GFS tape job across
  LTO-7/8/9 (native capacity for already-compressed Veeam backups, EOM headroom).
- **Infrastructure tab** — a one-screen inventory mapping the Veeam BP design
  areas to what was parsed: backup server, config backup, proxies, repositories,
  SOBR, Enterprise Manager, tape, WAN accelerators, SureBackup, Cloud Connect,
  plug-ins, replication, plus a security posture summary (MFA / immutability /
  encryption).
- **Licensing tab** — parses the log's licence block to show instances consumed
  vs available (with a headroom gauge and renewal/expiry advisories), a
  per-workload consumption breakdown, capacity (VUL) usage where applicable, and
  an explainer of how Veeam consumes licences per workload type. Validated
  against real logs spanning 33%, 90%, and 0% consumption.
- **Security advisories (v2.3)** — the backup server build is checked against
  Veeam's published security advisories (CVE, CVSS, fixed build) and the latest
  build in KB2680, filtered by deployment type (Windows vs appliance). Data is
  embedded and dated; nothing is looked up online.
- **Fast Clone sizing (v3.0)** — repositories that report Fast Clone (ReFS/XFS) get a
  second "with Fast Clone" total next to the logical size.
- **Platform support (v3.0)** — ESXi, vCenter and Hyper-V versions from the MapCapture
  output are checked against the Help Center support pages for v12 or v13.
- **Version-correct links (v3.0)** — with the toggle on v12, Help Center links open the
  archived v12 copy of the same topic.
- **Resilience scorecard (v2.6)** — one table at the top of the BP Review tab summarising
  offsite copy, immutable/offline media, encryption, configuration backup, MFA, malware
  detection and SureBackup against the 3-2-1 rule, each linked to its finding. A summary,
  not a new score.
- **Security & Compliance Analyzer (v2.5)** — every Analyzer rule recorded in the log
  (all 70 v13 rule keys, Windows and Linux / appliance lists) is shown with Veeam's own
  title, check condition and Help Center link, including suppressed and unable-to-detect
  checks. Unknown keys are shown raw, never dropped.
- **Upgrade readiness (v2.4)** — for a v12 server, the log is checked against the
  Veeam v13 Upgrade Checklist: blockers (build below 12.3.1, support expiry), actions
  (upgrade order, CDP, hardware minimum, plug-ins, config backup) and items to verify.
  Offline; the full checklist still applies.
- **Orphaned/disabled job detection** — jobs that create no restore points.
- **Sizing calculator** — proxy / repository / backup-server / VSA sizing with
  named constants, NIC-bandwidth modelling, GFS retention, and storage-growth
  projection. Works from a parsed log **or** manual entry.
- **PDF export** — a printable report including both the generated date and the
  data-collection date.



## Collection date/time

A VMC.log can contain several appended collection runs. The tool selects the
run with the **latest date/time** (read from the per-line `[DD.MM.YYYY …]`
timestamp, which is unambiguous across locales) and show that **collection
date/time** in the UI and the exported PDF, so you always know how current the
data is. See Calculations.txt §12 for details.

## Files

| File | Purpose |
|------|---------|
| `index.html` | Veeam Advisor — single-server app |
| `Veeam_Advisor_v1.0_Calculations.txt` | Sizing & methodology reference (incl. coverage, orphan, multi-run) |
| `VeeamAdvisor-PowerShell-QA.ps1` | QA harness — URL + cmdlet + BP-logic validation |
| `VeeamAdvisor-PowerShell.ps1` | Customer VBR inventory + validation (standalone) |
| `VeeamAdvisor-MapCapture.ps1` | Read-only capture (job names, replica targets, tape sources, hypervisor versions and patch level) that enriches the Resiliency map and drives the platform support check |
| `staticwebapp.config.json` | Azure SWA routing + security headers; returns 404 for `/tools/*` and Markdown files |
| `robots.txt` | Block all web crawlers |
| `user-guide.html` | In-app User Guide (linked from the tool header) |
| `LICENSE` | Proprietary licence terms |
| `Veeam_Advisor_v3.0.html` | Locked v3.0 snapshot (byte-identical to `index.html`) |
| `Veeam_Advisor_v2.6.html` | Retained v2.6 snapshot |
| `Veeam_Advisor_v2.5.html` | Retained v2.5 snapshot |
| `Veeam_Advisor_v2.4.html` | Retained v2.4 snapshot |
| `Veeam_Advisor_v2.3.html` | Retained v2.3 snapshot |
| `Veeam_Advisor_v2.2.1.html` | Retained v2.2.1 snapshot |
| `tools/build-advisories.mjs` | Release-time refresh of the embedded security-advisory data (run by the maintainer, not the browser) |
| `tools/build-links.mjs` | Release-time check of every Help Center / KB link against the knowledge-service topic index; writes the v12 link map |
| `tools/release-refresh.mjs` | Runs both scripts above and reports drift in the platform matrix, Analyzer keys and upgrade minimums |
| `.github/workflows/refresh-advisories.yml` | Daily scheduled refresh: opens a pull request when Veeam publishes a new advisory or build |
| `Veeam_Advisor_v2.2.html` | Retained v2.2 snapshot |
| `Veeam_Advisor_v2.1.01.html` | Retained v2.1.01 snapshot |
| `Veeam_Advisor_v2.1.html` | Retained v2.1 snapshot |
| `Veeam_Advisor_v2.0.html` | Retained v2.0 snapshot |
| `Veeam_Advisor_v1.1.0.html` | Retained v1.1.0 snapshot (CI fixture — do not modify) |
| `Veeam_Advisor_v1.0.3.html` | Retained v1.0.3 snapshot |
| `Veeam_Advisor_v1.0.2.html` | Retained v1.0.2 snapshot |
| `confirm-bp-findings.js` | Single-server BP Review regression assertions (v1.0.3 + v1.1.0 fixtures + reference logs) |
| `fixtures.js` | Synthetic (fabricated) tape-parser log fixtures for the v2.1.01 tape tests |
| `audit.sh` | Anonymisation audit — checks deliverables for customer-identifying data |
| `.github/workflows/tests.yml` | BP Review fixture tests (CI — no customer data) |
| `CHANGELOG.md` | Version history |
| `POWERSHELL-REVIEW-v2.0.md` | v2.0 PowerShell review findings (read-only) |
| `RELEASE-NOTES-v3.0.md` | v3.0 release notes |
| `RELEASE-NOTES-v2.0.md` | v2.0 release notes & git package |

## PowerShell scripts (Windows PowerShell 5.1+ for VBR v12 / PowerShell 7 for VBR v13)

Veeam PowerShell v13 requires PowerShell 7; the current v13 documentation
specifies **PowerShell 7.6.3 or later** on the machine running the session.

All enforce **TLS 1.2+** for HTTPS, and support connecting to a local console,
a remote VBR server, or a VSA appliance by hostname or IP — prompting for
credentials automatically when targeting a remote/VSA host. **Veeam v13 aware:**
in v13, `Connect-VBRServer` defaults to port **443**; v12 uses the classic
console port **9392**. `VeeamAdvisor-PowerShell.ps1` and
`VeeamAdvisor-PowerShell-QA.ps1` try the given port and then fall back to the other one;
`VeeamAdvisor-MapCapture.ps1` defaults to 443 and falls back to 9392
(validated on v13.0.2.29).

```powershell
# QA harness (VeeamAdvisor-PowerShell-QA.ps1)
.\VeeamAdvisor-PowerShell-QA.ps1 -SkipModuleB                       # URLs + BP logic only, no VBR
.\VeeamAdvisor-PowerShell-QA.ps1                                    # full, on the VBR server
.\VeeamAdvisor-PowerShell-QA.ps1 -VBRServer <vsa-host> -ConnectionType VSA   # remote VSA by IP (prompts)

# Customer VBR inventory / validation (VeeamAdvisor-PowerShell.ps1)
.\VeeamAdvisor-PowerShell.ps1
.\VeeamAdvisor-PowerShell.ps1 -VBRServer vbr01.lab.local -Credential (Get-Credential)
```

`VeeamAdvisor-PowerShell-QA.ps1` is the developer QA harness (Module A: the
Help Center / BP reference URLs the tool links to; Module B: 13 VBR cmdlets;
Module C: 39 BP-logic scenarios, 160+ assertions). `VeeamAdvisor-PowerShell.ps1` is the customer-facing tool — it
pulls (via Veeam PowerShell cmdlets) the same data the app consumes (including a live coverage /
orphaned-job analysis). Both write timestamped results to a log file.

## Release: refresh and verify embedded data

Before each release, refresh and verify the embedded data (Node 18+, no dependencies):

```bash
node tools/release-refresh.mjs index.html    # advisories + link map, then drift checks
node confirm-bp-findings.js                  # regression checks
```

`release-refresh.mjs` runs `build-advisories.mjs` (security advisories, KB2680) and
`build-links.mjs` (every Help Center / KB link checked against the knowledge-service topic
index; v12 link map rewritten), then compares the hand-maintained tables — supported
platform ranges, Analyzer keys, v13 upgrade minimums — with the current Help Center pages.
Exit code 2 means something needs a maintainer's review. Use `--check` to verify without
writing.

## Keeping the patch & vulnerability check current

The security advisories and latest builds are embedded in the page, so they only change when
the data is refreshed. `.github/workflows/refresh-advisories.yml` does that automatically:

- **Daily**, on GitHub's runners, it runs `tools/release-refresh.mjs --stamp-after=30`.
- **When Veeam publishes a new advisory or build**, it opens one pull request
  (`auto/refresh-advisories`, updated in place by later runs) listing the new advisories,
  CVSS scores and builds, plus any warnings that need a maintainer (an advisory the parser
  cannot read, drift in the platform/Analyzer/upgrade tables, a broken link). The
  regression tests and `audit.sh` run first; the locked version snapshot is kept identical
  to `index.html`.
- **When nothing changed**, nothing happens; the data date is re-stamped (one small PR) at
  most every 30 days, so the page's "advisory data is N days old" warning appears only if
  the job stops running.
- Merge the pull request to deploy the new data. The page itself still never connects to
  anything.

One-time setup: *Settings → Actions → General → Workflow permissions* → enable **Allow
GitHub Actions to create and approve pull requests**. Run it on demand from the *Actions*
tab (*Refresh security advisories → Run workflow*).

The script reads the public Veeam security advisories and KB2680 from
knowledge.veeamiq.com. It exits with code 2 and a WARNING for any v12/v13
advisory it cannot parse — add that article to the `MANUAL` table in the script
(citing the KB) rather than ignoring it. Copy the updated `index.html` to the
version snapshot as usual.

## Privacy

Everything is processed locally in the browser. No VMC.log is uploaded or
transmitted; log-derived values are HTML-escaped before display. The page
carries `connect-src 'none'` (meta tag and hosted CSP), so the browser blocks
any network request it might make. Reference data such as the Veeam security
advisories is embedded at release time (see *Release: refresh and verify embedded data*),
never fetched while the tool is in use.

## Deployment

Azure Static Web Apps (Free tier). Push to `main` triggers auto-deploy via the
Azure-generated GitHub Actions workflow (created in the repository by Azure when
the Static Web App is linked; it is not included in this package).
App location `/` · Output location empty · Build preset Custom.

The deployed site serves `index.html`.

Because the app location is the repository root, every file is published. The
`routes` in `staticwebapp.config.json` return 404 for `/tools/*` (the release scripts)
and Markdown files (`README.md`, `CHANGELOG.md`, release notes), so those are not served.
Other repository files (PowerShell scripts, snapshots, tests) remain downloadable.

## Author

Created by **Jason Orchard**.

## Copyright & License

Copyright © 2026 Jason Orchard. **All Rights Reserved.**

This software is **proprietary and confidential**. It is the intellectual
property of Jason Orchard and is protected by copyright and other applicable
laws. No part of this software or its documentation may be copied, reproduced,
modified, distributed, published, or used in any form without the prior express
written permission of the author. See the [LICENSE](LICENSE) file for full
terms.
