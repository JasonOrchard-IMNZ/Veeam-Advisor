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

Both parse the same VMC.log format and cover the same core infrastructure
(VSA/VBR, platform, proxies, repositories, jobs, agents, GFS/retention,
malware, security BPA). They are separate codebases rather than one shared
engine, so newer additions to one (most recently: Veeam Backup for Azure
detection, and a few licensing-consumption corrections, both in Veeam
Advisor) aren't automatically present in the other. If a finding only shows
up in one tool for the same log, that's the most likely reason — check which
tool you're using before assuming a discrepancy is a bug.

## Veeam Advisor (single-server)

Drag-drop a VMC.log → parses the environment → sizing calculator + 50+ BP
findings across 15 tabs (VSA · VBR Windows · Proxy BP · Repository · Retention ·
Replication · All Jobs · Cloud Connect · Malware · Settings · BP Review · Agents ·
Tape · Infrastructure · Licensing).

Auto-detects: VSA vs Windows VBR, platform (VMware / Hyper-V / Proxmox /
Nutanix AHV), Cloud Connect (VCSP / Tenant), proxies, repositories, all job
types, replication, agent jobs, failover plans, GFS/retention, malware events,
security BPA, MFA, config-backup encryption, Enterprise Manager, tape
infrastructure, and NIC speed. If Veeam Backup for Azure is linked in
alongside VBR, also detects its protected VM/file-share counts and
repository capacity.

Highlights:
- **Protection coverage** — compares discovered infrastructure VMs against VMs
  covered by backup jobs **and Veeam Agent backups**, flagging an estimated
  unprotected count (severity-scaled). Presented as an estimate; directs to the
  Veeam ONE Protected VMs report for the exact list.
- **Agents tab** — distinguishes Veeam Agent job types parsed from the log:
  `EpAgentBackup` (managed-by-backup-server, counted as protected machines),
  `EpAgentPolicy` (managed-by-agent policies), and legacy `EndpointBackup`.
  Validated against live v13 API ground truth.
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
- **Orphaned/disabled job detection** — jobs that create no restore points.
- **Sizing calculator** — proxy / repository / backup-server / VSA sizing with
  named constants, NIC-bandwidth modelling, GFS retention, and storage-growth
  projection. Works from a parsed log **or** manual entry.
- **PDF export** — a printable report including both the generated date and the
  data-collection date.



## Collection date/time

A VMC.log can contain several appended collection runs. Both tools select the
run with the **latest date/time** (read from the per-line `[DD.MM.YYYY …]`
timestamp, which is unambiguous across locales) and show that **collection
date/time** in the UI and the exported PDF, so you always know how current the
data is. See Calculations.txt §12 for details.

## Files

| File | Purpose |
|------|---------|
| `index.html` | Veeam Advisor — single-server app |
| `Veeam_Advisor_v1.0.2.html` | Retained v1.0.2 snapshot |
| `Veeam_Advisor_v1.0_Calculations.txt` | Sizing & methodology reference (incl. coverage, orphan, multi-run) |
| `VeeamAdvisor-PowerShell-QA.ps1` | QA harness — URL + cmdlet + BP-logic validation |
| `VeeamAdvisor-PowerShell.ps1` | Customer VBR inventory + validation (standalone) |
| `staticwebapp.config.json` | Azure SWA routing + security headers |
| `robots.txt` | Block all web crawlers |
| `.github/workflows/azure-static-web-apps.yml` | CI/CD pipeline |
| `user-guide.html` | In-app User Guide (linked from the tool header) |
| `Veeam_Advisor_v2.0.html` | Locked v2.0 snapshot (byte-identical to `index.html`) |
| `Veeam_Advisor_v1.1.0.html` | Retained v1.1.0 snapshot (CI fixture — do not modify) |
| `Veeam_Advisor_v1.0.3.html` | Retained v1.0.3 snapshot |
| `confirm-bp-findings.js` | Single-server BP Review regression assertions (v1.0.3 + v1.1.0 fixtures + 20-log corpus) |
| `.github/workflows/tests.yml` | BP Review fixture tests (CI — no customer data) |
| `CHANGELOG.md` | Version history |
| `POWERSHELL-REVIEW-v2.0.md` | v2.0 PowerShell review findings (read-only) |
| `RELEASE-NOTES-v2.0.md` | v2.0 release notes & git package |

## PowerShell scripts (5.1+ for VBR v12 / 7.4.7+ for VBR v13)

All enforce **TLS 1.2+** for HTTPS, and support connecting to a local console,
a remote VBR server, or a VSA appliance by hostname or IP — prompting for
credentials automatically when targeting a remote/VSA host. **Veeam v13 aware:**
they connect via the classic console port first and automatically fall back to
the v13 Identity Service port (443) so they work against both v12 and v13
(validated on v13.0.2.29).

```powershell
# QA harness (VeeamAdvisor-PowerShell-QA.ps1)
.\VeeamAdvisor-PowerShell-QA.ps1 -SkipModuleB                       # URLs + BP logic only, no VBR
.\VeeamAdvisor-PowerShell-QA.ps1                                    # full, on the VBR server
.\VeeamAdvisor-PowerShell-QA.ps1 -VBRServer 10.0.0.50 -ConnectionType VSA   # remote VSA by IP (prompts)

# Customer VBR inventory / validation (VeeamAdvisor-PowerShell.ps1)
.\VeeamAdvisor-PowerShell.ps1
.\VeeamAdvisor-PowerShell.ps1 -VBRServer vbr01.lab.local -Credential (Get-Credential)
```

`VeeamAdvisor-PowerShell-QA.ps1` is the developer QA harness (Module A: 72 doc
URLs; Module B: 13 VBR cmdlets; Module C: 39 BP-logic scenarios, 160+
assertions). `VeeamAdvisor-PowerShell.ps1` is the customer-facing tool — it
pulls and publishes the same data the app consumes (including a live coverage /
orphaned-job analysis). Both write timestamped results to a log file.

## Privacy

Everything is processed locally in the browser. No VMC.log is uploaded or
transmitted; log-derived values are HTML-escaped before display.

## Deployment

Azure Static Web Apps (Free tier). Push to `main` triggers auto-deploy.
App location `/` · Output location empty · Build preset Custom.

The deployed site serves `index.html`.

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
