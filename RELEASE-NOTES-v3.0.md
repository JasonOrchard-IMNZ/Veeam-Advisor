# Veeam Advisor v3.0 — Release Notes

**Released:** 1 October 2026 · **Type:** Major release · **Previous version:** v2.6

---

## Summary

v3.0 completes the ten-item enhancement plan. Every feature still runs entirely in the
browser: the Veeam data each check needs is embedded in the page at release time, and the
page's Content-Security-Policy (`connect-src 'none'`) blocks any network request. Results
remain estimates for review, not official Veeam figures.

| Release | What it added |
|---|---|
| v2.3 | Security-advisory check for the detected build (CVE, CVSS, fixed build); network lockdown |
| v2.4 | v12 → v13 upgrade readiness against the Veeam Upgrade Checklist |
| v2.5 | All 70 Security & Compliance Analyzer rules in Veeam's wording, including suppressed and unable-to-detect results |
| v2.6 | Resilience scorecard: offsite copy, immutability, encryption, configuration backup, MFA, malware detection, SureBackup |
| **v3.0** | Fast Clone sizing · platform support · version-correct links · release-time link check and drift check · regression fixtures |

## New in v3.0

**Fast Clone sizing.** Repositories that report Fast Clone (ReFS block cloning, XFS
reflink) show a second total, *with Fast Clone*, next to the logical repository size.
Synthetic fulls and synthetic GFS fulls on those volumes reference blocks already on disk
(Help Center: *Fast Clone*), so each is counted as the changes since the previous full,
capped at a full. Active fulls are not cloned and stay full size. The logical size is still
the planning figure.

**Platform support.** VMC.log does not record hypervisor versions. Run the updated
`VeeamAdvisor-MapCapture.ps1` (read-only; new Section 7) and load its output with the log:
the Infrastructure tab then checks each ESXi, vCenter and Hyper-V host against the
supported versions for VBR v12 or v13, and BP Review flags unsupported hosts. Versions the
tool cannot read are marked *Check*, never guessed. The captured patch level also settles
security fixes that keep the same build number.

**Version-correct links.** With the version toggle on v12, Help Center links open Veeam's
archived v12 copy of the same page where one exists.

**Release tooling** (run by the maintainer, never by the page):

```bash
node tools/release-refresh.mjs index.html   # refresh advisories + link map, then drift checks
node confirm-bp-findings.js [logs-folder]   # regression suite (86 synthetic assertions)
```

- `tools/build-links.mjs` checks every Help Center and KB link against the knowledge-service
  topic index (75 + 13 links, all valid at release) and prints each link's page title so
  wrong-page links stand out.
- `tools/release-refresh.mjs` also reports drift in the embedded platform matrix, Analyzer
  rule list and v13 upgrade minimums.

## Files

### Changed
- `index.html` — v3.0 features, links normalised, version labels
- `VeeamAdvisor-MapCapture.ps1` — new read-only Section 7 (host versions, build, patch level)
- `VeeamAdvisor-PowerShell-QA.ps1` — Module A defers Help Center / KB links to `build-links.mjs`
- `confirm-bp-findings.js` — layer 1g (v3.0)
- `README.md`, `CHANGELOG.md`, `user-guide.html`, `audit.sh`, `.github/workflows/tests.yml`

### Added
- `Veeam_Advisor_v3.0.html` — locked snapshot, byte-identical to `index.html`
- `tools/build-links.mjs`, `tools/release-refresh.mjs`
- `RELEASE-NOTES-v3.0.md` — this file

## Before deploying

1. Run `node confirm-bp-findings.js <your-reference-logs-folder>` — the synthetic suite
   passes, but the new checks have not yet been run against real customer logs.
2. Run the updated `VeeamAdvisor-MapCapture.ps1` once on a v12 and a v13 server and load
   the output: confirm Section 7 lists the hosts with versions (property names can differ
   between builds; anything unreadable shows as `n/a` and is reported as *Check*).
3. `bash audit.sh` — confirms that none of the shipped files contain customer-identifying data.
