#!/usr/bin/env node
// v3.0 fixes from the 2026-10 deep audit. Every test runs the REAL application code from
// index.html (via tests/harness.js) on synthetic logs from tests/synth.js. No customer data.
'use strict';
const h = require('./harness');
const s = require('./synth');

let pass = 0, fail = 0; const fails = [];
function T(name, ok, info) { if (ok) pass++; else { fail++; fails.push(name + (info !== undefined ? '  -> ' + JSON.stringify(info) : '')); } }

// Parse + calculate; returns { c, d (render data), f (findings), html(id) }.
function full(text, opts) {
  const c = (opts && opts.ctx) || h.load();
  let cap = null; const r0 = c.render;
  c.render = d => { cap = d; return r0(d); };
  h.analyse(c, text, (opts && opts.fname) || 'VMC.log');
  if (opts && opts.before) opts.before(c);
  h.run(c, 'calculate()');
  c.render = r0;
  const f = cap ? c.buildFindings(cap) : [];
  return { c, d: cap, f, D: c.D, has: re => f.some(x => re.test(x.title)), find: re => f.find(x => re.test(x.title)) };
}
module.exports.full = full;

// ── H10: a second log must not inherit the first log's form values ─────────────
(function () {
  const c = h.load();
  h.analyse(c, s.log({ extraTop: [s.TS + '[VMware Infrastructure] ProxyServers: 6'] }));
  c.document.getElementById('proxyExist').value = '6';                      // as sf() would leave it
  c.document.getElementById('proxyExist').classList.add('af');
  h.analyse(c, s.log({ vms: 10 }));                                        // second log, no proxy count
  const el = c.document.getElementById('proxyExist');
  T('H10 second log clears values the new log lacks', el.value === '' && !el.classList.contains('af'), el.value);
  T('H10 second log fills its own VM count', String(c.document.getElementById('vmCount').value) === '10');
})();

// ── H11: the cached map picture is dropped when a new log is parsed or Reset ───
(function () {
  const c = h.load();
  h.run(c, '_bmMapPng="data:image/png;base64,AAAA"');
  h.analyse(c, s.log({}));
  T('H11 new log clears the cached map picture', h.run(c, '_bmMapPng') === null);
  h.run(c, '_bmMapPng="data:image/png;base64,AAAA"; resetAll()');
  T('H11 Reset clears the cached map picture and the parsed log', h.run(c, '_bmMapPng') === null && h.run(c, 'D.vbr') === null && h.run(c, '_lastRenderData') === null);
})();

// ── H1: immutability switched off everywhere must not pass as "immutability active" ──
(function () {
  const so = n => s.repo({ id: n, type: 'HPStoreOnceIntegration', extra: ' ImmutabilitySettings: { Enabled: False, Value: 7, Unit: Days },' });
  const r = full(s.log({ jobs: [s.backupJob({ repo: 50 })], repos: [so(50), so(51)] }));
  T('H1 StoreOnce "Enabled: False, Value: 7" everywhere -> cur.immutability False', r.D.cur.immutability === 'False', r.D.cur.immutability);
  T('H1 no "Repository immutability active" pass', !r.has(/immutability active/i));
  const hard = full(s.log({ repos: [s.repo({ id: 50, type: 'LinuxHardened', extra: ' ImmutabilitySettings: { Enabled: False, Value: 7, Unit: Days },' })] }));
  T('H1 hardened repo with immutability explicitly off is not immutable', hard.D.cur.immutability === 'False' && hard.D.encPosture.reposImmut === 0, hard.D.encPosture);
  const on = full(s.log({ repos: [s.repo({ id: 50, type: 'LinuxHardened', extra: ' ImmutabilitySettings: { Value: 14, Unit: Days },' })] }));
  T('H1 hardened repo with 14 days is immutable', on.D.cur.immutability === 'True' && on.D.encPosture.reposImmut === 1);
  const bleed = full(s.log({ repos: [s.repo({ id: 50, type: 'LinuxLocal', extra: ' ImmutabilitySettings: null, RWrateLimit: { Enabled: True, Value: 1 },' })] }));
  T('M13 immutability "Enabled" is not read from the next block on the line', bleed.D.repoList[0].immut !== true, bleed.D.repoList[0].immut);
  const none = full(s.log({ repos: [s.repo({ id: 50, type: 'LinuxLocal' })] }));
  T('M14 no immutability field -> unknown (null), not off', none.D.repoList[0].immut === null);
})();

// ── H4: a full repository (FreeSpace: 0) is 100% used ─────────────────────────
(function () {
  const r = full(s.log({ repos: [s.repo({ id: 50, free: 0 })] }));
  T('H4 FreeSpace 0 -> 100% used', r.D.repoList[0].used_pct === 100, r.D.repoList[0].used_pct);
  const t = full(s.log({ repos: [s.repo({ id: 50, extra: ' ConcurrentTaskLimit: { Enabled: False, Number: 4 },' }), s.repo({ id: 51 })] }));
  T('M12 task limit switched off is unlimited; absent is unknown', t.D.repoList.find(x => x.id === s.S(50)).tasks === -1 && t.D.repoList.find(x => x.id === s.S(51)).tasks === null);
})();

// ── H2: an incomplete newest run must not win run selection ──────────────────
(function () {
  const good = s.log({ vms: 40, date: '01.10.2026' });
  const trunc = ['Starting new log', 'Product: [Veeam Backup and Replication], Version: [12.3.2.4854]', 'CmdLineParams: [STARTCOLLECTINFRASTATISTIC]',
    '[02.10.2026 10:00:00.000]    <18>    Info (3)    =======================LICENSE INFORMATION=========================='].join('\n');
  const r = full(good + '\n' + trunc);
  T('H2 truncated newest run skipped; complete run used', r.D.vms === 40 && r.D.repoList.length === 1, { vms: r.D.vms });
  T('H2 skipped run is reported', !!r.D.skippedRun && r.has(/Newest collection run was incomplete/));
  const noHdr = s.log({ vms: 40, version: '12.2.0.334' }) + '\n' + s.log({ vms: 99, version: '12.3.1.1139', date: '05.10.2026', header: false });
  const r2 = full(noHdr);
  T('M5 a run appended without a header is still the newest run', r2.D.vms === 99 && r2.D.vbr === '12.3.1.1139', { vms: r2.D.vms, vbr: r2.D.vbr });
  const onlyMarkers = s.log({ header: false, version: '12.3.1.1139' });
  T('M4 run bounded on its marker keeps its version header', full(onlyMarkers).D.vbr === '12.3.1.1139');
  const osFirst = s.log({}).replace('Product: [Veeam', 'OS: [Windows Server], Version: [10.0.20348]\nProduct: [Veeam');
  T('L19 VBR build read from the Product line', full(osFirst).D.vbr === '12.3.2.4854');
})();

// ── H3: an RTF-wrapped log parses the same as the plain text ─────────────────
(function () {
  const plain = s.log({ repos: [s.repo({ id: 50, type: 'LinuxHardened', extra: ' ImmutabilitySettings: { Value: 7, Unit: Days },' }),
    s.repo({ id: 51, type: 'HPStoreOnceIntegration', extra: ' ImmutabilitySettings: { Enabled: True, Value: 14, Unit: Days },' })],
    extraTop: [s.TS + 'Repository types: { LinuxHardened: 1, HPStoreOnceIntegration: 1 }', s.TS + 'ProxmoxVMs: { Count: 7 }'] });
  const rtf = '{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0 Courier New;}}{\\colortbl;\\red0\\green0\\blue0;}\\f0\\fs18 ' +
    plain.replace(/\\/g, '\\\\').replace(/\{/g, '\\{').replace(/\}/g, '\\}').split('\n').join('\\par\n') + '}';
  const a = full(plain), b = full(rtf, { fname: 'VMC.rtf' });
  const sig = r => JSON.stringify({ vbr: r.D.vbr, vms: r.D.vms, repos: r.D.repoList.map(x => [x.id, x.type, x.immut, x.immutDays]), types: r.D.repoTypeCounts, imm: r.D.cur.immutability });
  T('H3 RTF log parses the same as plain text', sig(a) === sig(b), { plain: sig(a), rtf: sig(b) });
  const esc = full(plain.replace(/\{/g, '\\{').replace(/\}/g, '\\}'));
  T('H3 plain text with RTF brace escapes parses the same', sig(esc) === sig(a), sig(esc));
})();

// ── H5: older backup copy jobs (Type: Backup, JobSourceType: Backup) are copies ──
(function () {
  const copy = s.backupJob({ id: 9, repo: 51, src: 'Backup' });
  const r = full(s.log({ jobs: [s.backupJob({ id: 1, repo: 50 }), copy], repos: [s.repo({ id: 50 }), s.repo({ id: 51 })] }));
  T('H5 legacy copy job counted as a backup copy', r.D.jobCounts.BackupCopy === 1 && r.D.cur.backupCopy === 'True', r.D.jobCounts);
  T('H5 no "No backup copy" critical', !r.has(/No backup copy configured/));
  const bt = {}; (r.D.jobsByType || []).forEach(t => { bt[t.common] = t.count; });
  T('H5 job table: 1 backup job + 1 backup copy job', bt['Backup Job'] === 1 && bt['Backup copy job'] === 1, bt);
  const n51 = ((r.D.backupMap || {}).nodes || []).find(n => n.id === s.G(51)) || {};
  T('H5 map counts it as a copy into its repository, not a backup', n51.counts && n51.counts.copy === 1 && n51.counts.backup === 0, n51.counts);
})();

// ── H6: coverage counts only scheduled jobs ──────────────────────────────────
(function () {
  const r = full(s.log({ vms: 10, jobs: [s.backupJob({ id: 1, vms: 10, sched: false })] }));
  T('H6 a disabled job protects nothing', r.D.protectedVMs === 0 && r.D.coveragePct !== 100, { prot: r.D.protectedVMs, pct: r.D.coveragePct });
  const ok = full(s.log({ vms: 10, jobs: [s.backupJob({ id: 1, vms: 10 })] }));
  T('H6 an enabled job still counts', ok.D.protectedVMs === 10);
})();

// ── H7: SureBackup count comes from jobs, not the session counter ─────────────
(function () {
  const r = full(s.log({ extraTail: [s.TS + '[SureBackup] SureBackupLite: 40'] }));
  T('H7 40 SureBackup sessions with no SureBackup jobs -> 0 jobs', r.D.surebackup === 0, r.D.surebackup);
  T('H7 no "SureBackup jobs exist but no Virtual Labs" warning', !r.has(/SureBackup jobs exist but no Virtual Lab/i));
  const sb = `${s.TS}PlatformId: ${s.ZERO}, PlatformName: [VMware], JobID: ${s.G(7)}, Type: SureBackupLite, JobSourceType: [VDDK], ScheduleEnabled: True,`;
  const r2 = full(s.log({ jobs: [s.backupJob({}), sb], extraTail: [s.TS + '[SureBackup] SureBackupLite: 40'] }));
  T('H7 one SureBackup job -> 1', r2.D.surebackup === 1, r2.D.surebackup);
})();

// ── H8: v11 and older builds are end of life, not v13 ────────────────────────
(function () {
  const r = full(s.log({ version: '11.0.1.1261' }));
  T('H8 v11 build is not treated as v13', h.run(r.c, 'VBR_V13') === false && r.d.vbrV13 === false);
  T('H8 v11 build gets an end-of-life critical', (r.find(/end of life/) || {}).sev === 'crit');
  T('H8 no "VBR v13 on Windows" pass for a v11 build', !r.has(/VBR v13 on Windows/));
  T('H8 13.x still v13', h.run(full(s.log({ version: '13.0.1.2067' })).c, 'VBR_V13') === true);
})();

// ── H9: "Backup encryption" rows read job encryption, not the config backup flag ──
(function () {
  const conf = `${s.TS}PlatformId: ${s.ZERO}, PlatformName: Configuration, JobID: ${s.G(4)}, Type: ConfBackup, IsEnabled: True, ScheduleEnabled: True, Platform: EConf, RetentionPolicy: 10, StorageEncryptionEnabled: True,`;
  const r = full(s.log({ jobs: [s.backupJob({ id: 1, enc: false }), s.backupJob({ id: 2, enc: false }), conf] }));
  const html = r.c.infraTab(r.d);
  const row = (html.match(/<b>Backup encryption<\/b><\/td><td class="cell-val">([^<]*)/) || [])[1];
  T('H9 Infrastructure tab: backup encryption shows the jobs (0 of 2), not the config backup', /Disabled \(0 of 2 jobs\)/.test(row || ''), row);
  const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'index.html'), 'utf8');
  T('H9 PDF row uses the same job-encryption state', /iRow\('Backup encryption',jobEncState\(d\)/.test(src));
})();

// ── MapCapture: the parser reads what VeeamAdvisor-MapCapture.ps1 prints ──────
(function () {
  const c = h.load();
  const G1 = s.G(1), G2 = s.G(2), R = s.G(50), C = s.G(3), pad = (x, n) => String(x).padEnd(n);
  const txt = ['Veeam Advisor Backup Map capture', 'Host: LAB-VBR-01   Date: 2026-10-08',
    '==', '  1. REPOSITORIES  (simple + scale-out + object storage + external)', '==',
    'Object storage repositories: 1', '  ' + pad(R, 38) + ' ' + pad('AmazonS3', 28) + ' Lab S3',
    '  ' + pad(s.G(51), 38) + ' n/a (null)  Lab Archive',
    '==', '  2. JOB -> REPOSITORY  (x)', '==',
    pad(G1, 38) + ' ' + pad('Backup', 22) + ' ' + pad('False', 9) + ' ' + pad(R, 38) + ' VM job', '    repo name : Lab S3', '    size      : 100',
    pad(G2, 38) + ' ' + pad('VBRComputerBackupJob', 22) + ' ' + pad('False', 9) + ' ' + pad('n/a', 38) + ' Agent job', '    repo name : (unresolved)',
    pad(C, 38) + ' ' + pad('BackupSync', 22) + ' ' + pad('False', 9) + ' ' + pad(R, 38) + ' Copy job', '    repo name : Lab S3',
    '==', '  3. REPLICA TARGET HOST', '==',
    "  Job 'Cloud replica' Id: " + s.G(4), '    GetTargetHost() : n/a (null)', '    TargetHostId : ' + s.ZERO,
    '==', '  4b. CONFIGURATION BACKUP', '==', "  Config backup 'Configuration Backup'", '    Enabled : True', '    Repository Id : ' + R, '    Encryption : True', '    RestorePoints : 10',
    '==', '  4c. CLOUD CONNECT', '==', '  Main Gateway   host: 203.0.113.5 port: 6180',
    '==', '  5. JOB NAME <-> JOB ID', '==', 'JobId,JobName,JobType,IsReplica', `${G1},VM job,Backup,False`, `${G2},Agent job,VBRComputerBackupJob,False`, `${C},Copy job,BackupSync,False`,
    'Backup server build : 11.0.1.1261'].join('\n');
  T('Capture: ASCII header detected', c.isMapCapture(txt));
  const cap = c.parseMapCapture(txt);
  T('Capture: agent and copy jobs named (Section 5)', cap.jobs[G2] && cap.jobs[G2].name === 'Agent job' && cap.jobs[C] && cap.jobs[C].name === 'Copy job');
  T('Capture: agent line does not overwrite the previous job (Section 2)', cap.jobTargets[G1].repoName === 'Lab S3' && cap.jobTargets[G2].targetRepoId === null);
  T('Capture: object-storage repo listed; "n/a (null)" type keeps the name', cap.repoNames[R].name === 'Lab S3' && cap.repoNames[s.G(51)].name === 'Lab Archive');
  T('Capture: config backup without an Id is parsed', cap.configBackups.length === 1 && cap.configBackups[0].encryption === true && cap.configBackups[0].restorePoints === 10);
  T('Capture: zero-GUID replica target is not a deleted host', cap.replicaHosts[s.G(4)].deletedHost === null);
  T('Capture: gateway name with spaces kept', cap.cloudConnect.gateways.length === 1 && cap.cloudConnect.gateways[0].name === 'Main Gateway');
  T('Capture: any build number is read', cap.bsBuild === '11.0.1.1261');
  const fs = require('fs'), path = require('path');
  const ascii = ['VeeamAdvisor-MapCapture.ps1', 'VeeamAdvisor-PowerShell.ps1', 'VeeamAdvisor-PowerShell-QA.ps1']
    .every(f => !/[^\x00-\x7F]/.test(fs.readFileSync(path.join(__dirname, '..', f), 'latin1')));
  T('H13 PowerShell scripts are pure ASCII (parse in Windows PowerShell 5.1)', ascii);
})();

// ── KB4902 / KB4840 (2026-10-05 KB recheck) ────────────────────────────────────
(function () {
  const c = h.load();
  const hit = h.run(c, 'vaBuildCheck("13.0.2.29",false)').hits.find(x => x.kb === 'kb4902');
  T('KB4902 affected build carries the credential clean-up', !!hit && /Application-Aware Processing/.test(hit.afterFix || ''), hit);
  T('KB4902 clean-up does not mark the build as "verify"', hit && hit.verify === false);
  const fixed = h.run(c, 'vaBuildCheck("13.1.0.411",false)');
  T('KB4902 fixed build still gets a clean-up reminder', fixed.afterFix.length === 1 && fixed.afterFix[0].kb === 'kb4902');
  T('KB4902 not raised for v12', h.run(c, 'vaBuildCheck("12.3.2.4854",false)').afterFix.length === 0);
  const r = full(s.log({ version: '13.1.0.411' }));
  T('KB4902 reminder finding on a fixed v13 build', (r.find(/KB4902 clean-up/) || {}).sev === 'i');
  const r2 = full(s.log({ version: '13.0.2.29' }));
  T('KB4902 action in the missing-fixes finding', /Application-Aware Processing/.test(JSON.stringify(r2.find(/missing security fixes/) || {})));
  const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'index.html'), 'utf8');
  const bp = (src.match(/BackupServerUpToDate:\[[^\n]*/) || [''])[0];
  T('KB4840 update check covers Windows from 13.1', /Windows-based servers from 13\.1/.test(bp) && /kb4840/.test(bp), bp.slice(0, 120));
})();

// ── Parser root causes, round 1: infrastructure, job count, source TB, retention, GFS ──
(function () {
  const TB = 1099511627776;
  // p1#7: a brace-less Hyper-V line must not borrow the VMware VM count
  let r = full(s.log({ vms: 40, extraTop: [s.TS + '[Hyper-V Infrastructure] Hosts: 0, Clusters: 0'] }));
  T('P1-7 Hyper-V line does not bleed into the VMware line', r.D.vms === 40, r.D.vms);
  // p1#8: VMware clusters from the log, unknown when absent
  r = full(s.log({ extraTop: [s.TS + '[VMware Infrastructure] VirtualMachines: 40, HostSystems: 5, Clusters: 2'] }));
  T('P1-8 VMware clusters read from the log', r.D.clusters === 2 && r.D.hosts === 5, [r.D.hosts, r.D.clusters]);
  r = full(s.log({}));
  T('P1-8 VMware clusters unknown when absent', r.D.clusters === null, r.D.clusters);
  // p1#9/#10: job count from job records, not session counters; all platforms
  r = full(s.log({ extraTop: [s.TS + '[Backup] VDDKBackup: 340'], jobs: [s.backupJob({ id: 1 }), s.backupJob({ id: 2, plat: 'HyperV', src: 'HyperV' })] }));
  T('P1-10 job count ignores session counters and counts every platform', r.D.jobs === 2, r.D.jobs);
  // p1#21: platform presence without a VM count does not add a VM
  r = full(s.log({ vms: 40, extraTail: [s.TS + 'PlatformName: Nutanix, TotalBackupFilesCount: 250'] }));
  T('P1-21 Nutanix presence does not invent a VM', r.D.vms === 40, r.D.vms);
  // p1#15: EpAgentBackup counter is not AgentBackup
  r = full(s.log({ jobs: [], extraTop: [s.TS + '[Agents] EpAgentBackup: 5'] }));
  T('P1-15 EpAgentBackup is not read as AgentBackup', !r.D.jobCounts.AgentBackup && !r.D.agentJobs, [r.D.jobCounts.AgentBackup, r.D.agentJobs]);
  // p2#10: source TB from primary backup jobs only, by job
  const repl = s.TS + `PlatformId: ${s.ZERO}, PlatformName: VMware, JobID: ${s.G(9)}, Type: Replica, IncludedSize: ${3 * TB}, ScheduleEnabled: True, VMsCount: 2, RetentionPolicy: { Value: 7, Unit: Points },`;
  const repl2 = repl.replace(s.G(9), s.G(10));
  const copy = s.backupJob({ id: 8, src: 'Backup', size: 2 * TB });
  r = full(s.log({ jobs: [s.backupJob({ id: 1, size: TB }), copy, repl, repl2] }));
  T('P2-10 source TB counts primary backups only', r.D.tb === 1, r.D.tb);
  r = full(s.log({ jobs: [s.backupJob({ id: 1, size: TB }), s.backupJob({ id: 2, size: TB })] }));
  T('P2-10 two equal-size jobs both count', r.D.tb === 2, r.D.tb);
  // p2#11: retention from primary jobs, with units
  r = full(s.log({ jobs: [s.backupJob({ id: 1 }), repl, repl2] }));
  T('P2-11 retention from backup jobs, not replicas', r.D.retention === 14, r.D.retention);
  r = full(s.log({ jobs: [s.backupJob({ id: 1 }).replace('Value: 14, Unit: Points', 'Value: 3, Unit: Months')] }));
  T('P2-11 retention in months is converted to days', r.D.retention === 90 && /3 Months/.test(r.D.retentionLabel || ''), [r.D.retention, r.D.retentionLabel]);
  // p2#12: no invented 14-day default
  r = full(s.log({ jobs: [s.backupJob({ id: 1 }).replace(/RetentionPolicy: \{[^}]*\}, /, '')] }));
  T('P2-12 no retention in the log leaves it unknown', r.D.retention === null && r.D.gfsDaily === null, [r.D.retention, r.D.gfsDaily]);
  // p2#13: GFS weeks only from jobs with weekly GFS enabled
  r = full(s.log({ jobs: [
    s.backupJob({ id: 1, extra: ' WeeklyGFS: { Enabled: True, KeepBackupsForNumberOfWeeks: 4 },' }),
    s.backupJob({ id: 2, extra: ' WeeklyGFS: { Enabled: False, KeepBackupsForNumberOfWeeks: 52 },' })] }));
  T('P2-13 disabled weekly GFS does not set the weeks kept', r.D.gfsWeekly === 4, r.D.gfsWeekly);
  // p2#16: an active container job with data is not "No VMs assigned"
  r = full(s.log({ jobs: [s.backupJob({ id: 1, vms: 0, size: 2 * TB })] }));
  T('P2-16 container job with data is not orphaned', !r.D.orphanedJobs.some(o => /No VMs/.test(o.reason)), r.D.orphanedJobs);
  r = full(s.log({ jobs: [s.backupJob({ id: 1 }).replace(/VMsCount: \d+, /, '')] }));
  T('P2-16 job without a VMsCount field is not orphaned', !r.D.orphanedJobs.some(o => /No VMs/.test(o.reason)), r.D.orphanedJobs);
  // p2#32: active full inside a settings block
  r = full(s.log({ jobs: [s.backupJob({ id: 1, extra: ' ActiveFullSettings: { Schedule: Monthly, Enabled: True },' })] }));
  T('P2-32 active full read from its settings block', r.D.jobGFS[0].mode === 'AF', r.D.jobGFS[0].mode);
})();

// ── Parser root causes, round 2: counters, unknown vs 0, licence, tape, agents ──
(function () {
  const rec = (id, type, extra) => s.TS + `PlatformId: ${s.ZERO}, PlatformName: VMware, JobID: ${s.G(id)}, Type: ${type}, ScheduleEnabled: True,${extra || ''}`;
  let r = full(s.log({ jobs: [s.backupJob({ id: 1 }), s.backupJob({ id: 2, src: 'Backup', sched: false })] }));
  T('P2-5 disabled copy job is not an offsite copy', r.D.cur.backupCopy === 'False', r.D.cur.backupCopy);
  r = full(s.log({ jobs: [s.backupJob({ id: 1 }), rec(3, 'CdpPolicy')], extraTop: [s.TS + '[Other] CdpPolicy: 120'] }));
  T('P2-17 CDP policies from job records, not counters', r.D.cdpPolicies === 1, r.D.cdpPolicies);
  r = full(s.log({ extraTop: [s.TS + 'HostName: VEEAMONE01'] }));
  T('P2-18 a host named VEEAMONE is not "Veeam ONE: No"', r.D.veeamOne === null, r.D.veeamOne);
  r = full(s.log({ extraTop: [s.TS + 'IsVeeamONEConnected: True'] }));
  T('P2-18 Veeam ONE connected flag read', r.D.veeamOne === true, r.D.veeamOne);
  r = full(s.log({}));
  T('P2-20 no malware line gives unknown, not 0', r.D.malwareEvents === null, r.D.malwareEvents);
  T('P2-22 no virtual lab field gives unknown', r.D.virtualLabs === null, r.D.virtualLabs);
  r = full(s.log({ jobs: [s.backupJob({ id: 1 }), rec(4, 'SureBackupLite')] }));
  T('P2-22 SureBackup Lite does not need a virtual lab', !r.has(/no Virtual Labs/), r.f.map(x => x.title).filter(t => /Virtual/.test(t)));
  r = full(s.log({ extraTail: [s.TS + '{"RecommendationName": "MfaEnabledInBackupConsole", "Status": "Violation"}', s.TS + '{"RecommendationName": "MfaEnabledInBackupConsole", "Status": "Ok"}'] }));
  T('P2-21 BPA violations use the last status per rule', !r.D.securityBPA.MfaEnabledInBackupConsole, r.D.securityBPA);
  r = full(s.log({ jobs: [s.backupJob({ id: 1 }), rec(5, 'EpAgentPolicy', ' ComputerType: Server,'), rec(6, 'EpAgentBackup', ' ComputerType: Server,')] }));
  T('P2-9 EpAgent job types count as managed agents', r.D.agentRecon.mgdServer === 2, r.D.agentRecon);
  T('P2-34 agent jobs are not "Other"', !r.D.jobsByType.some(b => b.common === 'Other'), r.D.jobsByType.map(b => b.common));
  r = full(s.log({ extraTail: ['SureBackupCapacityTier: x', s.TS + 'SOBRs: 1, CapacityTier: { Enabled: False }, ArchiveTier: { Enabled: False }'] }));
  T('P2-14 disabled capacity/archive tiers are not configured', !r.D.sobrTiers.includes('ArchiveTier'), r.D.sobrTiers);
  r = full(s.log({ extraTail: [s.TS + '[TapeLibrary] Name: L1, DrivesCount: 2', s.TS + 'Tape infrastructure: { LibrariesCount: 2, DrivesCount: 6 }', s.TS + '[TapeDrives] Model: IBM ULTRIUM-HH LTO-10'] }));
  T('P1-16 tape drives from the estate total', r.D.tapeDrives === 6, r.D.tapeDrives);
  T('P1-25 LTO-10 is not LTO-1', r.D.tapeLTO === 'LTO-10', r.D.tapeLTO);
  r = full(s.log({ extraTop: [s.TS + '[Cloud Connect Infrastructure] Gateways: 0'] }));
  T('P1-26 missing Cloud Connect flags are unknown', r.D.cloudConnect.isProvider === null && r.D.cloudConnect.isTenant === null, r.D.cloudConnect);
  // licence date reading
  const c = h.load();
  const d = h.run(c, `[vaDaysUntil("2099-12-31")>0, vaDaysUntil("31.12.2099")>0, vaDaysUntil("12/31/2099")>0, vaDaysUntil("01/01/2000")<0, vaDaysUntil("05/11/2099")>0]`);
  T('P2-19 licence dates in ISO, dotted and US/NZ forms', d.every(Boolean), d);
  T('P2-19 an ambiguous date that reads expired one way and valid the other gives no answer', h.run(c, 'var _y=new Date().getFullYear(); vaDaysUntil("03/04/"+_y)===null || Math.abs(vaDaysUntil("03/04/"+_y))>90') === true);
  r = full(s.log({ extraTail: [s.TS + 'License[1]: Type: Subscription, ExpirationDate: 2099-12-31,', s.TS + '[VBServers] LicenseExpirationDate: 01/01/2025'] }));
  T('P2-24 another product\'s LicenseExpirationDate does not override', r.D.licExpiry === '2099-12-31', r.D.licExpiry);
})();

// ── Parser round 3: repeats, YARA, proxy hardware, GFS flag ─────────────────────
(function () {
  const tape = (id, enc) => s.TS + `PlatformId: ${s.ZERO}, PlatformName: VMware, JobID: ${s.G(id)}, Type: VmTapeBackup, IsEncryptionEnabled: ${enc}, RunManually: True,`;
  let r = full(s.log({ jobs: [s.backupJob({ id: 1 }), tape(7, 'False'), tape(7, 'False')] }));
  T('P2-27 a repeated tape job line counts once', r.D.tapeEncOff === 1 && r.D.tapeManual === 1 && r.D.vmTapeJobs === 1, [r.D.tapeEncOff, r.D.tapeManual, r.D.vmTapeJobs]);
  const j1 = s.backupJob({ id: 1, enc: false });
  r = full(s.log({ jobs: [j1, j1, s.backupJob({ id: 2, src: 'Backup', enc: false })] }));
  T('P2-27 encryption counts primary jobs once', r.D.cur.encTotal === 1 && r.D.cur.encUnenc === 1, [r.D.cur.encTotal, r.D.cur.encUnenc]);
  const vbs = s.TS + `[VBServers] VBServerID: ${s.G(30)}, TotalVMsCount: 8, ProtectedVMsCount: 8,`;
  r = full(s.log({ extraTail: [vbs, vbs] }));
  T('P2-28 a repeated [VBServers] line counts once', r.D.azureBackup && r.D.azureBackup.serverCount === 1 && r.D.azureBackup.protectedVMs === 8, r.D.azureBackup);
  r = full(s.log({ extraTail: [s.TS + '{"ActivityType": "SbScanBackup", "AntivirusScanEnabled": "True"}'] }));
  T('P2-29 an antivirus scan is not reported as YARA', r.D.yaraScan === null, r.D.yaraScan);
  r = full(s.log({ jobs: [s.backupJob({ id: 1, extra: ' WeeklyGFS: { Enabled: True, KeepBackupsForNumberOfWeeks: 4 },' })] }));
  T('P2-35 GFS flag on job records from WeeklyGFS', r.D.jobRecords[0].gfs === true, r.D.jobRecords[0]);
  r = full(s.log({ extraTop: [s.TS + '{"ComponentType": "Transport", "ComponentID": "' + s.G(40) + '", "HostID": "' + s.G(41) + '", "ComponentVersion": "12.3.2.4854"}'] }));
  T('P1-11 proxy with no hardware line is not assumed virtual', r.D.proxyList.length === 1 && r.D.proxyList[0].phys === null, r.D.proxyList);
})();

// ── Sizing and findings (calc audit) ─────────────────────────────────────────────
(function () {
  const TB = 1099511627776;
  const set = (id, v) => c => { c.document.getElementById(id).value = String(v); };
  const both = (...fs) => c => fs.forEach(f => f(c));
  let r = full(s.log({}));
  T('M4 absent guest-processing field raises no "disabled" warning', !r.has(/Guest processing disabled/));
  T('M4 absent storage-latency field raises no warning', !r.has(/Storage latency control disabled/));
  r = full(s.log({ jobs: [s.backupJob({ id: 1 }), s.backupJob({ id: 2, src: 'Backup', enc: false })] }));
  T('M5 no "all encrypted" pass when a copy job is unencrypted', !r.has(/^Backup encryption enabled/));
  r = full(s.log({ vms: 200, extraTop: [s.TS + '[VMware Infrastructure] VirtualMachines: 200, HostSystems: 10', s.TS + '[Backup] ProxyServers: 3'] }));
  T('M6 one recommended proxy count across the report', r.d.recProxies === r.d.pCnt, [r.d.recProxies, r.d.pCnt]);
  r = full(s.log({ vms: 300, extraTop: [s.TS + '[VMware Infrastructure] VirtualMachines: 300, HostSystems: 10'] }), { before: set('nicSpeed', 1) });
  T('M7 300 VMs on 1 GbE does not need dozens of proxies', r.d.pCnt < 20, r.d.pCnt);
  const small = full(s.log({ vms: 20, jobs: [s.backupJob({ id: 1, size: TB, vms: 20 })] }));
  const big = full(s.log({ vms: 20, jobs: [s.backupJob({ id: 1, size: 400 * TB, vms: 20 })] }));
  T('M7 task load grows with data volume', big.d.tasksNeeded > small.d.tasksNeeded, [small.d.tasksNeeded, big.d.tasksNeeded]);
  r = full(s.log({ repos: [s.repo({ extra: ' ConcurrentTaskLimit: { Enabled: True, Number: 16 },' })] }));
  T('M10 repository CPU is 2 tasks per core', r.d.repoComputeList[0].cpu === 8, r.d.repoComputeList[0]);
  r = full(s.log({ repos: [s.repo({ type: 'LinuxLocal', extra: ' IsReFsSyntheticEnabled: True,' })] }));
  T('L6 no ReFS RAM add-on for a Linux (XFS) repository', r.d.repoComputeList[0].ramRefs === 0, r.d.repoComputeList[0]);
  const gfs2 = s.backupJob({ id: 1, size: 10 * TB, extra: ' WeeklyGFS: { Enabled: True, KeepBackupsForNumberOfWeeks: 2 },' });
  const syn = full(s.log({ jobs: [gfs2] }), { before: set('backupMode', 'synthetic') });
  const noG = full(s.log({ jobs: [s.backupJob({ id: 1, size: 10 * TB })] }), { before: set('backupMode', 'synthetic') });
  T('M11 weekly GFS points that are chain fulls add no storage', syn.d.repoTB === noG.d.repoTB, [syn.d.repoTB, noG.d.repoTB]);
  const tape = s.TS + `PlatformId: ${s.ZERO}, PlatformName: VMware, JobID: ${s.G(7)}, Type: VmTapeBackup, IsEncryptionEnabled: True,`;
  r = full(s.log({ jobs: [s.backupJob({ id: 1 }), tape] }));
  T('M12 tape lowers "no backup copy" to a warning', !r.has(/No backup copy configured/) && (r.find(/second copy relies on tape/) || {}).sev === 'warn');
  r = full(s.log({}), { before: set('nicSpeed', 2.5) });
  T('L1 2.5 GbE is read as 2.5', r.d.nicGbE === 2.5, r.d.nicGbE);
  r = full(s.log({ extraTail: [s.TS + '[TapeDrives] Model: HP Ultrium 6-SCSI'] }));
  T('M8 LTO-6 detected and in the sizing table', r.d.tapeLTO === 'LTO-6' && h.run(r.c, 'vaTapeGen(_lastRenderData)') === 'LTO-6');
  // M2: a page with no data replaces the previous report
  const c = h.load();
  c.document.getElementById('results').innerHTML = 'STALE REPORT';
  h.run(c, 'calculate()');
  T('M2 an empty calculation replaces the previous report', !/STALE/.test(c.document.getElementById('results').innerHTML) && h.run(c, '_lastRenderData') === null);
  T('L15 esc() escapes single quotes', h.run(c, 'esc("a\'b")') === 'a&#39;b');
})();

// ── UI / PDF (ui audit) ──────────────────────────────────────────────────────────
(function () {
  const TB = 1099511627776;
  const c = h.load();
  h.analyse(c, '%PDF-1.7 binary junk\nnot a log at all', 'report.pdf');
  h.run(c, 'calculate()');
  T('M7 a file that is not a VMC.log is rejected', !!c.D.notVmcLog && /Not a VMC\.log/.test(c.document.getElementById('results').innerHTML) && c.D.vms === null);
  // PDF: inventory page, source file, licence over-use
  const repl = s.TS + `PlatformId: ${s.ZERO}, PlatformName: VMware, JobID: ${s.G(9)}, Type: Replica, IncludedSize: ${TB}, ScheduleEnabled: True, VMsCount: 2,`;
  const r = full(s.log({ jobs: [s.backupJob({ id: 1 }), repl], extraTail: [s.TS + 'License[1]: { Type: Subscription, InstancesCount: { InLicense: 10, Used: 14, LicenseState: Valid } }'] }), { fname: 'site-a-VMC.log' });
  h.run(r.c, '_exportPDFNow()');
  const pdf = String(r.c.document.getElementById('pdfReport').innerHTML || '');
  T('PDF names the source log', /Log: site-a-VMC\.log/.test(pdf));
  T('PDF has the repository and replication inventory', /Inventory detail/.test(pdf) && /Replication jobs/.test(pdf) && /<th>Task limit<\/th>/.test(pdf));
  T('M3 PDF shows licence over-use, not negative availability', /Over the licence/.test(pdf) && !/<td>-\d/.test(pdf), (pdf.match(/Instance consumption[\s\S]{0,400}/) || [''])[0]);
  const lic = String(h.run(r.c, 'licenseTab(_lastRenderData)') || '');
  T('M3 Licensing tab shows over-use', /over the licence/.test(lic));
  T('L1 TB licence is not labelled VUL', !/Capacity \(VUL\)/.test(pdf + lic));
})();

// ── Missing-information checks ───────────────────────────────────────────────────
(function () {
  let r = full(s.log({ extraTail: [s.TS + '[VmcStats] =LICENSE INFORMATION= collection result: Failed'] }));
  T('MI collection failure is reported', /LICENSE INFORMATION/.test(JSON.stringify(r.find(/collection failed/) || {})));
  r = full(s.log({ jobs: [s.backupJob({ id: 1, extra: ' LastResult: Failed, RestorePoints: 3,' }), s.backupJob({ id: 2, extra: ' LastResult: Success, RestorePoints: 0,' })] }));
  T('MI failed job raised', (r.find(/failed on the last run/) || {}).sev === 'crit');
  T('MI scheduled job with no restore points raised', !!r.find(/no restore points/));
  T('MI no configuration backup job raised', (r.find(/No configuration backup job/) || {}).sev === 'warn');
  const conf = s.TS + `PlatformId: ${s.ZERO}, PlatformName: VMware, JobID: ${s.G(20)}, Type: ConfBackup, ScheduleEnabled: False, StorageEncryptionEnabled: True,`;
  r = full(s.log({ jobs: [s.backupJob({ id: 1 }), conf] }));
  T('MI disabled configuration backup schedule raised', !!r.find(/Configuration backup schedule is disabled/) && !r.find(/No configuration backup job/));
  r = full(s.log({ jobs: [s.backupJob({ id: 1 })], repos: [s.repo({ type: 'LinuxHardened', extra: ' ImmutabilitySettings: { Enabled: True, Value: 30, Unit: Days },' })] }));
  T('MI immutability longer than retention raised', !!r.find(/Immutability is longer than retention/));
  const copy = s.backupJob({ id: 3, src: 'Backup' }).replace('Value: 14, Unit: Points', 'Value: 7, Unit: Points');
  r = full(s.log({ jobs: [s.backupJob({ id: 1 }), copy] }));
  T('MI copy retention shorter than primary raised', !!r.find(/backup copy keeps fewer restore points/));
})();

// ── Remaining audit items (round 4) ──────────────────────────────────────────────
(function () {
  const TS = s.TS;
  // P1-12 repo task total from each repository's own limit
  let r = full(s.log({ repos: [s.repo({ id: 50, extra: ' ConcurrentTaskLimit: { Enabled: True, Number: 16 },' }), s.repo({ id: 51, extra: ' ConcurrentTaskLimit: { Number: 8, Enabled: False },' })] }));
  T('P1-12 repo task total reads "{ Enabled: True, Number: 16 }" and skips a disabled limit', r.D.cur.repoTaskTotal === 16, r.D.cur.repoTaskTotal);
  // P2-26 tape cleaning keeps the worst library
  r = full(s.log({ extraTail: [TS + '[TapeLibrary] Name: A, IsAutoCleaningEnabled: False, CleaningTapesCount: 0', TS + '[TapeLibrary] Name: B, IsAutoCleaningEnabled: True, CleaningTapesCount: 2'] }));
  T('P2-26 one library without cleaning is not hidden by the next', r.D.tapeAutoClean === false && r.D.tapeCleaningTapes === 0, [r.D.tapeAutoClean, r.D.tapeCleaningTapes]);
  // P2-31 appliance OS from the backup server's record
  r = full(s.log({ extraTop: [TS + '[GatewayServers] Name: gw1, OSversion: WinServer2019', TS + 'DeploymentType: LinuxOVA, VeeamApplianceVersion: 13.0.1', TS + '[Veeam Backup and Replication server] CoresCount: 8, RAMTotalSize: 34359738368, OSversion: Rocky_Linux_9'] }));
  T('P2-31 VSA OS is not taken from a gateway line', r.D.vsaOS === 'Rocky Linux 9', r.D.vsaOS);
  T('L14 VSA gets the KB4879 Veeam Updater reminder', (r.find(/KB4879/) || {}).sev === 'i');
  // P1-3 FreeSpace missing is unknown, not 0
  r = full(s.log({ repos: [s.repo({}).replace(/FreeSpace: \d+, /, '')] }));
  const rp = r.D.repoList[0];
  T('P1-3 missing FreeSpace is unknown, not 0% used / 0 TB free', rp.free_b === null && rp.used_pct === null, [rp.free_b, rp.used_pct]);
  T('P1-3 repository table shows a dash, not 0 TB free', !/>0 TB</.test(String(h.run(r.c, 'document.getElementById("results").innerHTML'))));
  // P1-27 sub-TB repository size
  T('P1-27 repoSz falls back to GB below 0.1 TB', typeof r.c.repoSz === 'function' && r.c.repoSz(0, 40 * 1073741824) === '40 GB' && r.c.repoSz(2.5, 1) === '2.5 TB');
  // P1-16 media pools from the tape infrastructure total
  r = full(s.log({ extraTail: [TS + '[TapeLibrary] Name: L1, MediaPoolsCount: 1', TS + 'Tape infrastructure: { LibrariesCount: 1, DrivesCount: 2, MediaPoolsCount: 5 }'] }));
  T('P1-16 media pools from the estate total', r.D.mediaPools === 5, r.D.mediaPools);
  // P1-9 hosts across platforms
  r = full(s.log({ extraTop: [TS + '[Hyper-V Infrastructure] Hosts: 4, Clusters: 1, VirtualMachines: 10'] }));
  T('P1-9 Hyper-V hosts are added to VMware hosts', r.D.hosts === 7 && r.D.clusters === 1, [r.D.hosts, r.D.clusters]);
  // P2-35 map GFS from the per-period form
  r = full(s.log({ jobs: [s.backupJob({ id: 1, extra: ' WeeklyGFS: { Enabled: True, KeepCount: 4 },' })] }));
  const mj = (r.D.backupMap.nodes || []).reduce((a, n) => a.concat(n.jobList || []), []).find(j => /^00000001/.test(j.id || j.fullId || ''));
  T('P2-35 map reads WeeklyGFS', !!mj && mj.gfs === true, mj && mj.gfs);
  // P2-14 a null capacity tier is not configured
  r = full(s.log({ extraTail: [TS + 'SOBRs: 1, PerformanceTier: { Extents: 1 }, CapacityTier: null, ArchiveTier: null'] }));
  T('P2-14 "CapacityTier: null" is not a tier', r.D.sobrTiers.indexOf('CapacityTier') < 0 && r.D.sobrTiers.indexOf('ArchiveTier') < 0, r.D.sobrTiers);
})();

(function () {
  // M1 manual entry raises no criticals from missing data
  const c = h.load(); let cap = null; const r0 = c.render; c.render = d => { cap = d; return r0(d); };
  c.document.getElementById('vmCount').value = '100';
  h.run(c, 'calculate()'); c.render = r0;
  const f = cap ? c.buildFindings(cap) : [];
  T('M1 manual mode: no findings from data the log would supply', !f.some(x => /No backup copy configured|immutability not enabled|Enterprise Manager not configured|No GFS/i.test(x.title)), f.map(x => x.title));
  T('M1 manual mode: no "VBR v13 on Windows" pass without a build', !f.some(x => /VBR v13 on Windows/.test(x.title)));
  // M12 Settings tab matches the findings when tape exists
  const tape = s.TS + `PlatformId: ${s.ZERO}, PlatformName: VMware, JobID: ${s.G(7)}, Type: VmTapeBackup, IsEncryptionEnabled: True,`;
  const r = full(s.log({ jobs: [s.backupJob({ id: 1 }), tape] }));
  const rows = r.c.buildSettings(r.d);
  const bc = rows.find(x => /Backup copy/.test(x.name)), im = rows.find(x => /^Immutability/.test(x.name));
  T('M12 Settings: backup copy is a warning when tape exists', bc && bc.sev === 'warn', bc);
  T('M12 Settings: immutability is a warning when tape exists', im && im.sev === 'warn', im);
  // M3 defaulted inputs listed
  const r2 = full(s.log({ jobs: [s.backupJob({ id: 1, size: 0 }).replace('RetentionPolicy: { Value: 14, Unit: Points }, ', '')] }));
  T('M3 defaulted retention is listed', (r2.d.defaulted || []).some(x => /retention/.test(x)), r2.d.defaulted);
  // L7 retention tile shows the log's unit
  T('L7 overview shows "14 Points", not "14d"', /14 Points/.test(String(h.run(r.c, 'document.getElementById("results").innerHTML'))));
  // L5 unlimited repository tasks
  const r3 = full(s.log({ repos: [s.repo({ extra: ' ConcurrentTaskLimit: { Enabled: False, Number: 4 },' })] }));
  const rc = r3.d.repoComputeList[0];
  T('L5 an unlimited repository is sized for the estate tasks, not 1', rc && rc.tasks === r3.d.tasksNeeded && rc.tasks > 1, rc);
  // SureBackup unknown is not "Not configured"
  const inf = String(h.run(r.c, 'infraTab(_lastRenderData)') || '');
  T('SureBackup unknown is shown as Unknown', r.D.surebackup != null || /SureBackup[\s\S]{0,200}Unknown/.test(inf));
})();

(function () {
  // UI L4 nt() warning class for an inferred tape edge
  const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'index.html'), 'utf8');
  T('UI-L4 tape inferred edge uses the warning style', /nt\(m\.tape\.inferredEdges\?'w':'i'/.test(src));
  // UI H2 a new file disables Export until Calculate
  const r = full(s.log({}));
  h.analyse(r.c, s.log({ vms: 5 }), 'second.log');
  T('UI-H2 loading a new log clears the previous report for export', h.run(r.c, '_lastRenderData') == null);
  // Workflow fetches full history for the maintainer-commit check
  const wf = require('fs').readFileSync(require('path').join(__dirname, '..', '.github', 'workflows', 'refresh-advisories.yml'), 'utf8');
  T('S-M6 refresh workflow checks out full history', /fetch-depth:\s*0/.test(wf));
})();

if (require.main === module) {
  console.log(`v3.0 audit fixes: ${pass} passed, ${fail} failed`);
  if (fails.length) { console.log('\nFAILURES:'); fails.forEach(f => console.log('  ' + f)); process.exit(1); }
}
