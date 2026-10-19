#!/usr/bin/env node
/*
 * confirm-bp-findings.js — regression guard for the single-server BP Review findings.
 *
 * Every layer runs the REAL application code from index.html, loaded into a Node vm by
 * tests/harness.js (v3.0 fix: earlier layers tested hand-copied "mirrors" of the logic,
 * which drifted from the tool and could pass while the tool was wrong).
 *
 *   1. SYNTHETIC FIXTURES (always run, no external files) — made-up logs from tests/synth.js.
 *      Safe for CI: contains NO customer data and needs no VMC.log on disk.
 *   2. REAL REFERENCE LOGS (optional) — pass a folder of VMC.logs as argv[2] to additionally
 *      assert the per-file expected outcomes. Customer logs must NOT be committed to the repo.
 *   3. tests/v3-fixes.test.js — the 2026-10 audit fixes (run by this file too).
 *
 * Usage:  node confirm-bp-findings.js                 # fixtures only (CI)
 *         node confirm-bp-findings.js <logs-folder>   # fixtures + real reference logs
 * Exit:   0 = all passed, 1 = one or more failed
 */
const fs = require('fs');
const path = require('path');
const H = require('./tests/harness');
const SY = require('./tests/synth');
const APP = H.load();                         // one shared copy of the real tool
const V = code => H.run(APP, code);

// ── real-tool evaluation of the five original BP extractors ─────────────────────
// Parses a log with the real parseLog()/calculate() and reads the real findings and
// settings rows, mapped onto the original five outcome codes.
function evalReal(text, fname){
  const c = H.load(); let d=null; const r0=c.render; c.render=x=>{ d=x; return r0(x); };
  H.analyse(c, text, fname||'VMC.log'); H.run(c,'calculate()'); c.render=r0;
  if(!d) return {};
  const f=c.buildFindings(d), rows=c.buildSettings(d);
  const has=re=>f.some(x=>re.test(x.title)), row=n=>rows.find(r=>r.name===n);
  const vm=row('VMs per job'), hc=row('Health check'), dv=row('Remove deleted items data');
  return {
    enc: has(/^Encryption disabled — Backup Job/) ? 'crit' : 'silent',
    mal: has(/^Malware detected/) ? 'crit' : has(/suspicious restore point/) ? 'warn' : has(/^Malware scan events recorded/) ? 'info' : 'silent',
    vm:  vm ? ({ok:'ok',i:'info',crit:'crit'})[vm.sev] : '-',
    hc:  hc ? hc.sev : 'silent',
    dv:  dv ? (dv.cur==='Disabled' ? 'off' : 'on') : 'silent',
  };
}

// ── synthetic fixtures (no customer data) ───────────────────────────────────────
const job = (n,enc,hc,dv,vms) => SY.backupJob({ id:n, enc:enc==='True', vms:vms,
  extra:` HealthCheck : { Enabled: ${hc}, FullHealthCheckEnabled: True }, DeletedVMRetention : { Enabled: ${dv}, Days: 30 },` });
const malLine = (ev,inf,sus) => [
  `${SY.TS}Malware events counts: { EventsTotalCount: ${ev}, RansomwareExtensionsCount: ${ev} }`,
  `${SY.TS}OIBsRansomwareStatusCounts: { ManuallyChecked: { OIBsInfectedCount: 0, OIBsSuspiciousCount: 0 }, DetectedByVeeam: { OIBsInfectedCount: ${inf}, OIBsSuspiciousCount: ${sus} } }`];
const L = (jobs, tail) => SY.log({ jobs: jobs, extraTail: tail||[] });
const replicaOnly = `${SY.TS}PlatformId: ${SY.ZERO}, PlatformName: VMware, JobID: ${SY.G(4)}, Type: Replica, ScheduleEnabled: True, VMsCount: 3,`;

const FIXTURES = [
  // FIX #1 encryption
  { name:'enc: all jobs encrypted -> silent', text: L([job(1,'True','True','True',10), job(2,'True','True','True',10)]), expect:{ enc:'silent' } },
  { name:'enc: one job unencrypted -> crit', text: L([job(1,'True','True','True',10), job(2,'False','True','True',10)]), expect:{ enc:'crit' } },
  { name:'enc: no backup jobs (replica only) -> silent', text: L([replicaOnly]), expect:{ enc:'silent', vm:'-' } },
  // FIX #2 malware
  { name:'malware: infected restore points -> crit', text: L([job(1,'True','True','True',10)], malLine(50,2,0)), expect:{ mal:'crit' } },
  { name:'malware: suspicious only -> warn', text: L([job(1,'True','True','True',10)], malLine(800,0,5)), expect:{ mal:'warn' } },
  { name:'malware: events but 0 infected/suspicious -> info', text: L([job(1,'True','True','True',10)], malLine(4000,0,0)), expect:{ mal:'info' } },
  { name:'malware: no events -> silent', text: L([job(1,'True','True','True',10)]), expect:{ mal:'silent' } },
  // FIX #3 VMs per job
  { name:'vms: >300 -> crit',   text: L([job(1,'True','True','True',350)]), expect:{ vm:'crit' } },
  { name:'vms: 100-300 -> info', text: L([job(1,'True','True','True',150)]), expect:{ vm:'info' } },
  { name:'vms: <=100 -> ok',     text: L([job(1,'True','True','True',50)]),  expect:{ vm:'ok' } },
  // FIX #4 / #5 majority (deleted-VM retention is now informational: only its state is checked)
  { name:'healthCheck/delVM: majority disabled', text: L([job(1,'True','False','False',10), job(2,'True','False','False',10), job(3,'True','True','True',10)]), expect:{ hc:'warn', dv:'off' } },
  { name:'healthCheck/delVM: majority enabled',  text: L([job(1,'True','True','True',10), job(2,'True','True','True',10), job(3,'True','False','False',10)]), expect:{ hc:'ok', dv:'on' } },
];

// ── reference-log expectations (only files present in the target folder are asserted) ──
const EXPECT = {
  'VMC.log':{enc:'silent',vm:'info'}, 'log-08.log':{enc:'silent'},
  'log-03.log':{enc:'crit',mal:'warn'}, 'log-05.log':{enc:'crit',vm:'crit'},
  'log-01.log':{enc:'crit',mal:'warn'},
  'log-02.log':{enc:'crit',hc:'ok'}, 'log-07.log':{enc:'crit',hc:'ok'},
  'log-10.log':{enc:'crit'}, 'log-04.log':{enc:'silent'},
  'log-06.log':{enc:'silent'}, 'log-09.log':{enc:'silent'},
};

// ── runner ──────────────────────────────────────────────────────────────────────
let pass=0, fail=0; const fails=[];
function check(label, got, exp){
  Object.keys(exp).forEach(k=>{
    if(got[k]===exp[k]) pass++;
    else { fail++; fails.push(`  ${label}  [${k}] expected '${exp[k]}' got '${got[k]}'`); }
  });
}

// layer 1 — fixtures (always)
FIXTURES.forEach(f=> check(f.name, evalReal(f.text), f.expect));
console.log(`Fixtures: ${pass} passed, ${fail} failed`);

// layer 1b — per-job-type classification + agent licence counts, from the real parser
const _p0=pass, _f0=fail;
function T11(label, cond){ if(cond) pass++; else { fail++; fails.push(`  v1.1.0: ${label}`); } }
(function(){
  const rec=(id,type,extra)=>`${SY.TS}PlatformId: ${SY.ZERO}, PlatformName: Windows, JobID: ${SY.G(id)}, Type: ${type}, ScheduleEnabled: True,${extra||''}`;
  const parse=t=>{ const c=H.load(); H.analyse(c,t); return c.D; };
  const byType=D=>{ const m={}; (D.jobsByType||[]).forEach(t=>{ m[t.common]=t.count; }); return m; };
  const d1=parse(SY.log({ jobs:[ rec(1,'BCSMPolicy'), rec(2,'AgentPolicy',' ComputerType: Workstation,'), rec(3,'EpAgentManagement'), rec(4,'NasBackup'), rec(5,'Backup'), rec(5,'Backup') ] }));
  const bt=byType(d1);
  T11('classify BCSMPolicy -> Backup copy job', bt['Backup copy job']===1);
  T11('classify AgentPolicy(Workstation) -> Agent backup', bt['Agent backup']===1);
  T11('classify EpAgentManagement -> Agent backup (mgmt)', bt['Agent backup (mgmt)']===1);
  T11('job records de-duplicated by JobID', (d1.jobRecords||[]).filter(j=>j.type==='Backup').length===1);
  const ag=parse(SY.log({ jobs:[ rec(1,'AgentBackup',' ComputerType: Server,'), rec(2,'AgentPolicy',' ComputerType: Workstation,'), rec(3,'AgentPolicy',' ComputerType: Workstation,'),
    rec(4,'EndpointBackup'), rec(6,'EndpointBackup') ] })).agentRecon||{};
  T11('agents: 1 server / 2 workstation / 2 standalone', ag.mgdServer===1 && ag.mgdWorkstation===2 && ag.standalone===2);
  T11('agents: 2 workstations -> 1 instance (ceil/3)', ag.expWksInst===1);
  const w4=parse(SY.log({ jobs:[1,2,3,4].map(n=>rec(n,'AgentPolicy',' ComputerType: Workstation,')) })).agentRecon||{};
  T11('agents: 4 workstations -> 2 instances', w4.expWksInst===2);
  const unk=parse(SY.log({ jobs:[ rec(1,'AgentBackup') ] })).agentRecon||{};
  T11('agents: unknown ComputerType counts as server', unk.mgdServer===1);
  T11('agents: 1 server agent with no licence data -> over-licence', unk.overServer===true);
})();
console.log(`v1.1.0:   ${pass-_p0} passed, ${fail-_f0} failed`);

// layer 1c — v2.3 security-advisory check. Loads the REAL vaBuildCheck() from index.html
// (between the VA-ADVISORIES markers) and drives it with FIXED synthetic advisory data, so
// these assertions do not change when tools/build-advisories.mjs refreshes the embedded copy.
// The embedded copy itself is only checked for shape.
const _p1=pass, _f1=fail;
function T23(label, cond){ if(cond) pass++; else { fail++; fails.push(`  v2.3: ${label}`); } }
(function(){
  const c=H.load();
  const api={check:c.vaBuildCheck, data:()=>H.run(c,'VA_ADVISORIES'), set:d=>{ c.__adv=d; H.run(c,'VA_ADVISORIES=__adv'); }};
  // shape of the embedded (real) data
  const real=api.data();
  T23('embedded data has asOf date', /^\d{4}-\d{2}-\d{2}$/.test(real.asOf||''));
  T23('embedded data has latest v12 and v13 builds', !!(real.latest&&real.latest[12]&&real.latest[13]));
  T23('embedded advisories well-formed', Array.isArray(real.advisories) && real.advisories.length>0 &&
      real.advisories.every(x=>(x.major===12||x.major===13) && /^1[23]\.\d+\.\d+\.\d+$/.test(x.affectedMax) && x.cves.length && x.kb));
  // synthetic data for logic assertions
  api.set({asOf:'2026-01-01', latest:{12:{name:'12.9',build:'12.9.0.100',date:'2026-01-01'},13:{name:'13.9',build:'13.9.0.100',date:'2026-01-01'}},
    advisories:[
      {kb:'kbA',major:12,affectedMax:'12.3.2.4165',fixed:['12.3.2.4465'],cves:[{id:'CVE-A1',cvss:9.9,deploy:null},{id:'CVE-A2',cvss:6.0,deploy:null}]},
      {kb:'kbB',major:13,affectedMax:'13.0.1.1071',fixed:['13.0.1.2067'],cves:[{id:'CVE-B1',cvss:9.9,deploy:['windows']},{id:'CVE-B2',cvss:9.1,deploy:['vsa']},{id:'CVE-B3',cvss:7.7,deploy:['windows','vsa']}]},
      {kb:'kbC',major:12,affectedMax:'12.0.0.1420',fixed:['12.0.0.1420 P20230223'],cves:[{id:'CVE-C1',cvss:7.5,deploy:null}]},
    ]});
  const r1=api.check('12.3.2.4165',false);
  T23('12.3.2.4165 hit by kbA only', r1 && r1.hits.length===1 && r1.hits[0].kb==='kbA');
  T23('critical count counts CVSS >= 9', r1.critCount===1 && r1.cveCount===2);
  T23('build above affectedMax is clean', api.check('12.3.2.4465',false).hits.length===0);
  T23('other major line not affected', api.check('13.0.1.1071',false).hits.every(h=>h.kb!=='kbA'));
  const w=api.check('13.0.1.1071',false), v=api.check('13.0.1.1071',true);
  T23('Windows server: windows + both CVEs only', w.hits[0].cves.map(c=>c.id).join()==='CVE-B1,CVE-B3');
  T23('Appliance: vsa + both CVEs only', v.hits[0].cves.map(c=>c.id).join()==='CVE-B2,CVE-B3');
  const p0=api.check('12.0.0.1420',false), p1=api.check('12.0.0.1420 P20230718',false);
  T23('same-build patch fix: unpatched build flagged for verification', p0.hits.some(h=>h.kb==='kbC'&&h.verify));
  T23('same-build patch fix: later patch suppresses', !p1.hits.some(h=>h.kb==='kbC'));
  T23('behind latest flagged', api.check('12.3.2.4465',false).behindLatest===true);
  T23('non v12/v13 build returns null', api.check('11.0.1.1261',false)===null && api.check('',false)===null);
})();
console.log(`v2.3:     ${pass-_p1} passed, ${fail-_f1} failed`);

// layer 1d — v2.4 v12 → v13 upgrade readiness. Loads the REAL vaUpgradeReadiness() from
// index.html with FIXED synthetic advisory "latest" data so dates do not drift on refresh.
const _p2=pass, _f2=fail;
function T24(label, cond){ if(cond) pass++; else { fail++; fails.push(`  v2.4: ${label}`); } }
(function(){
  const c=H.load();
  const api={u:c.vaUpgradeReadiness, set:d=>{ c.__adv=d; H.run(c,'VA_ADVISORIES=__adv'); }};
  api.set({asOf:'2026-01-01', latest:{12:{name:'12.9',build:'12.9.0.100',date:'2025-12-01'},13:{name:'13.9',build:'13.9.0.100',date:'2026-01-01'}}, advisories:[]});
  const st=(r,re)=>r.items.filter(x=>re.test(x.title)).map(x=>x.st).join();
  const old=api.u({vbr:'12.1.2.172',supportExpiry:'31/12/2025',bsCPUact:4,bsRAMact:8,veeamOne:true,enterpriseManager:'Local',o365Installed:true,
    cloudConnect:{isProvider:true},agentRecon:{mgdServer:2},plugins:[{name:'Veeam Plug-in for SAP HANA',version:'12.1.0.2131'},{name:'Veeam Plug-in for Nutanix AHV',version:'12.0.0.1'}],
    cdpPolicies:2,configBackupEncrypted:false,jobCounts:{FileCopy:1},fileTapeJobs:1,reverseJobs:3,sobrs:1,repoList:[{immut:true}],platform:'VMware'});
  T24('build below 12.3.1.1139 is a blocker', st(old,/cannot be upgraded/)==='block');
  T24('support ending before the v13 build date is a blocker', st(old,/Support contract ends/)==='block');
  T24('backup server below 8 cores / 16 GB is an action', st(old,/below the v13 minimum/)==='action');
  T24('Veeam ONE, Enterprise Manager and VB365 upgrade order', st(old,/Veeam ONE first/)==='action' && st(old,/Enterprise Manager first/)==='action' && st(old,/Microsoft 365 first/)==='action');
  T24('enterprise plug-in below 12.3.2.4165 flagged, virtualization plug-in not', st(old,/SAP HANA/)==='action' && st(old,/Nutanix/)==='');
  T24('CDP and unencrypted config backup are actions', st(old,/CDP polic/)==='action' && st(old,/Enable configuration backup encryption/)==='action');
  T24('log-blind items are checks', ['Agent versions','file copy','file to tape','Reverse incremental','extent immutability','vSphere'].every(t=>st(old,new RegExp(t,'i'))==='check'));
  T24('blockers sorted first', old.items[0].st==='block' && old.counts.block===2);
  const ok=api.u({vbr:'12.3.1.1139',supportExpiry:'02/01/2026',bsCPUact:8,bsRAMact:16,configBackupEncrypted:true,jobCounts:{},platform:'HyperV'});
  T24('ready server: no blockers, only the config backup action', ok.counts.block===0 && ok.counts.action===1 && ok.counts.check===0);
  T24('support date read as dd/mm/yyyy', st(ok,/Support contract covers/)==='ok');
  T24('missing support date is a check', st(api.u({vbr:'12.3.2.4854'}),/Support expiry/)==='check');
  T24('v13 and unknown builds return null', api.u({vbr:'13.1.1.18'})===null && api.u({vbr:null})===null);
})();
console.log(`v2.4:     ${pass-_p2} passed, ${fail-_f2} failed`);

// layer 1e — v2.5 Security & Compliance Analyzer map. Loads the REAL VA_SCA / vaScaInfo()
// from index.html and checks coverage of the v13 VBRBestPracticeType enumeration.
const _p3=pass, _f3=fail;
function T25(label, cond){ if(cond) pass++; else { fail++; fails.push(`  v2.5: ${label}`); } }
(function(){
  const api={map:V('VA_SCA'), info:APP.vaScaInfo};
  // VBRBestPracticeType members, Veeam PowerShell Reference v13 (Veeam PowerShell Enumerations)
  const ENUM13='BackupServerInProductionDomain VbrAndEmOnDifferentMachines BiosUEFIMode SecureBootEnable SMBSigningEnabled WDigestNotStorePasswordsInMemory WebProxyAutoDiscoveryDisabled TLS1Disabled TLS1_1Disabled SSLv2Disabled SSLv3Disabled WindowsScriptHostDisabled SMB1ProtocolDisabled LLMNRDisabled SMBEncryptionEnabled OutdatedSslAndTlsDisabled CSmbSigningAndEncryptionEnabled CredentialsGuardConfigured LsassProtectedProcess NetBiosDisabled RemoteDesktopServiceDisabled RemotePowerShellDisabled RemoteRegistryDisabled SMB1Disabled FirewallEnabled WinRmServiceDisabled MfaEnabledInBackupConsole ImmutableOrOfflineMediaPresence LossProtectionEnabled ConfigurationBackupEnabled ConfigurationBackupEncryptionEnabled EmailNotificationsEnabled ContainBackupCopies ReverseIncrementalInUse PublicCloudTargetJobEncrypted CloudConnectTargetJobEncrypted ManualLinuxHostAuthentication ConfigurationBackupRepositoryNotLocal ViProxyTrafficEncrypted HardenedRepositoryNotVirtual TrafficEncryptionEnabled LinuxServersUsingSSHKeys BackupServicesUnderLocalSystem ConfigurationBackupEnabledAndEncrypted PasswordsRotation HardenedRepositorySshDisabled OsBucketsInComplianceMode JobsTargetingCloudRepositoriesEncrypted BackupServerUpToDate PostgreSqlUseRecommendedSettings HardenedRepositoryNotContainsNBDProxies EncryptionPasswordsComplexityRules CredentialsPasswordsComplexityRules BackupServerHighAvailabilityEnabled LinuxSshPasswordAuthenticationDisabled LinuxPreventRootLogin LinuxUseIntrusionDetection LinuxUseSecurityModule LinuxAuditdConfigured LinuxOsIsFipsEnabled LinuxOsHasVaRandomization LinuxOsUsesTcpSyncookies LinuxWorldDirectoriesPermissions LinuxDisableProblematicServices LinuxUsePasswordPolicy LinuxUseAntivirus LinuxUseSecureBoot LinuxGrubPasswordSet LinuxAuditBinariesOwnerIsRoot LinuxAuditLogDirectoriesOwnerIsRoot'.split(' ');
  const missing=ENUM13.filter(k=>!api.map[k]);
  T25('every v13 enum key is mapped (missing: '+missing.join(',')+')', missing.length===0);
  T25('entries well-formed (list W/L/B, group I/P/O, title, https URL)', Object.values(api.map).every(e=>e.length===6&&/^[WLB]$/.test(e[0])&&/^[IPO]$/.test(e[1])&&e[2]&&/^https:\/\//.test(e[5])));
  T25('Linux checks are on the Linux list', ['LinuxUseSecureBoot','LinuxUseSecurityModule','LinuxAuditdConfigured','LinuxOsIsFipsEnabled'].every(k=>api.map[k][0]==='L'));
  T25('Windows-only checks are on the Windows list', ['LLMNRDisabled','WDigestNotStorePasswordsInMemory','LsassProtectedProcess','RemoteRegistryDisabled'].every(k=>api.map[k][0]==='W'));
  T25('retired keys grouped as earlier-version', ['BiosUEFIMode','LinuxUseAntivirus','LinuxGrubPasswordSet'].every(k=>api.map[k][1]==='O'));
  T25('corrected meanings kept (NBDSSL, manual Linux trust, EM password loss protection)', /NBDSSL/.test(api.map.ViProxyTrafficEncrypted[3]) && /manually/.test(api.map.ManualLinuxHostAuthentication[3]) && /Enterprise Manager/.test(api.map.LossProtectionEnabled[3]));
  const u=api.info('SomeFutureCheck');
  T25('unknown key is returned with its raw name, not dropped', u.known===false && u.title==='SomeFutureCheck' && /^https:/.test(u.url));
})();
console.log(`v2.5:     ${pass-_p3} passed, ${fail-_f3} failed`);

// layer 1f — v2.6 resilience scorecard. Loads the REAL vaResilience() from index.html and
// drives it with synthetic parsed data and findings.
const _p4=pass, _f4=fail;
function T26(label, cond){ if(cond) pass++; else { fail++; fails.push(`  v2.6: ${label}`); } }
(function(){
  const res=APP.vaResilience;
  const st=(r,k)=>(r.rows.find(x=>x.key===k)||{}).st;
  const weak=res({cur:{backupCopy:'False',immutability:'False'},mfaEnabled:false,inlineScan:false,configBackupEncrypted:false,virtualLabs:0,jobCounts:{},
      encPosture:{jobsTot:4,jobsEnc:0,jobsPct:0}},
    [{title:'No backup copy configured (3-2-1 rule violated)'},{title:'Short immutability period (3 days)'},{title:'Repository immutability not enabled'},{title:'MFA disabled on VBR console'}]);
  T26('weak server: copy, immutability, encryption, config, MFA, malware, SureBackup all not met', ['copy','immut','enc','cfg','mfa','mal','sb'].every(k=>st(weak,k)==='gap'));
  T26('rows link to their finding (immutability skips "Short immutability period")', weak.rows.find(x=>x.key==='immut').find===2 && weak.rows.find(x=>x.key==='copy').find===0 && weak.rows.find(x=>x.key==='mfa').find===3);
  T26('no finding to link -> no finding link', weak.rows.find(x=>x.key==='sb').find===-1);
  const strong=res({cur:{backupCopy:'True',immutability:'True'},jobCounts:{BackupCopy:2,SureBackup:1},virtualLabs:1,mfaEnabled:true,inlineScan:true,configBackupEncrypted:true,
      repoList:[{immut:true}],encPosture:{jobsTot:4,jobsEnc:4,jobsPct:100}},[]);
  T26('strong server: every row met', strong.counts.ok===7 && strong.counts.gap===0);
  const mid=res({cur:{backupCopy:'False',immutability:'False'},tapeJobs:2,jobCounts:{SureBackup:1},virtualLabs:0,encPosture:{jobsTot:4,jobsEnc:2,jobsPct:50}},[]);
  T26('tape without backup copy / immutability is partly met', st(mid,'copy')==='part' && st(mid,'immut')==='part');
  T26('partial encryption and SureBackup without a lab are partly met', st(mid,'enc')==='part' && st(mid,'sb')==='part');
  T26('unrecorded MFA / malware / config backup are "not in log"', st(mid,'mfa')==='unk' && st(mid,'mal')==='unk' && st(mid,'cfg')==='unk');
  const prov=res({cur:{backupCopy:'False',immutability:'False'},cloudConnect:{isProvider:true},inlineScan:false,jobCounts:{}},[]);
  T26('service provider: copy, immutability and inline scan are verify, not fail', st(prov,'copy')==='part' && st(prov,'immut')==='part' && st(prov,'mal')==='part');
  const inf=res({cur:{},inlineScan:true,malwareDetail:{oibInfected:3},jobCounts:{}},[]);
  T26('infected restore points override inline scan', st(inf,'mal')==='gap');
})();
console.log(`v2.6:     ${pass-_p4} passed, ${fail-_f4} failed`);

// layer 1g — v3.0: Fast Clone estimate, platform support, MapCapture Section 7, patch level,
// version-correct links. Each block loads the REAL function(s) from index.html.
const _p5=pass, _f5=fail;
function T30(label, cond){ if(cond) pass++; else { fail++; fails.push(`  v3.0: ${label}`); } }
(function(){
  const mk=(pre)=>{ const c=H.load(); if(pre) H.run(c,pre); return {fc:c.vaFastClone, plat:c.vaPlatformSupport, patch:c.vaVbrWithPatch}; };
  const api=mk();
  // Fast Clone: 10 TB full (10240 GB), 512 GB/day, 14 days, 4W/12M/3Y GFS, 1.2x overhead
  const base={fullGB:10240,incrGB:512,ret:14,gfsW:4,gfsM:12,gfsY:3,overhead:1.2};
  const logical=(retGB)=>(retGB+10240*19)*1.2;
  const inc=api.fc(Object.assign({},base,{mode:'incremental',retGB:10240+512*14,gfsWeeklyGB:40960,gfsMonthlyGB:122880,gfsYearlyGB:30720,totGB:logical(10240+512*14)}));
  T30('forever-forward: weekly GFS costs 7 days of change, monthly/yearly capped at a full', inc.gfsGB===512*7*4+10240*12+10240*3);
  T30('saving is logical minus Fast Clone total', Math.abs(inc.savedTB-Math.round((logical(10240+512*14)-inc.totGB)/1024*10)/10)<0.11 && inc.savedTB>0);
  const act=api.fc(Object.assign({},base,{mode:'active',retGB:2*10240+512*12,gfsWeeklyGB:40960,gfsMonthlyGB:122880,gfsYearlyGB:30720,totGB:logical(2*10240+512*12)}));
  T30('active full mode: nothing is cloned (no saving, GFS not cloned)', act.gfsCloned===false && act.savedTB===0);
  const syn=api.fc(Object.assign({},base,{mode:'synthetic',gfsW:0,gfsM:0,gfsY:0,retGB:2*10240+512*12,gfsWeeklyGB:0,gfsMonthlyGB:0,gfsYearlyGB:0,totGB:(2*10240+512*12)*1.2}));
  T30('synthetic full mode: second full costs 7 days of change', syn.retGB===10240+512*7+512*12);
  // Platform support
  const S=[{type:'ESXi',api:'6.5.0',name:'a'},{type:'ESXi',api:'8.0.3.0',name:'b'},{type:'VC',api:'9.5.0',name:'c'},
    {type:'HvServer',api:'6.3.9600',name:'d'},{type:'HvServer',api:'10.0.17763',name:'e'},{type:'HvServer',api:null,info:'Azure Stack HCI 23H2',name:'f'},
    {type:'ESXi',api:null,info:null,name:'g'},{type:'Scvmm',api:'10.22.1287.0',name:'h'}];
  const st=(r)=>r.rows.map(x=>x.st).join(',');
  T30('v13 matrix: ESXi 6.5 / Hyper-V 2012 R2 unsupported, 9.5 newer than listed, unreadable/Azure/SCVMM to check', st(api.plat('13.1.1.18',S))==='gap,ok,check,gap,ok,check,check,check');
  T30('v12 matrix: ESXi 6.5 and Hyper-V 2012 R2 supported', st(api.plat('12.3.2.4854',S))==='ok,ok,check,ok,ok,check,check,check');
  T30('no capture or no build -> null', api.plat('13.1.1.18',[])===null && api.plat('',S)===null);
  // Patch level from MapCapture is applied only to the matching build
  const withCap=mk("var _psCapture={bsBuild:'12.0.0.1420',bsPatch:'20230718'};");
  T30('patch level appended for the matching build', withCap.patch('12.0.0.1420')==='12.0.0.1420 P20230718');
  T30('patch level ignored for another build or when the log already has one', withCap.patch('13.1.1.18')==='13.1.1.18' && withCap.patch('12.0.0.1420 P20230223')==='12.0.0.1420 P20230223');
  // MapCapture Section 7 parser
  const parse=APP.parseMapCapture;
  const cap=parse(['Veeam Advisor — Backup Map capture','Host: LAB-VBR-01   Date: 2026-10-01','Backup server build : 12.3.2.4854','Backup server patch : P20250901',
    '  SRV | ESXi | 8.0.3.0 | VMware ESXi 8.0.3 build-1 | esx1.lab','  SRV | HvServer | n/a (null) | n/a (null) | hv1.lab'].join('\n'));
  T30('MapCapture Section 7: build, patch and servers parsed; n/a values become null', cap.bsBuild==='12.3.2.4854' && cap.bsPatch==='20250901' && cap.servers.length===2 && cap.servers[1].api===null && cap.servers[0].name==='esx1.lab');
  // Version-correct links (real VA_LINKS12 map)
  const L={map:V('VA_LINKS12'), fix:APP.vaVersionLinks};
  const u='https://helpcenter.veeam.com/docs/vbr/userguide/';
  T30('v12 links map is populated and well-formed', Object.keys(L.map).length>20 && Object.values(L.map).every(v=>Array.isArray(v)&&v.length));
  T30('v12 toggle: topic with a v12 copy goes to the archive (vSphere guide)', L.fix(u+'mfa.html?ver=13',false,'VMware')==='https://helpcenter.veeam.com/archive/backup/120/vsphere/mfa.html');
  T30('v12 toggle on Hyper-V prefers the Hyper-V guide', L.fix(u+'mfa.html',false,'HyperV')==='https://helpcenter.veeam.com/archive/backup/120/hyperv/mfa.html');
  T30('upgrade-checklist link always stays on v13', L.fix(u+'upgrade_vbr_byb.html?ver=13',false,'VMware')===u+'upgrade_vbr_byb.html?ver=13');
  T30('v13 toggle leaves links unchanged; unknown topic unchanged', L.fix(u+'mfa.html',true,'VMware')===u+'mfa.html' && L.fix(u+'no_such_topic.html',false,'VMware')===u+'no_such_topic.html');
})();
// v3.0 fixes found against real logs — the REAL parseLog() from index.html runs on a synthetic
// log: BackupSync copy jobs (target recorded only as TargetRepositoryType), SOBR extents,
// hardened repos with no Enabled flag, an explicit "Enabled: False" with a Value, Cloud Connect
// repos (immutability set by the provider), session counters that are not job counts, and
// storage-snapshot immutability (disabled) that is not repository immutability.
(function(){
  const ctx=H.load(), vm={runInContext:(code,c)=>H.run(c,code)};
  const ts='[01.10.2026 10:00:00.000]    <18>    Info (3)    ', G=n=>`0000000${n}-1111-2222-3333-444444444444`;
  const bk=(jid,repo)=>`${ts}PlatformId: 00000000-0000-0000-0000-000000000000, PlatformName: VMware, JobID: ${jid}, Type: Backup, IsCloudTarget: False, JobSourceType: VDDK, IncludedSize: 1099511627776, ScheduleEnabled: True, Platform: EVmware, VMsCount: 2, BackupRepository: ${repo}, RetentionPolicy: { Value: 14, Unit: Points }, Storage: { CompressionLevel: Optimal, Encryption: { Enabled: True, EncryptionType: Password } }, SnapshotImmutability: { Enabled: False, ImmutabilityDays: 3 },`;
  const log=[
    'Product: [Veeam Backup and Replication], Version: [13.0.1.2067]',
    'CmdLineParams: [STARTCOLLECTINFRASTATISTIC]',
    ts+'=======================CURRENT JOBS INFO==========================',
    bk(G(1),G(5)), bk(G(2),G(7)),
    `${ts}PlatformId: 00000000-0000-0000-0000-000000000000, PlatformName: VMware, JobID: ${G(3)}, Type: BackupSync, JobSourceType: Backup, IncludedSize: 1099511627776, ScheduleEnabled: True, Platform: EVmware, SimpleRetentionPolicy: { Value: 31, Unit: Points }, TargetRepositoryType: Cloud, IsEncryptionEnabled: True,`,
    `${ts}PlatformId: 00000000-0000-0000-0000-000000000000, PlatformName: Configuration, JobID: ${G(4)}, Type: ConfBackup, IsEnabled: True, ScheduleEnabled: True, Platform: EConf, RetentionPolicy: 10, StorageEncryptionEnabled: True,`,
    `${ts}PlatformId: 00000000-0000-0000-0000-000000000000, PlatformName: [VMware], JobID: ${G(9)}, Type: SureBackupLite, JobSourceType: [VDDK], ScheduleEnabled: True, Platform: [EVmware], LinkedJobsNum: 1,`,
    ts+'[VmcStats] =CURRENT JOBS INFO= collection result: Success',
    ts+'[Other] CatCleanup: 95, ConfBackup: 91',
    ts+'[SureBackup] SureBackupLite: 40',
    ts+'[Agents] EpAgentBackup: 63',
    ts+'Job counts: { VDDKBackup: 2, BackupHV: 0, SurebackupVMware: 0, SurebackupHV: 0, SurebackupMultiplatform: 0, SurebackupLite: 1 }',
    ts+'=======================CURRENT REPOSITORIES==========================',
    `${ts}RepositoryID: ${G(5)}, Type: LinuxHardened, TotalSpace: 10995116277760, FreeSpace: 5497558138880, NumberOfBackups: 3, RepositoryGroupType: BackupRepository, ImmutabilitySettings: { Value: 7, Unit: Days },`,
    `${ts}RepositoryID: ${G(6)}, Type: HPStoreOnceIntegration, TotalSpace: 10995116277760, FreeSpace: 5497558138880, NumberOfBackups: 0, RepositoryGroupType: BackupRepository, ImmutabilitySettings: { Enabled: False, Value: 7, Unit: Days },`,
    `${ts}RepositoryID: ${G(7)}, Type: ExtendableRepository, TotalSpace: 10995116277760, FreeSpace: 5497558138880, NumOfExtents: 1, ExtentsIDs: [${G(8)}], NumberOfBackups: 2, RepositoryGroupType: BackupRepository,`,
    `${ts}RepositoryID: ${G(8)}, Type: LinuxHardened, TotalSpace: 10995116277760, FreeSpace: 5497558138880, NumberOfBackups: 0, RepositoryGroupType: BackupRepository, ImmutabilitySettings: { Value: 14, Unit: Days },`,
    `${ts}RepositoryID: ${G(0)}, Type: Cloud, TotalSpace: 10995116277760, FreeSpace: 5497558138880, NumberOfBackups: 1, RepositoryGroupType: BackupRepository`,
    ts+'[VmcStats] =CURRENT REPOSITORIES= collection result: Success, Collection time: 00:00:01',
    ts+'=======================REPOSITORY TYPE COUNTS=========================='].join('\n');
  let err=null; try{ ctx.L=log; vm.runInContext('parseLog(L,"VMC.log")',ctx); }catch(e){ err=e.message; }
  const D=ctx.D, bm=D.backupMap||{}, ep=D.encPosture||{}, jc=D.jobCounts||{};
  const S=n=>G(n).slice(0,8), r=n=>(D.repoList||[]).find(x=>x.id===S(n))||{};
  T30('fixture parses without error ('+(err||'ok')+')', !err);
  T30('BackupSync counted as a backup copy job', jc.BackupCopy===1 && bm.copyJobsTotal===1);
  T30('BackupSync with one Cloud repo: target inferred, Cloud repo not idle', (bm.idle||[]).every(i=>i.id!==S(0)) && (bm.nodes||[]).some(n=>n.id===G(0)));
  T30('job counts come from job records, not session counters (ConfBackup 1, SureBackupLite 1)', jc.ConfBackup===1 && jc.SureBackupLite===1);
  T30('SOBR extent is not reported idle', (bm.idle||[]).every(i=>i.id!==S(8)) && (bm.extents||[]).some(e=>e.id===S(8)&&e.parent===S(7)));
  T30('only the unused StoreOnce repo is idle', (bm.idle||[]).length===1 && bm.idle[0].id===S(6));
  T30('hardened repo with no Enabled flag is immutable; "Enabled: False, Value: 7" is not', !!r(5).immut && !r(6).immut);
  T30('Cloud repo: set by provider, not counted as missing; SOBR immutable via extents', ep.reposProvider===1 && ep.reposImmut===3 && ep.reposTot===4);
  T30('"[Agents] EpAgentBackup: 63" is not read as 63 AgentBackup or EndpointBackup jobs', !jc.AgentBackup && !jc.EndpointBackup);
  const run=t=>{ ctx.L=t; try{ vm.runInContext('parseLog(L,"VMC.log")',ctx); }catch(e){} return ctx.D||{}; };
  const vro=run(log.replace('Product: [Veeam Backup and Replication], Version: [13.0.1.2067]\nCmdLineParams: [STARTCOLLECTINFRASTATISTIC]','CmdLineParams: [STARTCOLLECTINFRASTATISTIC]\nProduct: [Veeam Recovery Orchestrator], Version: [13.0.0.1167]'));
  T30('other Veeam products (Recovery Orchestrator) are flagged, not read as a VBR build', vro.unsupportedFormat && /Orchestrator/.test(vro.unsupportedFormat.product) && !vro.vbr);
  const vbo=run('Product: [Veeam Backup for Microsoft 365], Version: [13.5.0.523]\n'+ts+'RepositoryID: '+G(1)+', Type: Repository,');
  T30('Veeam Backup for Microsoft 365 log is flagged', vbo.unsupportedFormat && /Microsoft 365/.test(vbo.unsupportedFormat.product));
  const part=run('Module: [x]. Product version: [13.0.2.29], Assembly version: [13.0.1.0]\nCmdLineParams: [STARTLOGSEXPORT 1]\n'+ts+'=======================LICENSE INFORMATION==========================\n'+ts+'License[1]: { Product: Veeam Backup and Replication }');
  T30('log that ends before the inventory sections is reported as incomplete', part.incompleteLog && part.incompleteLog.version==='13.0.2.29' && part.incompleteLog.lastSection==='LICENSE INFORMATION' && !part.unsupportedFormat);
  T30('a complete VBR log is neither incomplete nor unsupported', !D.incompleteLog && !D.unsupportedFormat);
  T30('disabled snapshot immutability (3 days) does not set the minimum period (7 days from the repos)', String(D.immutabilityMinDays)==='7');
})();
console.log(`v3.0:     ${pass-_p5} passed, ${fail-_f5} failed`);

// layer 2 — real reference logs (optional)
const dir = process.argv[2];
if (dir && fs.existsSync(dir)) {
  let cp=pass, cf=fail, present=0;
  Object.keys(EXPECT).forEach(fname=>{
    const fp=path.join(dir,fname); if(!fs.existsSync(fp)) return; present++;
    check(fname, evalReal(fs.readFileSync(fp,'utf8'), fname), EXPECT[fname]);
  });
  console.log(`Reference:   ${pass-cp} passed, ${fail-cf} failed (${present} reference file(s) present)`);
} else if (dir) {
  console.log(`Reference:   folder '${dir}' not found — skipped`);
}

// layer 3 — the 2026-10 audit fixes (tests/v3-fixes.test.js), counted here so CI runs them
(function(){
  const r=require('child_process').spawnSync(process.execPath,[path.join(__dirname,'tests','v3-fixes.test.js')],{encoding:'utf8'});
  process.stdout.write(r.stdout||''); if(r.stderr) process.stdout.write(r.stderr);
  if(r.status!==0){ fail++; fails.push('  tests/v3-fixes.test.js failed (see above)'); }
})();

if (fails.length){ console.log('\nFAILURES:'); fails.forEach(f=>console.log(f)); process.exit(1); }
console.log('\nAll assertions passed.');
