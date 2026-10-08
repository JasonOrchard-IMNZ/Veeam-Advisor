#!/usr/bin/env node
/*
 * confirm-bp-findings.js — regression guard for the single-server BP Review findings.
 *
 * Two layers:
 *   1. SYNTHETIC FIXTURES (always run, no external files) — assert the five corrected
 *      extractors against hand-built log snippets that reproduce the field shapes from the
 *      validated reference set. Safe for CI: contains NO customer data and needs no VMC.log on disk.
 *   2. REAL REFERENCE LOGS (optional) — pass a folder of VMC.logs as argv[2] to additionally assert
 *      the per-file expected outcomes. Customer logs must NOT be committed to the repo.
 *
 * The extractors below MUST mirror the tool's parse logic in Veeam_Advisor_v1.1.0.html.
 * If you change the tool's logic, change it here too — a divergence is a real regression.
 *
 * Usage:  node confirm-bp-findings.js                 # fixtures only (CI)
 *         node confirm-bp-findings.js <logs-folder>   # fixtures + real reference logs
 * Exit:   0 = all passed, 1 = one or more failed
 */
const fs = require('fs');
const path = require('path');

// ── tool-equivalent preprocessing ──────────────────────────────────────────────
function stripRTF(s){ s=s.replace(/\\([a-z]+-?\d*)\s?/g,' '); s=s.replace(/[{}\\]/g,' '); return s; }
function mostRecentFull(t){
  const parts=t.split(/Starting new log/); let best=null,bt=-1,any=false;
  parts.forEach(b=>{ if(!/CURRENT JOBS INFO/.test(b)) return; any=true;
    const ms=[...b.matchAll(/\[(\d{2})\.(\d{2})\.(\d{4})/g)];
    const tt=ms.length?new Date(+ms.at(-1)[3],+ms.at(-1)[2]-1,+ms.at(-1)[1]).getTime():0;
    if(tt>=bt){bt=tt;best=b;} });
  return any?best:t;
}

// ── the five corrected extractors (mirror of v1.0.3) ────────────────────────────
function encryption(t){                                   // FIX #1
  const v=[]; t.split('\n').forEach(l=>{
    if(!/JobID:\s*[\w-]+,\s*Type:\s*Backup,/.test(l) || l.indexOf('PlatformName:')<0) return;
    const m=l.match(/Encryption:\s*\{?\s*Enabled:\s*(True|False)/); if(m) v.push(m[1]);
  });
  if(!v.length) return 'silent';
  return v.filter(x=>x==='False').length===0 ? 'silent' : 'crit';
}
function malware(t){                                       // FIX #2
  const sum=re=>(t.match(re)||[]).reduce((a,s)=>a+parseInt(s.replace(/\D/g,''),10),0);
  const inf=sum(/OIBsInfectedCount:\s*(\d+)/g), sus=sum(/OIBsSuspiciousCount:\s*(\d+)/g);
  const ev=+(t.match(/EventsTotalCount:\s*(\d+)/)||[0,0])[1];
  if(inf>0) return 'crit'; if(sus>0) return 'warn'; if(ev>0) return 'info'; return 'silent';
}
function vmsPerJob(t){                                     // FIX #3
  let mx=0; t.split('\n').filter(l=>l.includes('Type: Backup,')&&l.includes('PlatformName:'))
    .forEach(l=>{const m=l.match(/VMsCount:\s*(\d+)/); if(m) mx=Math.max(mx,+m[1]);});
  return mx>300?'crit':(mx>100?'info':(mx>0?'ok':'-'));
}
function majorityDisabled(t, field){                       // FIX #4 / #5
  const v=[]; t.split('\n').forEach(l=>{ if(l.indexOf('JobID:')<0) return;
    const m=l.match(new RegExp(field+'\\s*:\\s*\\{?\\s*Enabled:\\s*(True|False)')); if(m) v.push(m[1]); });
  if(!v.length) return 'silent';
  return v.filter(x=>x==='False').length > v.length/2 ? 'warn' : 'ok';
}
function evalAll(t){ return {
  enc: encryption(t), mal: malware(t), vm: vmsPerJob(t),
  hc: majorityDisabled(t,'HealthCheck'), dv: majorityDisabled(t,'DeletedVMRetention') }; }

// ── synthetic fixtures (no customer data) ───────────────────────────────────────
const HDR = '=======================CURRENT JOBS INFO==========================\n';
// one VM backup-job line carrying encryption / health-check / deleted-VM / VM-count fields
const job = (id,enc,hc,dv,vms) =>
  `PlatformName: VMware, JobID: ${id}, Type: Backup, Encryption: { Enabled: ${enc} }, `+
  `HealthCheck : { Enabled: ${hc}, FullHealthCheckEnabled: True }, `+
  `DeletedVMRetention : { Enabled: ${dv}, Days: 30 }, VMsCount: ${vms}`;
const malLine = (ev,inf,sus) =>
  `Malware events counts: { EventsTotalCount: ${ev}, RansomwareExtensionsCount: ${ev} }\n`+
  `OIBsRansomwareStatusCounts: { ManuallyChecked: { OIBsInfectedCount: 0, OIBsSuspiciousCount: 0 }, `+
  `DetectedByVeeam: { OIBsInfectedCount: ${inf}, OIBsSuspiciousCount: ${sus} } }`;
const id = n => `aaaaaaaa-0000-0000-0000-00000000000${n}`;

// ── v1.1.0 mirrors: per-job-type classification + agent licence reconciliation ──
// These MUST mirror the v1.1.0 data layer in Veeam_Advisor_v1.1.0.html (TYPEMAP,
// agent recon). A divergence is a real regression.
const TYPEMAP_11 = {Backup:'Backup Job',BCSMPolicy:'Backup copy job',ConfBackup:'Config backup',
  AgentBackup:'Agent backup',AgentPolicy:'Agent backup',EpAgentManagement:'Agent backup (mgmt)',
  SureBackupLite:'SureBackup (scan only)',SureBackup:'SureBackup (virtual labs)'};
function jobRecords11(t){
  const seen={}, recs=[];
  t.split('\n').forEach(l=>{
    const tm=l.match(/JobID:\s*([\w-]+),\s*Type:\s*(\w+)/); if(!tm) return;
    if(seen[tm[1]]) return; seen[tm[1]]=1;
    const e=l.match(/Encryption:\s*\{?\s*Enabled:\s*(True|False)/);
    const ct=l.match(/ComputerType:\s*(\w+)/);
    recs.push({type:tm[2], common:(TYPEMAP_11[tm[2]]||'Other'), enc:e?e[1]:null, computerType:ct?ct[1]:null});
  });
  return recs;
}
function classify11(t){ const m={}; jobRecords11(t).forEach(r=>{m[r.common]=(m[r.common]||0)+1;}); return m; }
function agentRecon11(t,licSrv,licWks,perpetual){
  let srv=0,wks=0,standalone=0;
  jobRecords11(t).forEach(j=>{
    if(j.type==='AgentBackup'||j.type==='AgentPolicy'){ if(j.computerType==='Workstation')wks++; else srv++; }
    else if(j.type==='EndpointBackup') standalone++;
  });
  const wksInst = wks>0?Math.ceil(wks/3):0;
  return { srv, wks, standalone, expSrvInst:srv, expWksInst:wksInst,
    reconciles: perpetual || (srv===licSrv && wksInst===licWks) || (srv===0&&wks===0&&standalone>0&&(licSrv+licWks)>0),
    overServer: (!perpetual && srv>licSrv) };
}

const FIXTURES = [
  // FIX #1 encryption
  { name:'enc: all jobs encrypted -> silent',
    text: HDR+job(id(1),'True','True','True',10)+'\n'+job(id(2),'True','True','True',10),
    expect:{ enc:'silent' } },
  { name:'enc: one job unencrypted -> crit',
    text: HDR+job(id(1),'True','True','True',10)+'\n'+job(id(2),'False','True','True',10),
    expect:{ enc:'crit' } },
  { name:'enc: RTF-stripped (no braces) unencrypted -> crit',
    text: HDR+'PlatformName: VMware, JobID: '+id(3)+', Type: Backup, Encryption:   Enabled: False  , VMsCount: 5',
    expect:{ enc:'crit' } },
  { name:'enc: no backup jobs (replica only) -> silent',
    text: HDR+'PlatformName: VMware, JobID: '+id(4)+', Type: Replica, VMsCount: 3',
    expect:{ enc:'silent', vm:'-' } },
  // FIX #2 malware
  { name:'malware: infected restore points -> crit',
    text: HDR+malLine(50,2,0), expect:{ mal:'crit' } },
  { name:'malware: suspicious only -> warn',
    text: HDR+malLine(800,0,5), expect:{ mal:'warn' } },
  { name:'malware: events but 0 infected/suspicious -> info (host-F case)',
    text: HDR+malLine(4000,0,0), expect:{ mal:'info' } },
  { name:'malware: no events -> silent',
    text: HDR+job(id(1),'True','True','True',10), expect:{ mal:'silent' } },
  // FIX #3 VMs per job
  { name:'vms: >300 -> crit',  text: HDR+job(id(1),'True','True','True',350), expect:{ vm:'crit' } },
  { name:'vms: 100-300 -> info',text: HDR+job(id(1),'True','True','True',150), expect:{ vm:'info' } },
  { name:'vms: <=100 -> ok',    text: HDR+job(id(1),'True','True','True',50),  expect:{ vm:'ok' } },
  // FIX #4 / #5 majority
  { name:'healthCheck/delVM: majority disabled -> warn',
    text: HDR+job(id(1),'True','False','False',10)+'\n'+job(id(2),'True','False','False',10)+'\n'+job(id(3),'True','True','True',10),
    expect:{ hc:'warn', dv:'warn' } },
  { name:'healthCheck/delVM: majority enabled -> ok',
    text: HDR+job(id(1),'True','True','True',10)+'\n'+job(id(2),'True','True','True',10)+'\n'+job(id(3),'True','False','False',10),
    expect:{ hc:'ok', dv:'ok' } },
];

// ── reference-log expectations (only files present in the target folder are asserted) ──
const EXPECT = {
  'VMC.log':{enc:'silent',vm:'info'}, 'log-08.log':{enc:'silent'},
  'log-03.log':{enc:'crit',mal:'warn'}, 'log-05.log':{enc:'crit',vm:'crit'},
  'log-01.log':{enc:'crit',mal:'warn'},
  'log-02.log':{enc:'crit',hc:'ok',dv:'ok'}, 'log-07.log':{enc:'crit',hc:'ok',dv:'ok'},
  'log-10.log':{enc:'crit',dv:'ok'}, 'log-04.log':{enc:'silent'},
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
FIXTURES.forEach(f=> check(f.name, evalAll(mostRecentFull(f.text)), f.expect));
console.log(`Fixtures: ${pass} passed, ${fail} failed`);

// layer 1b — v1.1.0 fixtures: per-job-type classification + agent reconciliation
const _p0=pass, _f0=fail;
function T11(label, cond){ if(cond) pass++; else { fail++; fails.push(`  v1.1.0: ${label}`); } }
(function(){
  // classification (TYPEMAP)
  T11('classify BCSMPolicy -> Backup copy job', classify11('JobID: a, Type: BCSMPolicy, PlatformName: X\n')['Backup copy job']===1);
  T11('classify AgentPolicy(Workstation) -> Agent backup', jobRecords11('JobID: b, Type: AgentPolicy, ComputerType: Workstation\n')[0].common==='Agent backup');
  T11('classify EpAgentManagement -> Agent backup (mgmt)', jobRecords11('JobID: c, Type: EpAgentManagement, X\n')[0].common==='Agent backup (mgmt)');
  T11('classify unknown type -> Other', jobRecords11('JobID: d, Type: NasBackup, X\n')[0].common==='Other');
  T11('jobRecords de-dupes by JobID', jobRecords11('JobID: e, Type: Backup, X\nJobID: e, Type: Backup, X\n').length===1);

  // agent reconciliation — host-A shape: 1 server + 2 workstation managed + 2 standalone, lic 1/1
  const hvb=agentRecon11('JobID: s1, Type: AgentBackup, ComputerType: Server\nJobID: w1, Type: AgentPolicy, ComputerType: Workstation\nJobID: w2, Type: AgentPolicy, ComputerType: Workstation\nJobID: e1, Type: EndpointBackup, X\nJobID: e2, Type: EndpointBackup, X\n',1,1,false);
  T11('recon host-A: 1 srv / 2 wks / 2 standalone', hvb.srv===1&&hvb.wks===2&&hvb.standalone===2);
  T11('recon host-A: 2 wks -> 1 instance (ceil/3)', hvb.expWksInst===1);
  T11('recon host-A: reconciles 1/1', hvb.reconciles===true);
  T11('recon host-A: not over-licensed', hvb.overServer===false);

  // workstation rounding: 4 workstations -> 2 instances
  const w4=agentRecon11('JobID: a, Type: AgentPolicy, ComputerType: Workstation\nJobID: b, Type: AgentPolicy, ComputerType: Workstation\nJobID: c, Type: AgentPolicy, ComputerType: Workstation\nJobID: d, Type: AgentPolicy, ComputerType: Workstation\n',0,2,false);
  T11('recon: 4 wks -> 2 instances (ceil), reconciles', w4.expWksInst===2 && w4.reconciles===true);

  // over-licence: 2 servers, 1 licensed -> overServer fires
  const over=agentRecon11('JobID: a, Type: AgentBackup, ComputerType: Server\nJobID: b, Type: AgentBackup, ComputerType: Server\n',1,0,false);
  T11('recon: 2 srv vs 1 lic -> over-licence fires', over.overServer===true);

  // perpetual: server agent present, sockets cover -> reconciles, no over-licence
  const perp=agentRecon11('JobID: a, Type: AgentBackup, ComputerType: Server\n',0,0,true);
  T11('recon: perpetual covers agents (no over-licence)', perp.reconciles===true && perp.overServer===false);

  // standalone covers a workstation licence (host-J shape: 0 managed, 1 standalone, lic 0/1)
  const sa=agentRecon11('JobID: e, Type: EndpointBackup, X\n',0,1,false);
  T11('recon: standalone agent covers workstation licence', sa.reconciles===true);

  // unknown ComputerType counts as server (conservative)
  const unk=agentRecon11('JobID: a, Type: AgentBackup, X\n',1,0,false);
  T11('recon: unknown ComputerType -> server', unk.srv===1 && unk.reconciles===true);
})();
console.log(`v1.1.0:   ${pass-_p0} passed, ${fail-_f0} failed`);

// layer 1c — v2.3 security-advisory check. Loads the REAL vaBuildCheck() from index.html
// (between the VA-ADVISORIES markers) and drives it with FIXED synthetic advisory data, so
// these assertions do not change when tools/build-advisories.mjs refreshes the embedded copy.
// The embedded copy itself is only checked for shape.
const _p1=pass, _f1=fail;
function T23(label, cond){ if(cond) pass++; else { fail++; fails.push(`  v2.3: ${label}`); } }
(function(){
  const html=fs.readFileSync(path.join(__dirname,'index.html'),'utf8');
  const a=html.indexOf('/*VA-ADVISORIES:START*/'), b=html.indexOf('  function calculate(){',a);
  if(a<0||b<0){ T23('advisory block and vaBuildCheck present in index.html', false); return; }
  const api=new Function(html.slice(a,b)+'; return {check:vaBuildCheck, data:function(){return VA_ADVISORIES;}, set:function(d){VA_ADVISORIES=d;}};')();
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
  const html=fs.readFileSync(path.join(__dirname,'index.html'),'utf8');
  const a=html.indexOf('/*VA-ADVISORIES:START*/'), b=html.indexOf('  function calculate(){',a);
  if(html.indexOf('function vaUpgradeReadiness',a)<0||b<0){ T24('vaUpgradeReadiness present in index.html', false); return; }
  const api=new Function(html.slice(a,b)+'; return {u:vaUpgradeReadiness, set:function(d){VA_ADVISORIES=d;}};')();
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
  const html=fs.readFileSync(path.join(__dirname,'index.html'),'utf8');
  const a=html.indexOf('/*VA-ADVISORIES:START*/'), b=html.indexOf('  function calculate(){',a);
  if(html.indexOf('var VA_SCA=',a)<0||b<0){ T25('VA_SCA present in index.html', false); return; }
  const api=new Function(html.slice(a,b)+'; return {map:VA_SCA, info:vaScaInfo};')();
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
  const html=fs.readFileSync(path.join(__dirname,'index.html'),'utf8');
  const a=html.indexOf('// v2.6: Resilience scorecard.'), b=html.indexOf('var VA_RES_LABEL',a);
  if(a<0||b<0){ T26('vaResilience present in index.html', false); return; }
  const res=new Function(html.slice(a,b)+'; return vaResilience;')();
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
  const html=fs.readFileSync(path.join(__dirname,'index.html'),'utf8');
  const a=html.indexOf('/*VA-ADVISORIES:START*/'), b=html.indexOf('  function calculate(){',a);
  if(html.indexOf('function vaFastClone',a)<0||html.indexOf('function vaPlatformSupport',a)<0){ T30('v3.0 functions present in index.html', false); return; }
  const mk=(pre)=>new Function((pre||'')+html.slice(a,b)+'; return {fc:vaFastClone, plat:vaPlatformSupport, patch:vaVbrWithPatch};')();
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
  const ps=html.indexOf('function parseMapCapture(text){'), pe=html.indexOf('function applyCaptureToMap(){',ps);
  const parse=new Function(html.slice(ps,pe)+'; return parseMapCapture;')();
  const cap=parse(['Veeam Advisor — Backup Map capture','Host: LAB-VBR-01   Date: 2026-10-01','Backup server build : 12.3.2.4854','Backup server patch : P20250901',
    '  SRV | ESXi | 8.0.3.0 | VMware ESXi 8.0.3 build-1 | esx1.lab','  SRV | HvServer | n/a (null) | n/a (null) | hv1.lab'].join('\n'));
  T30('MapCapture Section 7: build, patch and servers parsed; n/a values become null', cap.bsBuild==='12.3.2.4854' && cap.bsPatch==='20250901' && cap.servers.length===2 && cap.servers[1].api===null && cap.servers[0].name==='esx1.lab');
  // Version-correct links (real VA_LINKS12 map)
  const ls=html.indexOf('/*VA-LINKS12:START*/'), le=html.indexOf('function encryptionSection',ls);
  const L=new Function(html.slice(ls,le)+'; return {map:VA_LINKS12, fix:vaVersionLinks};')();
  const u='https://helpcenter.veeam.com/docs/vbr/userguide/';
  T30('v12 links map is populated and well-formed', Object.keys(L.map).length>20 && Object.values(L.map).every(v=>Array.isArray(v)&&v.length));
  T30('v12 toggle: topic with a v12 copy goes to the archive (vSphere guide)', L.fix(u+'mfa.html?ver=13',false,'VMware')==='https://helpcenter.veeam.com/archive/backup/120/vsphere/mfa.html');
  T30('v12 toggle on Hyper-V prefers the Hyper-V guide', L.fix(u+'mfa.html',false,'HyperV')==='https://helpcenter.veeam.com/archive/backup/120/hyperv/mfa.html');
  T30('upgrade-checklist link always stays on v13', L.fix(u+'upgrade_vbr_byb.html?ver=13',false,'VMware')===u+'upgrade_vbr_byb.html?ver=13');
  T30('v13 toggle leaves links unchanged; unknown topic unchanged', L.fix(u+'mfa.html',true,'VMware')===u+'mfa.html' && L.fix(u+'no_such_topic.html',false,'VMware')===u+'no_such_topic.html');
})();
console.log(`v3.0:     ${pass-_p5} passed, ${fail-_f5} failed`);

// layer 2 — real reference logs (optional)
const dir = process.argv[2];
if (dir && fs.existsSync(dir)) {
  let cp=pass, cf=fail, present=0;
  Object.keys(EXPECT).forEach(fname=>{
    const fp=path.join(dir,fname); if(!fs.existsSync(fp)) return; present++;
    let t=fs.readFileSync(fp,'utf8'); if(t.trimStart().startsWith('{\\rtf')) t=stripRTF(t);
    check(fname, evalAll(mostRecentFull(t)), EXPECT[fname]);
  });
  console.log(`Reference:   ${pass-cp} passed, ${fail-cf} failed (${present} reference file(s) present)`);
} else if (dir) {
  console.log(`Reference:   folder '${dir}' not found — skipped`);
}

if (fails.length){ console.log('\nFAILURES:'); fails.forEach(f=>console.log(f)); process.exit(1); }
console.log('\nAll assertions passed.');
