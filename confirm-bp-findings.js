#!/usr/bin/env node
/*
 * confirm-bp-findings.js — regression guard for the single-server BP Review findings.
 *
 * Two layers:
 *   1. SYNTHETIC FIXTURES (always run, no external files) — assert the five corrected
 *      extractors against hand-built log snippets that reproduce the field shapes from the
 *      validated corpus. Safe for CI: contains NO customer data and needs no VMC.log on disk.
 *   2. REAL CORPUS (optional) — pass a folder of VMC.logs as argv[2] to additionally assert
 *      the per-file expected outcomes. Customer logs must NOT be committed to the repo.
 *
 * The extractors below MUST mirror the tool's parse logic in Veeam_Advisor_v1.1.0.html.
 * If you change the tool's logic, change it here too — a divergence is a real regression.
 *
 * Usage:  node confirm-bp-findings.js                 # fixtures only (CI)
 *         node confirm-bp-findings.js <logs-folder>   # fixtures + real corpus
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
  { name:'malware: events but 0 infected/suspicious -> info (Tatua case)',
    text: HDR+malLine(4529,0,0), expect:{ mal:'info' } },
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

// ── corpus expectations (only files present in the target folder are asserted) ──
const EXPECT = {
  'VMC.log':{enc:'silent',vm:'info'}, 'mdc-VMC.log':{enc:'silent'},
  'VMC-Tatua.txt':{enc:'crit',mal:'warn'}, 'datacom-VMC.log':{enc:'crit',vm:'crit'},
  'Manux-VMC-AKL-Prod_may_2026.log':{enc:'crit',mal:'warn'},
  'MillBrook-VMC.log':{enc:'crit',hc:'ok',dv:'ok'}, 'may25-eliveVMC.log':{enc:'crit',hc:'ok',dv:'ok'},
  'wrhnbak01-VMC.log':{enc:'crit',dv:'ok'}, 'VSA-VMC.log':{enc:'silent'},
  'hv-a-VMC.log':{enc:'silent'}, 'vrb-orc-VMC.log':{enc:'silent'},
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

  // agent reconciliation — hv-b shape: 1 server + 2 workstation managed + 2 standalone, lic 1/1
  const hvb=agentRecon11('JobID: s1, Type: AgentBackup, ComputerType: Server\nJobID: w1, Type: AgentPolicy, ComputerType: Workstation\nJobID: w2, Type: AgentPolicy, ComputerType: Workstation\nJobID: e1, Type: EndpointBackup, X\nJobID: e2, Type: EndpointBackup, X\n',1,1,false);
  T11('recon hv-b: 1 srv / 2 wks / 2 standalone', hvb.srv===1&&hvb.wks===2&&hvb.standalone===2);
  T11('recon hv-b: 2 wks -> 1 instance (ceil/3)', hvb.expWksInst===1);
  T11('recon hv-b: reconciles 1/1', hvb.reconciles===true);
  T11('recon hv-b: not over-licensed', hvb.overServer===false);

  // workstation rounding: 4 workstations -> 2 instances
  const w4=agentRecon11('JobID: a, Type: AgentPolicy, ComputerType: Workstation\nJobID: b, Type: AgentPolicy, ComputerType: Workstation\nJobID: c, Type: AgentPolicy, ComputerType: Workstation\nJobID: d, Type: AgentPolicy, ComputerType: Workstation\n',0,2,false);
  T11('recon: 4 wks -> 2 instances (ceil), reconciles', w4.expWksInst===2 && w4.reconciles===true);

  // over-licence: 2 servers, 1 licensed -> overServer fires
  const over=agentRecon11('JobID: a, Type: AgentBackup, ComputerType: Server\nJobID: b, Type: AgentBackup, ComputerType: Server\n',1,0,false);
  T11('recon: 2 srv vs 1 lic -> over-licence fires', over.overServer===true);

  // perpetual: server agent present, sockets cover -> reconciles, no over-licence
  const perp=agentRecon11('JobID: a, Type: AgentBackup, ComputerType: Server\n',0,0,true);
  T11('recon: perpetual covers agents (no over-licence)', perp.reconciles===true && perp.overServer===false);

  // standalone covers a workstation licence (hv-a shape: 0 managed, 1 standalone, lic 0/1)
  const sa=agentRecon11('JobID: e, Type: EndpointBackup, X\n',0,1,false);
  T11('recon: standalone agent covers workstation licence', sa.reconciles===true);

  // unknown ComputerType counts as server (conservative)
  const unk=agentRecon11('JobID: a, Type: AgentBackup, X\n',1,0,false);
  T11('recon: unknown ComputerType -> server', unk.srv===1 && unk.reconciles===true);
})();
console.log(`v1.1.0:   ${pass-_p0} passed, ${fail-_f0} failed`);

// layer 2 — real corpus (optional)
const dir = process.argv[2];
if (dir && fs.existsSync(dir)) {
  let cp=pass, cf=fail, present=0;
  Object.keys(EXPECT).forEach(fname=>{
    const fp=path.join(dir,fname); if(!fs.existsSync(fp)) return; present++;
    let t=fs.readFileSync(fp,'utf8'); if(t.trimStart().startsWith('{\\rtf')) t=stripRTF(t);
    check(fname, evalAll(mostRecentFull(t)), EXPECT[fname]);
  });
  console.log(`Corpus:   ${pass-cp} passed, ${fail-cf} failed (${present} reference file(s) present)`);
} else if (dir) {
  console.log(`Corpus:   folder '${dir}' not found — skipped`);
}

if (fails.length){ console.log('\nFAILURES:'); fails.forEach(f=>console.log(f)); process.exit(1); }
console.log('\nAll assertions passed.');
