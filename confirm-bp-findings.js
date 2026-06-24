#!/usr/bin/env node
/*
 * confirm-bp-findings.js — regression guard for the single-server BP Review findings.
 *
 * Why this exists: confirm-outputs.js validates the FLEET tool (coverage math + render
 * safety) and never exercises the single-server findings path, where the v1.0.3
 * false-positive fixes live. This test encodes the corrected extraction logic and asserts
 * the expected outcome for each of the five fixed findings against the reference VMC.log
 * corpus (VBR 12.1 / 12.2 / 12.3 and 13.x, RTF + plain, VMware / Hyper-V / agent / CC).
 *
 * The extractors below MUST mirror the tool's parse logic in Veeam_Advisor_v1.0.3.html.
 * If you change the tool's logic, change it here too — a divergence is a real regression.
 *
 * Usage:  node confirm-bp-findings.js [path-to-folder-of-VMC-logs]
 *         (defaults to ./reference-logs, then the current directory)
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
function load(p){ let r=fs.readFileSync(p,'utf8'); if(r.trimStart().startsWith('{\\rtf')) r=stripRTF(r); return mostRecentFull(r); }

// ── the five corrected extractors (mirror of v1.0.3) ────────────────────────────
function encryption(t){                                   // FIX #1
  const v=[]; t.split('\n').forEach(l=>{
    if(!/JobID:\s*[\w-]+,\s*Type:\s*Backup,/.test(l) || l.indexOf('PlatformName:')<0) return;
    const m=l.match(/Encryption:\s*\{?\s*Enabled:\s*(True|False)/); if(m) v.push(m[1]);
  });
  if(!v.length) return {verdict:'silent', unenc:0, total:0};        // no backup jobs → silent
  const unenc=v.filter(x=>x==='False').length;
  return {verdict: unenc===0?'silent':'crit', unenc, total:v.length};
}
function malware(t){                                      // FIX #2
  const sum=re=>(t.match(re)||[]).reduce((a,s)=>a+parseInt(s.replace(/\D/g,''),10),0);
  const inf=sum(/OIBsInfectedCount:\s*(\d+)/g), sus=sum(/OIBsSuspiciousCount:\s*(\d+)/g);
  const ev=+(t.match(/EventsTotalCount:\s*(\d+)/)||[0,0])[1];
  if(inf>0) return {verdict:'crit', inf, sus};
  if(sus>0) return {verdict:'warn', inf, sus};
  if(ev>0)  return {verdict:'info', inf, sus};
  return {verdict:'silent', inf, sus};
}
function vmsPerJob(t){                                     // FIX #3
  let mx=0; t.split('\n').filter(l=>l.includes('Type: Backup,')&&l.includes('PlatformName:'))
    .forEach(l=>{const m=l.match(/VMsCount:\s*(\d+)/); if(m) mx=Math.max(mx,+m[1]);});
  return {max:mx, verdict: mx>300?'crit':(mx>100?'info':'ok')};
}
function majorityDisabled(t, field){                      // FIX #4 / #5
  const v=[]; t.split('\n').forEach(l=>{ if(l.indexOf('JobID:')<0) return;
    const m=l.match(new RegExp(field+'\\s*:\\s*\\{?\\s*Enabled:\\s*(True|False)')); if(m) v.push(m[1]); });
  if(!v.length) return {verdict:'silent'};
  const off=v.filter(x=>x==='False').length;
  return {verdict: off>v.length/2 ? 'warn' : 'ok'};
}

// ── expected outcomes (from the validated 20-log corpus) ────────────────────────
// Only files present in the target folder are asserted; others are skipped.
const EXPECT = {
  'VMC.log':                                  { enc:'silent', mal:'info', vm:'info', hc:'warn', dv:'warn' }, // ANZCO 13.0.2 — all encrypted
  'mdc-VMC.log':                              { enc:'silent', mal:'silent', vm:'ok' },                       // 12.2 — all encrypted
  'VMC-Tatua.txt':                            { enc:'crit', mal:'warn', vm:'ok' },                           // 12.1 RTF — unenc + suspicious OIBs
  'Manux-VMC-AKL-Prod_may_2026.log':          { enc:'crit', mal:'warn' },                                    // suspicious OIBs
  'Manux-VMC-CHC-PROD_may_2026.log':          { enc:'crit', vm:'ok' },
  'datacom-VMC.log':                          { enc:'crit', vm:'crit' },                                     // 381-VM job
  'Enterprise_Services_New_Zealand_jun2026_VMC.log': { enc:'crit' },
  'MillBrook-VMC.log':                        { enc:'crit', hc:'ok', dv:'ok' },                              // HC/DV actually enabled
  'may25-eliveVMC.log':                       { enc:'crit', hc:'ok', dv:'ok' },                              // HC/DV actually enabled
  'wrhnbak01-VMC.log':                        { enc:'crit', dv:'ok' },                                       // DV actually enabled
  'procare-VMC.log':                          { enc:'crit', vm:'ok' },
  'Richo-motta_16_june_2025_VMC.log':         { enc:'crit' },
  'vbr-sp-VMC.log':                           { enc:'crit' },
  'hv-b-VMC.log':                             { enc:'crit', mal:'info' },
  'hv-b-agent-VMC-v2.log':                    { enc:'crit', mal:'info' },
  'VSA-VMC.log':                              { enc:'silent' },                                              // no backup jobs
  'hv-a-VMC.log':                             { enc:'silent' },
  'vrb-orc-VMC.log':                          { enc:'silent' },
};

const dirArg = process.argv[2];
const dir = [dirArg, path.join(__dirname,'reference-logs'), '.'].find(d=>d&&fs.existsSync(d));
let pass=0, fail=0, skip=0;
const fails=[];
Object.keys(EXPECT).forEach(fname=>{
  const fp=path.join(dir,fname);
  if(!fs.existsSync(fp)){ skip++; return; }
  const t=load(fp), exp=EXPECT[fname];
  const got={ enc:encryption(t).verdict, mal:malware(t).verdict, vm:vmsPerJob(t).verdict,
              hc:majorityDisabled(t,'HealthCheck').verdict, dv:majorityDisabled(t,'DeletedVMRetention').verdict };
  Object.keys(exp).forEach(k=>{
    if(got[k]===exp[k]) pass++;
    else { fail++; fails.push(`  ${fname}  [${k}] expected '${exp[k]}' got '${got[k]}'`); }
  });
});

console.log(`BP-findings regression: ${pass} passed, ${fail} failed, ${skip} file(s) not present`);
if(fails.length){ console.log('FAILURES:'); fails.forEach(f=>console.log(f)); process.exit(1); }
console.log('All present reference logs match expected BP-Review outcomes.');
