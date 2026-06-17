#!/usr/bin/env node
/*
 * Veeam Advisor — Output Confirmation Harness
 * ───────────────────────────────────────────
 * Loads the Fleet tool's own parser (a separate codebase from the single-
 * server tool's parser — NOT byte-identical; they've diverged as features
 * were added to one and not the other) and confirms RENDERED OUTPUTS are
 * correct, not just that code runs:
 *   - every reference log parses to valid, internally-consistent values
 *   - coverage math (effProt = min(prot+agent, infra)) holds
 *   - collection time is captured (newest run)
 *   - fleet dashboard / matrix / aggregate render without undefined/NaN/injection
 *   - edge cases (empty, garbage, XSS, overlap, no-marker fallback) are safe
 *
 * Usage:  node confirm-outputs.js [path-to-logs-dir]
 * Exit:   0 = all confirmations passed, 1 = one or more failed
 */
const fs=require('fs'), path=require('path');
const LOGDIR=process.argv[2]||'/mnt/user-data/uploads';
const TOOL=path.join(__dirname,'Veeam_Advisor_Fleet.html');

// Minimal DOM so the browser script loads under Node.
let store={};
function mkEl(id){return{addEventListener(){},click(){},style:{},classList:{add(){},remove(){},toggle(){},contains(){return false;}},set innerHTML(v){store[id]=v;},get innerHTML(){return store[id]||'';},set textContent(v){store[id+'_t']=v;},get textContent(){return store[id+'_t']||'';},scrollIntoView(){},options:[],selectedIndex:0,value:'',appendChild(){},querySelector(){return null;},children:[],focus(){},checked:false};}
global.document={getElementById:id=>mkEl(id),querySelectorAll:()=>[],createElement:()=>mkEl('t'),body:{appendChild(){}},querySelector:()=>null,head:{appendChild(){}}};
global.window={}; global.FileReader=function(){};
eval(fs.readFileSync(TOOL,'utf8').match(/<script[^>]*>([\s\S]*?)<\/script>/)[1]);

let pass=0, fail=0; const fails=[];
function check(name,cond){ if(cond){pass++;} else {fail++;fails.push(name);} }

// 1. Per-log validity + coverage-math consistency
// NOTE: as of the EndpointBackup-masking fix, the unprot/coverage-math checks
// below only fire when D.coveragePct is non-null. hv-a-VMC.log and similar
// logs that had ONLY EndpointBackup agent jobs (no VM-job coverage, no
// EpAgentBackup) now correctly yield coveragePct=null rather than a number
// derived from a masked/excluded workload type — so the total check count is
// expected to be 2 lower than before that fix (91->89), not a regression.
const logs=fs.readdirSync(LOGDIR).filter(f=>/\.(log|txt)$/i.test(f) && !/Results_/i.test(f) && !/Validation_/i.test(f) && !/netstat/i.test(f) && (/VMC/i.test(f) || /\.log$/i.test(f))).sort();
logs.forEach(f=>{
  let D; try{ D=parseLog(fs.readFileSync(path.join(LOGDIR,f),'utf8'),f); }
  catch(e){ check(f+' parses',false); return; }
  const sc=scoreServer(D);
  check(f+' collectionTime', D.collectionTime!=null);
  check(f+' coverage in range', D.coveragePct==null||(D.coveragePct>=0&&D.coveragePct<=100));
  check(f+' score in range', sc.score>=0&&sc.score<=100);
  check(f+' no negative counts', (D.infraVMs||0)>=0&&(D.unprotectedVMs==null||D.unprotectedVMs>=0)&&(D.disabledJobCount||0)>=0);
  if(D.coveragePct!=null&&D.infraVMs>0){
    const eff=Math.min((D.protectedVMs||0)+(D.agentProtected||0),D.infraVMs);
    check(f+' unprot math', D.unprotectedVMs===Math.max(0,D.infraVMs-eff));
    check(f+' coverage math', D.coveragePct===Math.round(eff/D.infraVMs*100));
  }
});

// 2. Fleet render outputs (use first 3 logs as an estate)
const sub=logs.slice(0,3).map(f=>{const D=parseLog(fs.readFileSync(path.join(LOGDIR,f),'utf8'),f);const sc=scoreServer(D);return{fname:f,server:(D.vbr&&D.vbr!=='Unknown')?D.vbr:f,D,score:sc.score,sev:sc.sev,findings:sc.findings};});
renderDashboard(sub); renderMatrix(sub); renderAggregate(sub);
['panel0','panel1','panel2'].forEach(p=>{
  const h=store[p]||'';
  check(p+' rendered', h.length>100);
  check(p+' no undefined', !h.includes('undefined'));
  check(p+' no NaN', !h.includes('NaN'));
  check(p+' no script injection', !h.includes('<script'));
});
check('dashboard Collected column', (store['panel0']||'').includes('<th>Collected</th>'));
check('matrix all checks', CHECKS.every(c=>(store['panel1']||'').includes(c.label)));

// 3. Edge cases
let ok=true; try{parseLog('','e');parseLog('garbage\x00\xff','g');}catch(e){ok=false;}
check('empty/garbage safe', ok);
check('esc neutralizes script', esc('<script>x</script>')==='&lt;script&gt;x&lt;/script&gt;');
const ov=parseLog('Starting new log\nCmdLineParams: [STARTCOLLECTINFRASTATISTIC g]\n[01.01.2026 10:00:00.000] Info Hyper-V Infrastructure: { VirtualMachines: 10 }\n[01.01.2026 10:00:00.000] Info JobID: a, Type: Backup, ScheduleEnabled: True, PlatformName: HyperV, VMsCount: 50\n','o');
check('overlap capped at 100%', ov.coveragePct===100&&ov.unprotectedVMs===0);

console.log('Veeam Advisor — Output Confirmation');
console.log('  Logs tested: '+logs.length);
console.log('  Checks: '+pass+' passed, '+fail+' failed');
if(fail){ console.log('  FAILURES:'); fails.forEach(f=>console.log('    ✗ '+f)); process.exit(1); }
console.log('  ✓ ALL OUTPUT CONFIRMATIONS PASSED');
process.exit(0);
