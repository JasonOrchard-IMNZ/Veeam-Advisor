#!/usr/bin/env node
/*
 * release-refresh.mjs — one command to refresh and verify the data embedded in index.html
 * before a release. Run it on YOUR machine; the browser never contacts any service.
 *
 *   1. node tools/build-advisories.mjs   → refreshes VA_ADVISORIES (security advisories, KB2680)
 *   2. node tools/build-links.mjs        → checks every Help Center / KB link, refreshes VA_LINKS12
 *   3. Drift checks — compares the hand-maintained tables in index.html with the current
 *      Help Center content on knowledge.veeamiq.com and reports any difference:
 *        • VA_PLAT     supported ESXi / vCenter and Hyper-V ranges (platform_support_vm/_hv)
 *        • VA_SCA      Security & Compliance Analyzer keys (VBRBestPracticeType enumeration)
 *        • VA_UPG      minimum build for the v13 upgrade and Cloud Connect tenant minimums
 *      These tables are not rewritten automatically: a difference means a maintainer should
 *      read the page and update the table (and its regression test) by hand.
 *
 * Usage:   node tools/release-refresh.mjs [path/to/index.html]   (default: ./index.html)
 *          node tools/release-refresh.mjs --check                 (no writes; steps 1-2 dry-run)
 *          node tools/release-refresh.mjs --stamp-after=30        (scheduled runs; passed to
 *                                                                   build-advisories.mjs)
 * Exit:    0 = refreshed and no drift, 2 = warnings / drift / broken links, 1 = could not run.
 * Needs:   Node 18+. No dependencies.
 */
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const BASE = 'https://knowledge.veeamiq.com';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const CHECK = args.includes('--check');
const TARGET = args.find(a => !a.startsWith('--')) || 'index.html';
let warn = 0;
const W = m => { warn++; console.warn('DRIFT: ' + m); };

function run(script, extra) {
  console.log(`\n── ${script} ${extra.join(' ')}`);
  const r = spawnSync(process.execPath, [path.join(HERE, script), TARGET, ...extra], { stdio: 'inherit' });
  if (r.status === 1 || r.status === null) { console.error(`${script} could not run`); process.exit(1); }
  if (r.status === 2) warn++;
}
async function topic(key, version, anchor) {
  const u = `${BASE}/api/v1/docs/topics/${key}${anchor ? '/sections/' + anchor : ''}?version=${version}${anchor ? '' : '&format=markdown'}`;
  const r = await fetch(u, { headers: { 'User-Agent': 'veeam-advisor-release-refresh' } });
  if (!r.ok) throw new Error(`${key}${anchor ? '#' + anchor : ''} v${version} -> HTTP ${r.status}`);
  const o = await r.json();
  return String(anchor ? o.section.markdown : o.markdown).replace(/ /g, ' ');
}

const STAMP = args.filter(a => a.startsWith('--stamp-after='));
run('build-advisories.mjs', CHECK ? ['--dry-run'] : STAMP);
run('build-links.mjs', CHECK ? ['--check'] : []);

console.log('\n── drift checks');
const html = fs.readFileSync(TARGET, 'utf8');
try {
  // VA_PLAT: v13 ESXi range and Hyper-V range
  const vm = await topic('vbr/userguide/platform_support_vm', 13);
  const esx = [...vm.matchAll(/ESXi (\d+)\.x(?: \(up to (\d+)\.(\d+)\))?/g)];
  const plat = html.match(/13:\{vmw:\{min:\[(\d+),(\d+)\],max:\[(\d+),(\d+)\]/);
  if (!esx.length || !plat) W('could not read the v13 ESXi range (page or VA_PLAT changed shape)');
  else {
    const lo = Math.min(...esx.map(m => +m[1])), top = esx.find(m => m[2]);
    const hi = top ? [+top[2], +top[3]] : [Math.max(...esx.map(m => +m[1])), 99];
    if (lo !== +plat[1] || hi[0] !== +plat[3] || (top && hi[1] !== +plat[4]))
      W(`v13 ESXi range is now ${lo}.x to ${hi.join('.')}; VA_PLAT has ${plat[1]}.${plat[2]} to ${plat[3]}.${plat[4]}`);
    else console.log(`ok   v13 ESXi / vCenter range ${lo}.x to ${hi.join('.')}`);
  }
  const hv = await topic('vbr/userguide/platform_support_hv', 13);
  const yrs = [...hv.matchAll(/Windows Server Hyper-V (20\d\d)/g)].map(m => +m[1]);
  const hvp = html.match(/13:\{vmw:[^}]*\}[^}]*?\},hv:\{min:(\d+),max:(\d+)/) || html.match(/hv:\{min:(\d+),max:(\d+),label:'Windows Server Hyper-V 2016/);
  if (!yrs.length || !hvp) W('could not read the v13 Hyper-V range');
  else if (Math.min(...yrs) !== +hvp[1] || Math.max(...yrs) !== +hvp[2]) W(`v13 Hyper-V range is now ${Math.min(...yrs)}-${Math.max(...yrs)}; VA_PLAT has ${hvp[1]}-${hvp[2]}`);
  else console.log(`ok   v13 Hyper-V range ${hvp[1]}-${hvp[2]}`);

  // VA_SCA: Analyzer keys
  const en = await topic('vbr/powershell/enums', 13, 'vbrbestpracticetype');
  const keys = [...en.matchAll(/^\| (\w+) \|/gm)].map(m => m[1]).filter(k => k !== 'Member');
  const sca = html.slice(html.indexOf('var VA_SCA=(function'), html.indexOf('var VA_SCA_GROUP'));
  const mapped = new Set([...sca.matchAll(/^\s+(\w+):\['[WLB]'/gm)].map(m => m[1]));
  const missing = keys.filter(k => !mapped.has(k));
  if (!keys.length) W('could not read VBRBestPracticeType');
  else if (missing.length) W(`Analyzer keys not in VA_SCA: ${missing.join(', ')}`);
  else console.log(`ok   all ${keys.length} Analyzer keys are in VA_SCA`);

  // VA_UPG: minimum build and tenant minimums
  const up = await topic('vbr/userguide/upgrade_vbr', 13);
  const mb = up.match(/must be running version [\d.]+ \(build (1[23]\.\d+\.\d+\.\d+)\)/);
  const cur = (html.match(/minBuild:'([\d.]+)'/) || [])[1];
  if (!mb) W('could not read the minimum upgrade build from upgrade_vbr');
  else if (mb[1] !== cur) W(`minimum build for the v13 upgrade is now ${mb[1]}; VA_UPG has ${cur}`);
  else console.log(`ok   v13 upgrade minimum build ${cur}`);
  const byb = await topic('vbr/userguide/upgrade_vbr_byb', 13);
  const tm = byb.match(/minimal supported tenant versions are: Veeam Backup & Replication (1[23]\.\d+\.\d+\.\d+)/);
  const ccur = (html.match(/ccTenantMin:'Veeam Backup & Replication ([\d.]+)/) || [])[1];
  if (!tm) W('could not read the Cloud Connect tenant minimum from upgrade_vbr_byb');
  else if (tm[1] !== ccur) W(`Cloud Connect tenant minimum is now ${tm[1]}; VA_UPG has ${ccur}`);
  else console.log(`ok   Cloud Connect tenant minimum ${ccur}`);
} catch (e) { console.error('Drift checks could not run: ' + e.message); process.exit(1); }

console.log(warn ? `\n${warn} warning(s) — review before releasing.` : '\nAll embedded data is current.');
process.exit(warn ? 2 : 0);
