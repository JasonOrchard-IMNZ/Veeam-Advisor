#!/usr/bin/env node
/*
 * build-advisories.mjs — release-time refresh of the offline security-advisory data
 * embedded in index.html.
 *
 * Run this on YOUR machine when preparing a release. It downloads public Veeam data
 * (security advisories and the KB2680 build list) from the Veeam knowledge service at
 * knowledge.veeamiq.com and writes it, with today's date, into index.html between the
 *   / *VA-ADVISORIES:START* /  …  / *VA-ADVISORIES:END* /
 * markers. The browser never contacts any service: the tool compares the build in the
 * uploaded VMC.log against this embedded copy, entirely offline.
 *
 * Usage:   node tools/build-advisories.mjs [path/to/index.html]   (default: ./index.html)
 *          node tools/build-advisories.mjs --dry-run              (print, don't write)
 *          node tools/build-advisories.mjs --stamp-after=30       (scheduled runs: if nothing
 *              changed, keep the existing date unless it is older than 30 days, so an
 *              unchanged check does not produce a diff every day)
 * Needs:   Node 18+ (built-in fetch). No dependencies.
 *
 * Only Veeam Backup & Replication v12 and v13 builds are kept — the versions the tool
 * analyses. Sections of an advisory that concern other products (Veeam Agent, Veeam ONE,
 * VSPC, Enterprise Manager …) are skipped because VMC.log does not carry their builds.
 * Any VBR advisory the parser cannot read is reported as a WARNING so a maintainer can
 * add it to MANUAL below — nothing is silently dropped.
 */
import fs from 'node:fs';

const BASE = 'https://knowledge.veeamiq.com';
const args = process.argv.slice(2);
const DRY = args.includes('--dry-run');
const STAMP_AFTER = Number((args.find(a => a.startsWith('--stamp-after=')) || '').split('=')[1]) || 0;
const TARGET = args.find(a => !a.startsWith('--')) || 'index.html';
const MAJORS = [12, 13];

// Advisories whose wording the generic parser cannot read. Keep entries minimal and
// cite the KB; verify against the article when adding one.
const MANUAL = {
  // CVE-2023-27532: fixed for v12 by patch P20230223, which keeps build 12.0.0.1420.
  kb4424: { segments: [{ major: 12, affectedMax: '12.0.0.1420', fixed: ['12.0.0.1420 P20230223'],
    note: 'The fix (P20230223) does not change the build number: a 12.0.0.1420 server is affected only if that patch, or a later 12.0 patch, is not installed.',
    cves: [{ id: 'CVE-2023-27532', cvss: 7.5, severity: 'high', deploy: null,
      desc: 'Allows an unauthenticated user to obtain encrypted credentials stored in the configuration database.' }] }] },
};
// Advisories with a hotfix that does not change the build number.
const NOTES = {
  kb4724: 'A hotfix for 12.3.0.310 resolves this without changing the build number — verify the hotfix file hashes listed in KB4724 before treating 12.3.0.310 as affected.',
};

async function get(path, asText) {
  const r = await fetch(BASE + path, { headers: { 'User-Agent': 'veeam-advisor-build-advisories' } });
  if (!r.ok) throw new Error(`${path} -> HTTP ${r.status}`);
  // Veeam's articles use non-breaking spaces inside product names and build numbers.
  return asText ? (await r.text()).replace(/\u00a0/g, ' ') : r.json();
}

const cmp = (a, b) => { const x = a.split('.').map(Number), y = b.split('.').map(Number);
  for (let i = 0; i < 4; i++) { const d = (x[i] || 0) - (y[i] || 0); if (d) return d; } return 0; };

// Strip markdown so descriptions render as plain text in the tool.
const plain = t => (t || '').replace(/\\$/, '').replace(/\[([^\]]*)\]\([^)]*\)/g, '$1').replace(/[`*_]/g, '').replace(/\s+/g, ' ').trim();

function parseCves(block) {
  const out = [];
  const re = /#{3,6}\s*\*{0,2}\[?(CVE-\d{4}-\d{4,7})\]?(?:\([^)]*\))?\*{0,2}([\s\S]*?)(?=#{3,6}\s*\*{0,2}\[?CVE-|#{1,3}\s*\*{0,2}Solution|$)/g;
  let m;
  while ((m = re.exec(block))) {
    const body = m[2];
    const cvss = (body.match(/CVSS[^:\n]*Score:\*{0,2}\s*([0-9]+(?:\.[0-9])?)/i) || [])[1];
    const sev = (body.match(/\*\*(?:CVSS )?Severity:\*\*\s*([A-Za-z]+)/) || [])[1];
    const dep = (body.match(/Affected Deployment Type:\*\*\s*([^\n\\]+)/) || [])[1];
    const desc = body.split('\n').map(s => s.trim()).find(s => s && !s.startsWith('*') && !s.startsWith('#') && !/^CVSS/i.test(s) && !s.startsWith('\\') && !s.startsWith('-'));
    let deploy = null;
    if (dep) { deploy = []; if (/Windows/i.test(dep)) deploy.push('windows'); if (/Appliance/i.test(dep)) deploy.push('vsa'); }
    const affected = (body.match(/Affected Product[\s\S]*?\n\s*-?\s*([^\n]+)/) || [])[1] || '';
    out.push({ id: m[1], cvss: cvss ? Number(cvss) : null, severity: sev ? sev.toLowerCase() : null,
      deploy, desc: plain(desc), affectedLine: affected });
  }
  return out;
}

const AFFECT_RE = /Veeam Backup &(?:amp;)? Replication\*{0,2}\s+\*{0,2}(1[23]\.\d+\.\d+\.\d+)\*{0,2}\s+and all \[?earlier version (1[23]) builds/;
function fixedBuilds(text) {
  const sol = text.split(/fixed starting/i).slice(1).join(' ');
  const out = new Set();
  for (const m of sol.matchAll(/\[Veeam Backup &(?:amp;)? Replication[^\]]*?(1[23]\.\d+\.\d+\.\d+)[^\]]*\]/g)) out.add(m[1]);
  return [...out];
}

function parseArticle(kb, md) {
  if (MANUAL[kb]) return MANUAL[kb].segments;
  // Split into product sections where the article has them ("## Veeam Backup & Replication",
  // "## Veeam Agent for …"); otherwise treat the whole article as one section.
  const parts = md.split(/\n(?=##\s+(?!#))/);
  const segs = [];
  const vbrParts = parts.filter(p => !/^##\s+(Veeam Agent|Veeam ONE|Veeam Service Provider|Veeam Backup \*?for|Veeam Backup Enterprise)/.test(p));
  const whole = vbrParts.join('\n');
  // Case A: one "affect X and all earlier version N builds" for the whole article/section.
  const top = whole.match(AFFECT_RE);
  const cves = parseCves(whole).filter(c => !/Veeam Agent|Veeam ONE|Service Provider/i.test(c.affectedLine));
  if (!cves.length) return segs;
  // Case B: per-CVE "Affected Product" lines (may differ by CVE).
  const byMajor = {};
  for (const c of cves) {
    const a = (c.affectedLine.match(/(1[23]\.\d+\.\d+\.\d+)\s+and all \[?earlier version (1[23])/) || []);
    const affectedMax = a[1] || (top && top[1]);
    const major = Number(a[2] || (top && top[2]));
    if (!affectedMax || !MAJORS.includes(major)) continue;
    const key = major + '|' + affectedMax;
    (byMajor[key] = byMajor[key] || { major, affectedMax, cves: [] }).cves.push(c);
  }
  const fixed = fixedBuilds(whole);
  for (const s of Object.values(byMajor)) {
    const fx = fixed.filter(f => Number(f.split('.')[0]) === s.major || cmp(f, s.affectedMax) > 0);
    segs.push({ major: s.major, affectedMax: s.affectedMax, fixed: fx.length ? fx : fixed,
      note: NOTES[kb] || null,
      cves: s.cves.map(({ affectedLine, ...c }) => c) });
  }
  return segs;
}

function parseLatest(md) {
  const lines = [];
  for (const m of md.matchAll(/\|\s*Veeam Backup & Replication ([^|]+?)\s*\|\s*(1[23]\.\d+\.\d+\.\d+)(?: (P\d+))?\s*\|\s*(\d{4}-\d{2}-\d{2})/g))
    lines.push({ name: m[1].trim(), build: m[2], patch: m[3] || null, date: m[4] });
  const latest = {};
  for (const l of lines) { const mj = Number(l.build.split('.')[0]);
    if (MAJORS.includes(mj) && (!latest[mj] || cmp(l.build, latest[mj].build) > 0)) latest[mj] = l; }
  return { latest, lines: lines.filter(l => MAJORS.includes(Number(l.build.split('.')[0]))) };
}

const list = await get('/api/v1/security-advisories?product=VBR&limit=200');
const advisories = [], warnings = [];
for (const a of list.advisories) {
  if (!(a.products || []).includes('Veeam Backup & Replication')) continue;
  if (!a.cves || !a.cves.length) continue;                       // improvement lists, no CVEs
  if (/Enterprise Manager/i.test(a.title)) {                     // EM builds are not in VMC.log
    console.log(`skip ${a.kb_id}: Enterprise Manager advisory (EM build not recorded in VMC.log)`); continue; }
  const md = await get(`/kb/${a.kb_id}.md`, true);
  const mentionsScope = /\b1[23]\.\d+\.\d+\.\d+\b/.test(md) || MANUAL[a.kb_id];
  if (!mentionsScope) continue;                                   // pre-v12 advisories
  const segs = parseArticle(a.kb_id, md);
  if (!segs.length) {
    if (/Veeam Backup & Replication (1[23])\b|version 1[23] builds/.test(md))
      warnings.push(`${a.kb_id} (${a.title}) mentions v12/v13 but could not be parsed — add it to MANUAL`);
    continue;
  }
  for (const s of segs) advisories.push({ kb: a.kb_id, title: a.title, url: a.url,
    published: (a.published_at || '').slice(0, 10), ...s });
}
const latest = parseLatest(await get('/kb/kb2680.md', true));
if (!latest.latest[12] || !latest.latest[13]) warnings.push('KB2680 latest builds not found for v12 and v13');

const data = { asOf: new Date().toISOString().slice(0, 10), source: 'knowledge.veeamiq.com (Veeam security advisories, KB2680)',
  latest: { 12: latest.latest[12], 13: latest.latest[13] }, advisories };
const block = `/*VA-ADVISORIES:START*/\nvar VA_ADVISORIES = ${JSON.stringify(data, null, 1)};\n/*VA-ADVISORIES:END*/`;

warnings.forEach(w => console.warn('WARNING: ' + w));
console.log(`${advisories.length} advisory segments, latest v12 ${data.latest[12]?.build}, v13 ${data.latest[13]?.build}, as of ${data.asOf}`);
if (DRY) { console.log(block); process.exit(warnings.length ? 2 : 0); }
const html = fs.readFileSync(TARGET, 'utf8');
const re = /\/\*VA-ADVISORIES:START\*\/[\s\S]*?\/\*VA-ADVISORIES:END\*\//;
if (!re.test(html)) { console.error(`Markers not found in ${TARGET}`); process.exit(1); }

// Compare with the copy already in the page and report what changed (used for the PR body
// by the scheduled workflow). Lines starting "CHANGE:" are the summary.
let old = null;
try { old = JSON.parse(html.match(re)[0].replace(/^[\s\S]*?var VA_ADVISORIES = /, '').replace(/;\s*\/\*VA-ADVISORIES:END\*\/$/, '')); } catch { old = null; }
const strip = d => JSON.stringify({ latest: d.latest, advisories: d.advisories });
const changed = !old || strip(old) !== strip(data);
if (old) {
  const ok = new Set(old.advisories.map(a => a.kb)), nk = new Set(data.advisories.map(a => a.kb));
  [...nk].filter(k => !ok.has(k)).forEach(k => { const a = data.advisories.find(x => x.kb === k);
    console.log(`CHANGE: new advisory ${k.toUpperCase()} — ${a.title} (v${a.major}, up to ${a.affectedMax}; max CVSS ${Math.max(...a.cves.map(c => c.cvss || 0))})`); });
  [...ok].filter(k => !nk.has(k)).forEach(k => console.log(`CHANGE: advisory ${k.toUpperCase()} no longer listed`));
  for (const mj of MAJORS) { const o = old.latest && old.latest[mj], n = data.latest[mj];
    if (o && n && o.build !== n.build) console.log(`CHANGE: latest v${mj} build ${o.build} → ${n.build} (${n.name}, ${n.date})`); }
  if (changed && ![...nk].some(k => !ok.has(k))) console.log('CHANGE: advisory details updated (CVE scores, fixed builds or notes)');
}
if (!changed && STAMP_AFTER && old && old.asOf) {
  const age = Math.floor((Date.now() - Date.parse(old.asOf + 'T00:00:00Z')) / 86400000);
  if (age < STAMP_AFTER) {
    console.log(`No advisory or build changes; keeping the existing date ${old.asOf} (${age} days old, re-stamped after ${STAMP_AFTER}).`);
    process.exit(warnings.length ? 2 : 0);
  }
  console.log(`CHANGE: no new advisories or builds; data re-verified (previous check ${old.asOf}, ${age} days ago)`);
}
fs.writeFileSync(TARGET, html.replace(re, () => block));
console.log(`Updated ${TARGET}`);
process.exit(warnings.length ? 2 : 0);
