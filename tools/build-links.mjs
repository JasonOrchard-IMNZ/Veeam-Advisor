#!/usr/bin/env node
/*
 * build-links.mjs — release-time link check and v12 link map for index.html.
 *
 * Run this on YOUR machine when preparing a release. The browser never contacts any
 * service: this script reads the public topic manifests from the Veeam knowledge service
 * (knowledge.veeamiq.com) and
 *
 *   1. CHECKS every helpcenter.veeam.com link in index.html against the topic index:
 *      a current (/docs/...) link must be a v13 topic, an archive (/archive/backup/120/...)
 *      link must be a v12 topic. Help Center itself answers automated requests with 403, so
 *      requesting the pages cannot tell a good link from a broken one; the index can.
 *      Veeam KB links (veeam.com/kbNNNN) are checked against the KB article index.
 *   2. Prints each link with the TITLE of the topic it points at (--titles), so a maintainer
 *      can spot a link that resolves but goes to the wrong page.
 *   3. WRITES the VA_LINKS12 map between the  / *VA-LINKS12:START* /  …  / *VA-LINKS12:END* /
 *      markers: for each current topic the tool links to, the v12 guides (archive folders)
 *      that contain the same topic. The page uses it to point links at the v12 copy when the
 *      version toggle is set to v12.
 *
 * Usage:   node tools/build-links.mjs [path/to/index.html]      (default: ./index.html)
 *          node tools/build-links.mjs --check                   (check only, write nothing)
 *          node tools/build-links.mjs --titles                  (also list link -> topic title)
 * Exit:    0 = all links valid, 2 = broken links found (map still written unless --check),
 *          1 = could not run (markers missing, service unreachable).
 * Needs:   Node 18+ (built-in fetch). No dependencies.
 */
import fs from 'node:fs';

const BASE = 'https://knowledge.veeamiq.com';
const args = process.argv.slice(2);
const CHECK = args.includes('--check');
const TITLES = args.includes('--titles');
const TARGET = args.find(a => !a.startsWith('--')) || 'index.html';
// Guides on the current site whose v12 copies live in the archive under the same topic name.
const V13_GUIDES = ['userguide', 'em', 'cloud', 'powershell'];
// Preferred v12 archive folders for each current guide (first match wins at runtime, except
// that Hyper-V estates prefer 'hyperv' for user-guide topics).
const V12_FOLDERS = { userguide: ['vsphere', 'hyperv', 'agents', 'plugins', 'storage'], em: ['em'], cloud: ['cloud'], powershell: ['powershell'] };

async function manifest(product, version) {
  const r = await fetch(`${BASE}/api/v1/docs/manifest?version=${version}&product=${product}`,
    { headers: { 'User-Agent': 'veeam-advisor-build-links' } });
  if (!r.ok) throw new Error(`manifest ${product} v${version} -> HTTP ${r.status}`);
  const map = new Map();
  for (const line of (await r.text()).split('\n')) {
    if (!line.trim()) continue;
    let o; try { o = JSON.parse(line); } catch { throw new Error(`manifest ${product} v${version}: truncated NDJSON`); }
    map.set(o.url.split('#')[0].split('?')[0], o.title);
  }
  if (!map.size) throw new Error(`manifest ${product} v${version} is empty`);
  return map;
}
async function kbExists(id) {
  const r = await fetch(`${BASE}/kb/kb${id}.md`, { headers: { 'User-Agent': 'veeam-advisor-build-links' } });
  return r.status === 200 ? true : r.status === 404 ? false : null;
}

const html = fs.readFileSync(TARGET, 'utf8');
const MARK = /\/\*VA-LINKS12:START\*\/[\s\S]*?\/\*VA-LINKS12:END\*\//;
if (!MARK.test(html)) { console.error(`VA-LINKS12 markers not found in ${TARGET}`); process.exit(1); }

// Links as written in the page. Prefix constants such as H='…/userguide/' are expanded by the
// page at run time, so also collect "prefix + 'name.html'" pairs.
const hc = new Set();
for (const m of html.matchAll(/https:\/\/helpcenter\.veeam\.com\/[^\s'"<>)]+/g)) hc.add(m[0].replace(/[\\]+$/, ''));
for (const m of html.matchAll(/var\s+(\w+)\s*=\s*'(https:\/\/helpcenter\.veeam\.com\/docs\/vbr\/userguide\/)'/g)) {
  const re = new RegExp(`\\b${m[1]}\\+'([\\w.-]+\\.html)`, 'g');
  for (const n of html.matchAll(re)) hc.add(m[2] + n[1]);
}
const kbs = new Set([...html.matchAll(/veeam\.com\/kb(\d{4})\b/g)].map(m => m[1]));

let v13, v13one, v12;
try {
  [v13, v13one, v12] = await Promise.all([manifest('vbr', 13), manifest('one', 13), manifest('vbr', 12)]);
} catch (e) { console.error('Could not read the topic index: ' + e.message); process.exit(1); }

const broken = [], rows = [], map12 = {};
const v12ByName = {};
for (const u of v12.keys()) {
  const m = u.match(/^https:\/\/helpcenter\.veeam\.com\/archive\/backup\/120\/([^/]+)\/(.+)\.html$/);
  if (m) (v12ByName[m[2]] = v12ByName[m[2]] || new Set()).add(m[1]);
}
for (const raw of [...hc].sort()) {
  const url = raw.split('#')[0].split('?')[0];
  if (url.endsWith('/')) { rows.push([raw, '(guide root — not checked)']); continue; }
  const title = v13.get(url) || v13one.get(url) || v12.get(url);
  if (!title) { broken.push(raw); rows.push([raw, 'NOT IN TOPIC INDEX']); continue; }
  rows.push([raw, title]);
  const m = url.match(/^https:\/\/helpcenter\.veeam\.com\/docs\/vbr\/([\w-]+)\/([\w.-]+)\.html$/);
  if (m && V13_GUIDES.includes(m[1]) && v12ByName[m[2]]) {
    const have = V12_FOLDERS[m[1]].filter(f => v12ByName[m[2]].has(f));
    if (have.length) map12[`${m[1]}/${m[2]}`] = have;
  }
}
const kbBad = [], kbUnknown = [];
for (const id of [...kbs].sort()) {
  const ok = await kbExists(id);
  if (ok === false) kbBad.push('KB' + id); else if (ok === null) kbUnknown.push('KB' + id);
}

if (TITLES) for (const [u, t] of rows) console.log(`${t.padEnd(48).slice(0, 48)}  ${u}`);
console.log(`${hc.size} Help Center links: ${broken.length} not in the topic index; ${Object.keys(map12).length} have a v12 copy.`);
console.log(`${kbs.size} KB links: ${kbBad.length} not found${kbUnknown.length ? `, ${kbUnknown.length} not checked (service error)` : ''}.`);
broken.forEach(b => console.warn('BROKEN: ' + b));
kbBad.forEach(b => console.warn('BROKEN: ' + b));

if (!CHECK) {
  const sorted = Object.fromEntries(Object.keys(map12).sort().map(k => [k, map12[k]]));
  const block = `/*VA-LINKS12:START*/\nvar VA_LINKS12 = ${JSON.stringify(sorted)};\n/*VA-LINKS12:END*/`;
  fs.writeFileSync(TARGET, html.replace(MARK, () => block));
  console.log(`Updated VA_LINKS12 in ${TARGET}`);
}
process.exit(broken.length || kbBad.length ? 2 : 0);
