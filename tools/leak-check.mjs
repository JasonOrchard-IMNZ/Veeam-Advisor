#!/usr/bin/env node
// Customer-data leak check for every tracked file (replaces audit.sh, which listed real
// customer names itself and had two checks that could never fail).
//
// Generic checks: GUIDs, IP addresses, email addresses, machine names, customer log file
// names. Customer estate names are NOT kept in the repo: put one per line in the
// git-ignored file .leak-names.txt, or pass them in the LEAK_NAMES environment variable
// (comma or newline separated, e.g. from a CI secret).
//
// Usage: node tools/leak-check.mjs            exit 0 = clean, 1 = review required
import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';

const ALLOW = {
  guid: new Set(['00000000-0000-0000-0000-000000000000', '88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec']),
  ip: new Set(['10.0.0.50', '192.168.1.20', '127.0.0.1', '124.0.0.0']),
  email: new Set(['jason@cheekylittlemoney.net', 'noreply@anthropic.com']),
};
const SKIP = [/^Veeam_Advisor_v1\./, /^LICENSE$/, /\.(png|jpg|ico|zip|pdf)$/i];

const files = execFileSync('git', ['ls-files'], { encoding: 'utf8' }).split('\n').filter(f => f && !SKIP.some(r => r.test(f)));
let names = (process.env.LEAK_NAMES || '').split(/[,\n]/);
if (existsSync('.leak-names.txt')) names = names.concat(readFileSync('.leak-names.txt', 'utf8').split('\n'));
names = names.map(n => n.trim()).filter(n => n && !n.startsWith('#'));
const esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const CHECKS = [
  ['GUID beyond Veeam built-ins', /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, m => !ALLOW.guid.has(m.toLowerCase())],
  // Dotted quads: Veeam / ESXi / Windows build numbers look like IPv4 addresses, so only
  // private ranges and addresses with a first octet of 20 or more are treated as IPs.
  ['IP address', /\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b/g,
    m => { const o = m.split('.').map(Number); if (ALLOW.ip.has(m)) return false;
      if (o[0] === 203 && o[1] === 0 && o[2] === 113) return false;          // RFC 5737 documentation ranges
      if (o[0] === 198 && o[1] === 51 && o[2] === 100) return false;
      if (o[0] === 192 && o[1] === 0 && o[2] === 2) return false;
      return o[0] === 10 || o[0] === 172 || o[0] === 192 || o[0] >= 20; }],
  ['email address', /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, m => !ALLOW.email.has(m.toLowerCase()) && !/@(example\.(com|org)|users\.noreply\.github\.com)$/i.test(m)],
  ['bracketed machine name', /MachineName:\s*\[([A-Za-z][^\]]*)\]/g, m => !/\[(LAB-|VBR\d|SRV|x\]|\$)/i.test(m)],
  ['customer log file name', /\b[\w-]*VMC[-_ ][\w -]{2,}\.(?:log|txt)\b/g, () => true],
];
if (names.length) CHECKS.push(['customer estate name', new RegExp('\\b(?:' + names.map(esc).join('|') + ')\\b', 'gi'), () => true]);

let fail = 0;
for (const [label, re, keep] of CHECKS) {
  const hits = [];
  for (const f of files) {
    let t; try { t = readFileSync(f, 'utf8'); } catch { continue; }
    for (const m of t.matchAll(re)) if (keep(m[0])) hits.push(`${f}: ${m[0]}`);
  }
  const uniq = [...new Set(hits)];
  if (uniq.length) { fail = 1; console.log(`  FAIL  ${label}`); uniq.slice(0, 20).forEach(h => console.log('          ' + h)); if (uniq.length > 20) console.log(`          ... ${uniq.length - 20} more`); }
  else console.log(`  PASS  ${label}`);
}
console.log(names.length ? `  (checked ${names.length} customer names from .leak-names.txt / LEAK_NAMES)` : '  NOTE  no customer names list supplied (.leak-names.txt or LEAK_NAMES); name check skipped');
console.log(fail ? '\nREVIEW REQUIRED' : '\nCLEAN: no customer-identifying data in tracked files');
process.exit(fail);
