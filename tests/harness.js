// Loads the REAL application script from index.html into a Node vm context with a
// minimal DOM stub, so tests exercise the tool's own parseLog(), calculate() and
// findings code rather than hand-copied mirrors. No customer data; no browser needed.
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

function makeEl(id) {
  const store = { id: id || '', value: '', checked: false, textContent: '', innerHTML: '', innerText: '',
    style: {}, dataset: {}, options: [], children: [], className: '', disabled: false, title: '' };
  const classSet = new Set();
  store.classList = { add: c => classSet.add(c), remove: c => classSet.delete(c),
    toggle: (c, f) => { const on = f === undefined ? !classSet.has(c) : f; on ? classSet.add(c) : classSet.delete(c); return on; },
    contains: c => classSet.has(c) };
  return new Proxy(store, {
    get(t, k) {
      if (k in t) return t[k];
      if (k === 'querySelector') return () => makeEl();
      if (k === 'querySelectorAll' || k === 'getElementsByTagName' || k === 'getElementsByClassName') return () => [];
      if (typeof k === 'symbol') return undefined;
      return () => makeEl();
    },
    set(t, k, v) { t[k] = v; return true; }
  });
}

function load(opts) {
  opts = opts || {};
  const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
  // Pull out each inline script body. This reads our own index.html (not untrusted HTML), so a
  // plain indexOf scan is enough and avoids a tag-matching regex.
  const blocks = [], low = html.toLowerCase();
  for (let i = low.indexOf('<script'); i >= 0; i = low.indexOf('<script', i + 1)) {
    const open = low.indexOf('>', i), close = low.indexOf('</script', open);
    if (open < 0 || close < 0) break;
    blocks.push(html.slice(open + 1, close));
  }
  const main = blocks.reduce((a, b) => (b.length > a.length ? b : a), '');
  const els = {};
  const document = {
    getElementById: id => (els[id] = els[id] || makeEl(id)),
    querySelector: () => makeEl(), querySelectorAll: () => [],
    createElement: t => makeEl(t), createElementNS: () => makeEl(),
    documentElement: makeEl('html'), head: makeEl('head'), body: makeEl('body'),
    addEventListener() {}, removeEventListener() {},
  };
  const storage = {};
  const ctx = {
    document, console: opts.verbose ? console : { log() {}, warn() {}, error() {}, info() {} },
    localStorage: { getItem: k => (k in storage ? storage[k] : null), setItem: (k, v) => { storage[k] = String(v); }, removeItem: k => { delete storage[k]; } },
    navigator: { userAgent: 'node', clipboard: null }, location: { href: 'file:///index.html', search: '' },
    setTimeout: (f) => 0, clearTimeout() {}, setInterval: () => 0, clearInterval() {}, requestAnimationFrame: () => 0,
    alert() {}, confirm: () => true, matchMedia: () => ({ matches: false, addEventListener() {}, addListener() {} }),
    Blob: function () {}, URL: { createObjectURL: () => 'blob:x', revokeObjectURL() {} },
    FileReader: function () {}, Image: function () {}, XMLSerializer: function () { this.serializeToString = () => ''; },
    getComputedStyle: () => ({ getPropertyValue: () => '' }), addEventListener() {}, print() {},
    open: () => ({ document: { open() {}, write() {}, close() {} }, focus() {}, print() {}, close() {} }),
  };
  ctx.window = ctx; ctx.self = ctx; ctx.globalThis = ctx;
  vm.createContext(ctx);
  vm.runInContext(main, ctx, { filename: 'index.html' });
  ctx.__els = els;
  return ctx;
}

// Parse a log and run calculate(); returns the context (D, findings, element HTML).
function analyse(ctx, text, fname) {
  ctx.__L = text; ctx.__F = fname || 'VMC.log';
  vm.runInContext('parseLog(__L,__F)', ctx);
  return ctx;
}
function run(ctx, code) { return vm.runInContext(code, ctx); }

module.exports = { load, analyse, run };
