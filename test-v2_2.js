// Veeam Advisor v2.2 — validation harness.
//
// Loads index.html headless and asserts the tape parsing / reporting fixes.
// All input is synthetic (see fixtures.js). No customer, lab or production log is
// read, embedded or referenced, so this suite is safe to commit and runs anywhere.
//
//   npm install jsdom && node test-v2_1_01.js [path/to/index.html]

const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');
const fx = require('./fixtures');
const { tapeLog, noTapeLog, orphanMediaLog, coverageLog, encryptionLog, mapLog, mapCaptureTape } = fx;

let pass = 0, fail = 0;
function ok(name, cond, extra) {
  if (cond) { pass++; console.log('  PASS  ' + name); }
  else { fail++; console.log('  FAIL  ' + name + (extra !== undefined ? '   -> ' + extra : '')); }
}
function eq(name, actual, expected) {
  ok(name, actual === expected, 'got ' + JSON.stringify(actual) + ', want ' + JSON.stringify(expected));
}

const file = process.argv[2] || 'index.html';
const html = fs.readFileSync(path.resolve(file), 'utf8');

const dom = new JSDOM(html, { runScripts: 'dangerously', pretendToBeVisual: true, url: 'https://localhost/' });
const w = dom.window;
const errs = [];
w.addEventListener('error', e => errs.push(e.message));

// Parse a fixture and hand back the populated module-level D.
function parse(log) { w.parseLog(log, 'fixture.log'); return w.D; }

setTimeout(() => {
  console.log('Veeam Advisor v2.2 — validation (' + file + ')');
  console.log('Input: synthetic fixtures only — no customer data.\n');

  console.log('=== 1. Page loads clean ===');
  eq('no uncaught errors on load', errs.length, 0);
  ok('parseLog is defined', typeof w.parseLog === 'function');
  ok('vaTapeGen is defined (new in v2.1.01)', typeof w.vaTapeGen === 'function');
  ok('vaTapeChoice is defined (new in v2.1.01)', typeof w.vaTapeChoice === 'function');

  console.log('\n=== 2. Tape generation is read, not assumed ===');
  eq('"Ultrium 7" -> LTO-7', parse(tapeLog({ driveModel: 'GENERIC Ultrium 7-SCSI' })).tapeLTO, 'LTO-7');
  eq('"Ultrium 8" -> LTO-8', parse(tapeLog({ driveModel: 'GENERIC Ultrium 8-SCSI' })).tapeLTO, 'LTO-8');
  eq('"Ultrium 9" -> LTO-9', parse(tapeLog({ driveModel: 'GENERIC Ultrium 9' })).tapeLTO, 'LTO-9');
  eq('explicit "LTO-8" still works', parse(tapeLog({ driveModel: 'VENDOR LTO-8 drive' })).tapeLTO, 'LTO-8');
  eq('unversioned Ultrium -> generic label', parse(tapeLog({ driveModel: 'GENERIC Ultrium drive' })).tapeLTO, 'Ultrium (LTO)');
  eq('unknown model -> no generation', parse(tapeLog({ driveModel: 'VENDOR TapeUnit 3000' })).tapeLTO, null);

  console.log('\n=== 3. Drive / library counts read the right fields ===');
  let D = parse(tapeLog({ drives: 2, libraries: 1 }));
  eq('drives from DrivesCount, not ParallelDrivesCount:4', D.tapeDrives, 2);
  eq('libraries from estate LibrariesCount', D.tapeLibraries, 1);
  // Two tape servers, each reporting 1 library, estate total 2.
  D = parse(tapeLog({ libraries: 2, tapeServers: 2, perServerLibraries: 1 }));
  eq('multi-server: estate total, not first server', D.tapeLibraries, 2);

  console.log('\n=== 4. Media pool counts come from [MediaPools] records ===');
  // Six jobs all pointing at one pool type must not inflate the pool count.
  D = parse(tapeLog({ poolTypes: ['Free', 'UserSimple', 'Imported', 'Retired'], vmJobs: 1, fileJobs: 5 }));
  eq('total pools', D.mediaPools, 4);
  eq('regular pools (not the 6 job records)', D.regularMediaPools, 4);
  eq('gfs pools', D.gfsMediaPools, 0);
  ok('gfs + regular reconciles with total', D.gfsMediaPools + D.regularMediaPools === D.mediaPools,
     D.gfsMediaPools + '+' + D.regularMediaPools + ' vs ' + D.mediaPools);

  // A configured GFS pool must be seen even though no job record names it.
  D = parse(tapeLog({ poolTypes: ['Free', 'GFS', 'UserSimple'] }));
  eq('configured GFS pool detected', D.gfsMediaPools, 1);
  eq('remaining pools counted as regular', D.regularMediaPools, 2);

  // No [MediaPools] records -> previous job-line inference.
  D = parse(tapeLog({ omitMediaPoolRecords: true, vmJobs: 1, fileJobs: 2 }));
  eq('fallback path still yields a number', D.regularMediaPools, 3);

  console.log('\n=== 5. Job counts unchanged ===');
  D = parse(tapeLog({ vmJobs: 1, fileJobs: 5 }));
  eq('vmTapeJobs', D.vmTapeJobs, 1);
  eq('fileTapeJobs', D.fileTapeJobs, 5);
  eq('tapeJobs', D.tapeJobs, 6);
  eq('tapeServers', D.tapeServers, 1);

  console.log('\n=== 6. Sizing follows the detected drive ===');
  const base = { dataTB: 36, ret: 10, gfsW: 0, gfsM: 0, gfsY: 0 };
  const t7 = w.tapeCalc(base, 'LTO-7', false);
  const t9 = w.tapeCalc(base, 'LTO-9', false);
  eq('LTO-7 native TB/tape', t7.cap, 6);
  eq('LTO-9 native TB/tape', t9.cap, 18);
  ok('generation changes the tape count', t7.tapes !== t9.tapes, t7.tapes + ' vs ' + t9.tapes);
  eq('vaTapeGen uses the detected drive',
     w.vaTapeGen(parse(tapeLog({ driveModel: 'GENERIC Ultrium 7-SCSI' }))), 'LTO-7');

  console.log('\n=== 7. PDF cannot contradict the screen ===');
  D = parse(tapeLog({ driveModel: 'GENERIC Ultrium 7-SCSI' }));
  w._vaTapeSel = null;
  eq('no user choice -> detected generation', w.vaTapeChoice(D).gen, 'LTO-7');
  w._vaTapeSel = { gen: 'LTO-8', useComp: true };
  eq('user choice honoured (generation)', w.vaTapeChoice(D).gen, 'LTO-8');
  eq('user choice honoured (compression)', w.vaTapeChoice(D).useComp, true);
  w._vaTapeSel = { gen: 'NOT-A-GEN', useComp: false };
  eq('invalid choice falls back safely', w.vaTapeChoice(D).gen, 'LTO-7');
  w._vaTapeSel = null;

  console.log('\n=== 8. Fallbacks and no-tape safety ===');
  eq('vaTapeGen(null) -> LTO-9', w.vaTapeGen(null), 'LTO-9');
  eq('vaTapeGen({}) -> LTO-9', w.vaTapeGen({}), 'LTO-9');
  eq('vaTapeGen(generic Ultrium label) -> LTO-9', w.vaTapeGen({ tapeLTO: 'Ultrium (LTO)' }), 'LTO-9');
  let threw = null;
  try { D = parse(noTapeLog()); } catch (e) { threw = e.message; }
  ok('log with no tape records does not throw', threw === null, threw);
  eq('no tape jobs reported', D.tapeJobs, 0);

  console.log('\n=== 9. Tape documentation links ===');
  ok('File to Tape -> file_to_tape_jobs.html', html.indexOf('file_to_tape_jobs.html') !== -1);
  ok('VM to Tape -> backup_to_tape_jobs.html', html.indexOf('backup_to_tape_jobs.html') !== -1);
  ok('no tape type left on backup_copy.html',
     html.indexOf("Tape',        bp:'https://helpcenter.veeam.com/docs/backup/vsphere/backup_copy.html") === -1);

  console.log('\n=== 10. Version stamps ===');
  ok('title bumped', html.indexOf('<title>Veeam Advisor v2.2</title>') !== -1);
  ok('hero pill bumped', html.indexOf('>v2.2</span>') !== -1);
  ok('PDF meta bumped', html.indexOf('Veeam Advisor v2.2 &nbsp;|&nbsp; Feedback') !== -1);
  ok('no stale v2.0 stamp remains', html.indexOf('Veeam Advisor v2.0') === -1);

  console.log('\n=== 11. v2.1 theme system untouched ===');
  ['vaApplyTheme','vaSetTheme','vaExportCode','vaParseCode','vaNormHex','vaLoadPalette','vaSavePalette']
    .forEach(fn => ok('v2.1 fn intact: ' + fn, typeof w[fn] === 'function'));
  ok('vaStore shim intact', w.vaStore && typeof w.vaStore.get === 'function');
  const seed = w.vaDefaultPalette();
  const code = 'VA1-' + w.VA_PALETTE.map(e => String(seed[e.k]).replace('#', '')).join('-');
  eq('scheme code round-trips to 18 colours', Object.keys(w.vaParseCode(code) || {}).length, 18);
  ok('malformed scheme code rejected', !w.vaParseCode('VA1-nope'));

  console.log('\n=== 12. This suite carries no customer data ===');
  const self = fs.readFileSync(__filename, 'utf8') + fs.readFileSync(path.join(__dirname, 'fixtures.js'), 'utf8');
  // Needles are assembled at runtime so this check cannot match its own source.
  const uploadsNeedle = ['/mnt', 'user-data', 'uploads'].join('/');
  const logNeedle = 'VMC' + '.log';
  ok('no uploads path referenced', self.indexOf(uploadsNeedle) === -1);
  ok('no customer log filename referenced', self.indexOf(logNeedle) === -1);
  ok('no IPv4 literals', !/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(self));
  ok('no real-looking GUIDs', !/\b(?!aaaa)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i.test(self));

  console.log('\n=== 13. Leg 4 — tape best-practice checks ===');
  ok('tapeBPChecks is defined', typeof w.tapeBPChecks === 'function');
  function byName(checks, name) { return checks.filter(c => c.name === name)[0]; }

  // A deliberately bad estate.
  parse(tapeLog({
    cleaningRequired: true, cleaningTapes: 0, autoClean: false,
    encryption: false, vaults: 0, offlineTracking: false, wormTapes: 0,
    manualJobs: true, notifications: false,
    freeTapes: 1, dailyMediaSet: true, protectRetention: true,
    parallelDrives: 4, drives: 1, poolTypes: ['Free', 'UserSimple', 'Imported', 'Retired'],
    vmCompressionOn: true, fileCompressionOff: true, gfsCounts: false,
    vmJobs: 1, fileJobs: 5
  }));
  let C = w.tapeBPChecks(w.D);
  eq('cleaning -> critical', byName(C, 'Drive cleaning').sev, 'c');
  eq('encryption off -> critical', byName(C, 'Tape encryption').sev, 'c');
  eq('no air gap -> critical', byName(C, 'Air gap / offline media').sev, 'c');
  eq('all manual -> critical', byName(C, 'Job scheduling').sev, 'c');
  eq('all notifications off -> critical', byName(C, 'Job notifications').sev, 'c');
  eq('1 free tape w/ daily+protect -> critical', byName(C, 'Free media headroom').sev, 'c');
  eq('parallel > drives -> warning', byName(C, 'Parallel processing').sev, 'warn');
  eq('no GFS pool -> warning', byName(C, 'GFS on tape').sev, 'warn');
  eq('compression misconfigured -> warning', byName(C, 'Hardware compression').sev, 'warn');

  // A well-configured estate: everything should pass.
  parse(tapeLog({
    cleaningRequired: false, cleaningTapes: 2, autoClean: true,
    encryption: true, vaults: 1, offlineTracking: true, wormTapes: 5,
    manualJobs: false, notifications: true,
    freeTapes: 12, dailyMediaSet: false, protectRetention: false,
    parallelDrives: 1, drives: 2, poolTypes: ['Free', 'GFS', 'UserSimple'],
    vmCompressionOn: false, fileCompressionOff: false, gfsCounts: true,
    vmJobs: 1, fileJobs: 5
  }));
  C = w.tapeBPChecks(w.D);
  eq('well-configured estate: 0 critical', C.filter(c => c.sev === 'c').length, 0);
  eq('well-configured estate: 0 warning', C.filter(c => c.sev === 'warn').length, 0);
  ok('well-configured estate: all pass/info', C.length > 0 && C.every(c => c.sev === 'ok' || c.sev === 'i'), C.map(c => c.name + '=' + c.sev).join(', '));

  // No tape estate -> no checks (not wrong checks).
  parse(noTapeLog());
  eq('no tape estate -> no checks', w.tapeBPChecks(w.D).length, 0);

  // Partial collection degrades gracefully.
  parse(tapeLog({ omitMediaPoolRecords: true, vmJobs: 1, fileJobs: 2, encryption: true, notifications: true }));
  C = w.tapeBPChecks(w.D);
  ok('partial collection still yields some checks', C.length > 0, C.length);
  ok('no check throws on partial data', C.every(c => c.sev && c.name && c.cur && c.rec));

  console.log('\n=== 14. Leg 3 — tape on the Resiliency Map ===');
  ok('parseMapCapture is defined', typeof w.parseMapCapture === 'function');

  // (a) Inference path: one VM-to-tape job, no capture -> edge from the backup repo, flagged inferred.
  w._psCapture = null;
  let ml = mapLog({ repos: 1, backupJobs: 2, vmTapeJobs: 1, fileTapeJobs: 0 });
  w.parseLog(ml.text, 'map.log');
  let bm = w.D.backupMap;
  ok('backupMap built', !!bm);
  ok('tape present on map', bm.tape && bm.tape.present === true);
  eq('one VM-to-tape job counted', bm.tape.vmJobs, 1);
  eq('feeds the backup repository', Object.keys(bm.tape.feedRepos).length, 1);
  ok('single-job edge flagged inferred', bm.tape.inferredEdges === true);
  ok('inference is not from capture', bm.tape.fromCapture === false);

  // (b) Ambiguity guard: two VM-to-tape jobs, no capture -> NO guessed edges.
  w._psCapture = null;
  ml = mapLog({ repos: 2, backupJobs: 4, vmTapeJobs: 2, fileTapeJobs: 0 });
  w.parseLog(ml.text, 'map2.log');
  bm = w.D.backupMap;
  eq('two VM-to-tape jobs counted', bm.tape.vmJobs, 2);
  eq('no inferred edges when ambiguous', Object.keys(bm.tape.feedRepos).length, 0);
  ok('ambiguous case not flagged inferred', bm.tape.inferredEdges === false);

  // (c) Capture path: two VM-to-tape jobs, capture resolves source jobs -> solid edges.
  ml = mapLog({ repos: 2, backupJobs: 4, vmTapeJobs: 2, fileTapeJobs: 0, tapeSourceGuids: false });
  // Build a capture that maps each tape job to the backup jobs of one repo.
  const capText = mapCaptureTape([
    { id: fx.guid(600), sources: [{ id: ml.bjId(0), name: 'BJ0' }, { id: ml.bjId(2), name: 'BJ2' }] },
    { id: fx.guid(601), sources: [{ id: ml.bjId(1), name: 'BJ1' }, { id: ml.bjId(3), name: 'BJ3' }] }
  ]);
  w._psCapture = w.parseMapCapture(capText);
  ok('capture parsed a tape section', Object.keys(w._psCapture.tape.jobs).length === 2);
  w.parseLog(ml.text, 'map3.log');
  bm = w.D.backupMap;
  ok('capture resolves edges', bm.tape.fromCapture === true);
  ok('capture edges not inferred', bm.tape.inferredEdges === false);
  ok('both repos feed tape via capture', Object.keys(bm.tape.feedRepos).length === 2, Object.keys(bm.tape.feedRepos).length);
  w._psCapture = null;

  // (d) File-to-tape counted separately, not as a repo edge.
  ml = mapLog({ repos: 1, backupJobs: 1, vmTapeJobs: 0, fileTapeJobs: 3 });
  w.parseLog(ml.text, 'map4.log');
  bm = w.D.backupMap;
  eq('file-to-tape jobs counted', bm.tape.fileJobs, 3);
  eq('no VM-to-tape', bm.tape.vmJobs, 0);
  eq('file-to-tape produces no repo edge', Object.keys(bm.tape.feedRepos).length, 0);

  // (e) SVG actually renders the tape node.
  ok('buildMapSvg is defined', typeof w.buildMapSvg === 'function');
  w._psCapture = null;
  ml = mapLog({ repos: 1, backupJobs: 2, vmTapeJobs: 1 });
  w.parseLog(ml.text, 'map5.log');
  const out = w.buildMapSvg(w.D.backupMap);
  ok('SVG contains a tape archive node', out.svg.indexOf('Tape archive') !== -1);
  ok('SVG well-formed (single root close)', (out.svg.match(/<\/svg>/g) || []).length === 1);

  console.log('\n=== 15. Media pool inventory — media without an active tape job ===');
  parse(orphanMediaLog());
  let Dp = w.D;
  eq('pools deduplicated across runs', Dp.tapeMediaPoolList.length, 3);
  eq('total cartridges', Dp.tapeMediaPoolList.reduce((a, p) => a + p.tapes, 0), 90);
  ok('pool types captured', Dp.tapeMediaPoolList.map(p => p.type).join(',') === 'Retired,Imported,Unrecognized', Dp.tapeMediaPoolList.map(p => p.type).join(','));
  ok('capacity captured', Dp.tapeMediaPoolList[1].capacity === 112480003031040);
  eq('no Free pool -> free tapes null', Dp.tapeFreeTapes, null);
  eq('no tape jobs', Dp.tapeJobs, 0);
  eq('no tape servers', Dp.tapeServers || 0, 0);
  // BP checks: no active tape estate, so the scored checks stay empty (media alone is not a job to score).
  eq('no scored BP checks for orphaned media', w.tapeBPChecks(Dp).length, 0);

  // Tab rendering: the orphaned-media state and inventory appear; the estimate is hypothetical.
  let shimA = { fromLog: true, tapeServers: 0, tapeJobs: 0, vmTapeJobs: 0, fileTapeJobs: 0,
    tapeLibraries: 0, tapeDrives: 0, mediaPools: 3, gfsMediaPools: 0, tapeLTO: null,
    tapeMediaPoolList: Dp.tapeMediaPoolList, tapeTapesTotal: Dp.tapeTapesTotal, dataTB: 20, ret: 10 };
  let htmlA = w.tapeTab(shimA);
  ok('orphaned-media banner shown', htmlA.indexOf('no active tape backup') !== -1);
  ok('inventory table shown', htmlA.indexOf('Media pool inventory') !== -1);
  ok('idle-media advice shown', htmlA.indexOf('these cartridges are idle') !== -1);
  ok('estimate marked hypothetical', htmlA.indexOf('Hypothetical.') !== -1);
  ok('old "no tape server or tape jobs" text gone', htmlA.indexOf('no tape server or tape jobs found in the log') === -1);

  // Genuinely empty tape (no media, no jobs) still says no infrastructure, no inventory table.
  parse(noTapeLog());
  let shimB = { fromLog: true, tapeServers: 0, tapeJobs: 0, tapeMediaPoolList: w.D.tapeMediaPoolList,
    tapeTapesTotal: w.D.tapeTapesTotal, mediaPools: w.D.mediaPools, gfsMediaPools: 0, dataTB: 10, ret: 10 };
  let htmlB = w.tapeTab(shimB);
  ok('truly-empty: no-infrastructure banner', htmlB.indexOf('No tape infrastructure detected') !== -1);
  ok('truly-empty: no inventory table', htmlB.indexOf('Media pool inventory') === -1);

  console.log('\n=== 16. Coverage rework — combined protection + reliability gate ===');
  // Reliable: backup + replica + agent, no overshoot, every job enumerates VMs.
  parse(coverageLog({ infraVMs: 100, backupJobs: [30, 30], replicaJobs: [20], agents: 10 }));
  let Dc = w.D;
  eq('combined = backup+replica+agent', Dc.combinedProtected, 90);
  eq('replicaVMs counted', Dc.replicaVMs, 20);
  ok('reliable estimate flagged reliable', Dc.coverageReliable === true);
  eq('reliable coverage %', Dc.coveragePct, 90);
  eq('unprotected computed', Dc.unprotectedVMs, 10);

  // Overshoot: counts exceed infra -> withhold %, flag unreliable (the old false-100%).
  parse(coverageLog({ infraVMs: 100, backupJobs: [80], replicaJobs: [40] }));
  Dc = w.D;
  ok('overshoot -> not reliable', Dc.coverageReliable === false);
  eq('overshoot -> % withheld', Dc.coveragePct, null);
  ok('overshoot -> reason recorded', Dc.coverageReasons.length > 0);
  ok('overshoot -> floor capped at 100%', Dc.coverageFloor === 100);

  // Zero-enumeration active job (VMsCount 0 but has data) -> withhold, ceil = infra.
  parse(coverageLog({ infraVMs: 100, backupJobs: [30, 0] }));
  Dc = w.D;
  ok('zero-enum active job -> not reliable', Dc.coverageReliable === false);
  eq('zero-enum -> % withheld', Dc.coveragePct, null);
  eq('zero-enum -> ceiling is infra', Dc.coverageCeil, 100);
  ok('zero-enum -> floor is what we can attribute', Dc.coverageFloor === 30);

  // Disabled/empty job (0 VMs AND 0 size) must NOT trip the gate.
  parse(coverageLog({ infraVMs: 100, backupJobs: [30, 0], zeroDataIdx: [1] }));
  Dc = w.D;
  ok('disabled empty job -> still reliable', Dc.coverageReliable === true);
  eq('disabled empty job -> % computed', Dc.coveragePct, 30);

  // Replica-first estate (mostly replica, few backup jobs): no ambiguity -> reliable,
  // and NOT mislabelled near-0%.
  parse(coverageLog({ infraVMs: 100, backupJobs: [4], replicaJobs: [40, 40] }));
  Dc = w.D;
  ok('replica-first -> reliable', Dc.coverageReliable === true);
  eq('replica-first -> combined counts replica', Dc.combinedProtected, 84);
  ok('replica-first -> not near-zero', Dc.coveragePct === 84);

  // Hyper-V platform path works identically.
  parse(coverageLog({ platform: 'HyperV', infraVMs: 50, backupJobs: [25], replicaJobs: [10] }));
  Dc = w.D;
  eq('HyperV infra parsed', Dc.infraVMs, 50);
  eq('HyperV combined', Dc.combinedProtected, 35);
  ok('HyperV reliable %', Dc.coverageReliable && Dc.coveragePct === 70);

  console.log('\n=== 17. A+ — JOB TYPE COUNTS cross-check & backup-copy exclusion ===');
  // Backup-copy jobs (JobSourceType: Backup) must not count as primary protection.
  parse(coverageLog({ infraVMs: 100, platform: 'VMware', backupJobs: [30, 20], copyJobs: [30, 20] }));
  let Da = w.D;
  eq('copy jobs excluded from backup count', Da.protectedVMs, 50);
  ok('copy jobs do not inflate combined', Da.combinedProtected === 50, Da.combinedProtected);

  // A+ reconciliation: authoritative section matches jobs seen -> stays reliable.
  parse(coverageLog({ infraVMs: 100, platform: 'VMware', backupJobs: [30, 20], replicaJobs: [10],
    jobCounts: { VDDKBackup: 2, ReplicaVMware: 1 } }));
  Da = w.D;
  ok('jobTypeCounts parsed', Da.jobTypeCounts && Da.jobTypeCounts.VDDKBackup === 2);
  ok('auth matches seen -> reliable', Da.coverageReliable === true, JSON.stringify(Da.coverageReasons));
  eq('auth-backup vs seen recorded', Da.jobCountAuth.backup + '/' + Da.jobCountAuth.seenBackup, '2/2');

  // A+ catches a shortfall: authoritative reports more backup jobs than the estimate saw.
  parse(coverageLog({ infraVMs: 100, platform: 'VMware', backupJobs: [30], replicaJobs: [10],
    jobCounts: { VDDKBackup: 5, ReplicaVMware: 1 } }));
  Da = w.D;
  ok('shortfall -> unreliable', Da.coverageReliable === false);
  ok('shortfall reason mentions authoritative', Da.coverageReasons.some(r => /authoritative/.test(r)), JSON.stringify(Da.coverageReasons));

  // Cross-check skipped cleanly when no JOB TYPE COUNTS section exists.
  parse(coverageLog({ infraVMs: 100, platform: 'VMware', backupJobs: [30, 30, 20] }));
  Da = w.D;
  ok('no section -> jobCountAuth null, no crash', Da.jobCountAuth == null);
  eq('no section -> still computes coverage', Da.coveragePct, 80);

  console.log('\n=== 18. Tab toolbar moved to top of results panel ===');
  w.parseLog(tapeLog({ vmJobs: 1, fileJobs: 2 }), 't.log');
  if (w.calculate) w.calculate();
  const resHtml = w.document.getElementById('results') ? w.document.getElementById('results').innerHTML : '';
  ok('results rendered', resHtml.length > 0);
  const tbIdx = resHtml.indexOf('tabs-toolbar');
  const stIdx = resHtml.indexOf('srow');
  ok('toolbar present', tbIdx >= 0);
  ok('toolbar renders before the stat cards', tbIdx >= 0 && (stIdx < 0 || tbIdx < stIdx), tbIdx + ' vs ' + stIdx);
  const tabsN = (resHtml.match(/class="tab[ "]/g) || []).length;
  eq('all 16 tabs present', tabsN, 16);
  ok('tab-content container intact', resHtml.indexOf('id="tc"') >= 0);
  // sw() still maps tab -> panel by index
  const tabsEl = w.document.querySelectorAll('.tab');
  const panelsEl = w.document.querySelectorAll('#tc>div');
  eq('tabs and panels equal count', tabsEl.length, panelsEl.length);
  if (tabsEl.length > 12) {
    w.sw(12, tabsEl[12]);
    ok('clicking a tab activates its panel', tabsEl[12].classList.contains('active') && panelsEl[12].classList.contains('active'));
    ok('exactly one active tab after switch', w.document.querySelectorAll('.tab.active').length === 1);
  }

  console.log('\n=== 18b. v2.2 fix — immutability parsed in all 3 log formats ===');
  // Build a minimal repo block in each immutability format and confirm each is read as
  // immutable. Regression for the Value/Unit form (LinuxHardened appliances) that was
  // previously missed and shown as "Not set".
  function repoImmutLog(immutField) {
    const TS = '[10.06.2026 16:08:40.230]    <21> [0006]    Info (3)    ';
    return [
      'Starting new log', TS + 'STARTCOLLECTINFRASTATISTIC',
      TS + 'VMware Infrastructure: { VirtualMachines: 10, Hosts: 1, Clusters: 1 }',
      TS + '=======================CURRENT REPOSITORIES==========================',
      TS + 'RepositoryID: aaaa0201-bbbb-cccc-dddd-eeee0201ffff, Type: LinuxHardened, TotalSpace: 128781914112, FreeSpace: 77662965760, ' + immutField,
      TS + 'REPOSITORY TYPE COUNTS'
    ].join('\n') + '\n';
  }
  // Form (a): Enabled: True
  parse(repoImmutLog('ImmutabilitySettings: { Enabled: True, Value: 7 }'));
  ok('form (a) Enabled:True -> immutable', w.D.repoList[0] && w.D.repoList[0].immut === true);
  // Form (b): Value/Unit, no Enabled key (the reported bug)
  parse(repoImmutLog('ImmutabilitySettings: { Value: 7, Unit: Days }'));
  ok('form (b) Value:7 -> immutable', w.D.repoList[0] && w.D.repoList[0].immut === true);
  eq('form (b) days extracted', w.D.repoList[0] && w.D.repoList[0].immutDays, 7);
  // Form (c): BackupImmutability Enabled
  parse(repoImmutLog('BackupImmutability: { Enabled: True, Days: 14 }'));
  ok('form (c) BackupImmutability -> immutable', w.D.repoList[0] && w.D.repoList[0].immut === true);
  // Negative: Value:0 / Enabled:False must NOT be immutable
  parse(repoImmutLog('ImmutabilitySettings: { Enabled: False }'));
  ok('Enabled:False -> not immutable', w.D.repoList[0] && w.D.repoList[0].immut === false);

  console.log('\n=== 19. v2.2 — Encryption posture (3 tiers) ===');
  ok('encryptionSection defined', typeof w.encryptionSection === 'function');

  // Fully encrypted, immutable, transit off.
  parse(encryptionLog({ jobsEnc: 5, jobsUnenc: 0, reposImmut: 2, reposPlain: 0, configEncrypted: true, transitOff: true }));
  let E = w.D.encPosture;
  eq('all jobs encrypted', E.jobsEnc + '/' + E.jobsTot, '5/5');
  eq('atRest headline = on', E.atRest, 'on');
  eq('repos immutable', E.reposImmut + '/' + E.reposTot, '2/2');
  eq('config encrypted', E.configEncrypted, true);
  eq('transit off (BPA)', E.transit, 'off');

  // Mixed job encryption -> partial, unencrypted rows carried.
  parse(encryptionLog({ jobsEnc: 3, jobsUnenc: 2, reposImmut: 1, reposPlain: 2 }));
  E = w.D.encPosture;
  eq('mixed jobs', E.jobsEnc + '/' + E.jobsTot, '3/5');
  eq('atRest headline = partial', E.atRest, 'partial');
  eq('per-job rows carried', E.jobRows.length, 5);
  eq('per-repo rows carried', E.repoRows.length, 3);

  // No job encryption at all -> off (the common repo-only estate).
  parse(encryptionLog({ jobsEnc: 0, jobsUnenc: 4, reposImmut: 0, reposPlain: 1 }));
  E = w.D.encPosture;
  eq('no job encryption -> off', E.atRest, 'off');

  // Transit not flagged when no BPA violation.
  parse(encryptionLog({ jobsEnc: 2, jobsUnenc: 0, transitOff: false }));
  E = w.D.encPosture;
  eq('transit not-flagged (no BPA)', E.transit, 'not-flagged');

  // Config backup plaintext surfaces.
  parse(encryptionLog({ jobsEnc: 1, configEncrypted: false }));
  eq('config plaintext', w.D.encPosture.configEncrypted, false);

  // Section renders all three tiers with KB links.
  parse(encryptionLog({ jobsEnc: 2, jobsUnenc: 1, reposImmut: 1, reposPlain: 1 }));
  const secHtml = w.encryptionSection(w.D);
  ok('renders at-rest panel', secHtml.indexOf('At rest') !== -1);
  ok('renders in-transit panel', secHtml.indexOf('In transit') !== -1);
  ok('renders per-job tier', secHtml.indexOf('Per backup job') !== -1);
  ok('renders per-repo tier', secHtml.indexOf('Per repository') !== -1);
  ok('KB ver=13 link present', secHtml.indexOf('data_encryption.html?ver=13') !== -1);
  ok('unencrypted job shows Enable link', secHtml.indexOf('Enable') !== -1);
  ok('BPA transit caveat present', secHtml.indexOf('flags it') !== -1);

  // No encryption data at all -> section stays empty (no crash, nothing invented).
  parse(noTapeLog());
  ok('no data -> empty section, no crash', typeof w.encryptionSection(w.D) === 'string');

  console.log('\n=== 20a. v2.2 — Encryption posture in PDF export ===');
  // Build the PDF report directly (bypassing the map-raster/print path jsdom can't run).
  w.print = function () {};
  parse(encryptionLog({ jobsEnc: 2, jobsUnenc: 2, reposImmut: 1, reposPlain: 1, transitOff: true }));
  if (w.calculate) { try { w.calculate(); } catch (e) {} }
  let pdfOk = false, pdfHtml = '';
  if (typeof w._exportPDFNow === 'function') {
    try { w._exportPDFNow(); } catch (e) {}
    const pr = w.document.getElementById('pdfReport');
    pdfHtml = pr ? pr.innerHTML : '';
    pdfOk = pdfHtml.length > 0;
  }
  ok('PDF report built', pdfOk);
  if (pdfOk) {
    ok('PDF has Encryption posture section', pdfHtml.indexOf('Encryption posture') !== -1);
    ok('PDF shows at-rest state', pdfHtml.indexOf('At rest') !== -1);
    ok('PDF shows in-transit state', pdfHtml.indexOf('In transit') !== -1);
    ok('PDF has per-job tier', pdfHtml.indexOf('Per backup job') !== -1);
    ok('PDF has per-repo tier', pdfHtml.indexOf('Per repository') !== -1);
    ok('PDF shows unencrypted job', pdfHtml.indexOf('Not encrypted') !== -1);
    ok('PDF carries BPA in-transit caveat', pdfHtml.indexOf('flags it off') !== -1);
  }

  console.log('\n=== 20. v2.2 version stamps ===');  ok('title bumped to v2.2', html.indexOf('<title>Veeam Advisor v2.2</title>') !== -1);
  ok('hero pill v2.2', html.indexOf('>v2.2</span>') !== -1);
  ok('no stale v2.1.01 title', html.indexOf('<title>Veeam Advisor v2.1.01</title>') === -1);

  console.log('\n----------------------------------------');
  console.log(pass + ' passed, ' + fail + ' failed');
  process.exit(fail ? 1 : 0);
}, 1500);
