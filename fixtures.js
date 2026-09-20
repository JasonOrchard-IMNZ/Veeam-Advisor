// Veeam Advisor — synthetic collection-log fixtures for the v2.1.01 tape tests.
//
// Entirely fabricated. No customer, lab or production data is used or referenced:
// hostnames, GUIDs and sizes below are invented to exercise specific parser paths,
// and the tape hardware strings are generic vendor model names, not a real inventory.
//
// Each builder returns a minimal log that contains only the records the tape parser
// reads, in the same shape a real collection emits.

const TS = '[04.03.2026 09:15:00.000]    <11> [0001]    Info (3)    ';
function line(s) { return TS + s; }

// Deterministic, obviously-synthetic GUIDs.
function guid(n) {
  const h = String(n).padStart(4, '0');
  return 'aaaa' + h + '-bbbb-cccc-dddd-eeee' + h + 'ffff';
}

function header() {
  return [
    'Starting new log',
    line('STARTCOLLECTINFRASTATISTIC'),
    line('MachineName: [LAB-VBR-01]'),
    line('HostName: [LAB-VBR-01]'),
    line('VMs: 100, Hosts: 4, Clusters: 1, Jobs: 3'),
  ];
}

/**
 * Tape estate fixture.
 *   driveModel  — string written into [TapeDrives] Model
 *   libraries   — estate-wide LibrariesCount
 *   drives      — estate-wide DrivesCount
 *   poolTypes   — array of Type: values for [MediaPools] records
 *   vmJobs      — number of VmTapeBackup jobs
 *   fileJobs    — number of FileTapeBackup jobs
 *   tapeServers — number of [TapeServers] records
 *   perServerLibraries — TapeLibrariesCount on each [TapeServers] record
 *   omitMediaPoolRecords — emit no [MediaPools] lines (exercises the fallback)
 */
function tapeLog(o) {
  o = o || {};
  const driveModel = o.driveModel !== undefined ? o.driveModel : 'GENERIC Ultrium 7-SCSI';
  const libraries = o.libraries !== undefined ? o.libraries : 1;
  const drives = o.drives !== undefined ? o.drives : 1;
  const poolTypes = o.poolTypes !== undefined ? o.poolTypes : ['Free', 'UserSimple', 'Imported', 'Retired'];
  const vmJobs = o.vmJobs !== undefined ? o.vmJobs : 1;
  const fileJobs = o.fileJobs !== undefined ? o.fileJobs : 5;
  const tapeServers = o.tapeServers !== undefined ? o.tapeServers : 1;
  const perServerLibraries = o.perServerLibraries !== undefined ? o.perServerLibraries : libraries;
  const L = header();

  L.push(line('Veeam infrastructure: {Proxies: 2, Repositories: 3, TapeServers: ' + tapeServers + ', WANAccelerators: 0}'));

  L.push(line('Tape infrastructure: {LibrariesCount: ' + libraries + ', DrivesCount: ' + drives +
    ', MediaPoolsCount: ' + poolTypes.length + ', TapesCount: 60' +
    ', VaultsCount: ' + (o.vaults !== undefined ? o.vaults : 0) +
    ', NDMPHostsCount: 0, NDMPClustersCount: 0' +
    ', WormTapesCount: ' + (o.wormTapes !== undefined ? o.wormTapes : 0) +
    ', TapeProxiesCount: 1}'));

  for (let i = 0; i < libraries; i++) {
    L.push(line('[TapeLibrary] TapeLibraryID: ' + guid(100 + i) + ', Model: GENERIC 1x8 AUTOLOADER' +
      ', ServerID: ' + guid(200 + i) + ', Type: Automated, DrivesCount: ' + drives +
      ', SlotsCount: 8, TapesCount: 60, IEPortsCount: 1, IsAutoCleaningEnabled: ' + (o.autoClean ? 'True' : 'False') +
      ', IsNativeSCSICommandsEnabled: True, CleaningTapesCount: ' + (o.cleaningTapes !== undefined ? o.cleaningTapes : 0) +
      ', MaintenanceEnabled: False'));
  }

  for (let i = 0; i < drives; i++) {
    L.push(line('[TapeDrives] DeviceID: ' + guid(300 + i) + ', Location: ' + guid(100) +
      ', Standalone: False, Address: ' + i + ', Enabled: True, Model: ' + driveModel +
      ', ServerID: ' + guid(200) + ', MinimumBlockSize: 4096, MaximumBlockSize: 1048576' +
      ', DefaultBlockSize: 262144, CurrentBlockSize: 262144, IsCleaningRequired: ' +
      (o.cleaningRequired ? 'True' : 'False')));
  }

  if (!o.omitMediaPoolRecords) {
    const offline = o.offlineTracking ? 'True' : 'False';
    poolTypes.forEach(function (t, i) {
      // ParallelDrivesCount is deliberately higher than the physical drive count by
      // default, so the drive-count check cannot mistake it for the tape drive count.
      const freeTapes = (/^Free$/i.test(t) && o.freeTapes !== undefined) ? o.freeTapes : 15;
      L.push(line('[MediaPools] MediaPoolID: ' + guid(400 + i) + ', Type: ' + t +
        ', TapesCount: ' + freeTapes + ', Capacity: 90000000000000, Remaining: 45000000000000' +
        ', ParallelDrivesCount: ' + (o.parallelDrives !== undefined ? o.parallelDrives : 4) +
        ', IsOfflineMediaTrackingEnabled: ' + offline));
    });
  }

  for (let i = 0; i < tapeServers; i++) {
    L.push(line('[TapeServers] TapeServerID: ' + guid(500 + i) + ', LinkedProxyID: ' + guid(200 + i) +
      ', IsPhysical: True, Platform: Windows, OSVersion: 10.0, TapeDevicesCount: 2' +
      ', TapeLibrariesCount: ' + perServerLibraries));
  }

  const enc = o.encryption ? 'True' : 'False';
  const manual = o.manualJobs ? 'True' : 'False';
  const notif = o.notifications === false ? 'False' : (o.notifications ? 'True' : 'False');
  const mediaSet = o.dailyMediaSet ? 'Daily' : 'Always';
  const retType = o.protectRetention ? 'Protect' : 'Overwrite';
  const gfsW = o.gfsCounts ? 4 : 0;
  for (let i = 0; i < vmJobs; i++) {
    // Image (VM) jobs: hardware compression should be OFF.
    L.push(line('PlatformId: ' + guid(600 + i) + ', PlatformName: VMware, JobID: ' + guid(600 + i) +
      ', Type: VmTapeBackup, TargetType: Tape, JobSourceType: Backups, ScheduleEnabled: True' +
      ', RunManually: ' + manual + ', NotificationsEnabled: ' + notif +
      ', IsEncryptionEnabled: ' + enc +
      ', IsHardwareCompressionEnabled: ' + (o.vmCompressionOn ? 'True' : 'False') +
      ', IsIncrementProcessingEnabled: False' +
      ', NewMediaSetSetting: ' + mediaSet + ', RetentionPolicy: {Type: ' + retType + '}' +
      ', GFSWeeklyCount: ' + gfsW + ', GFSMonthlyCount: 0, GFSQuarterlyCount: 0, GFSYearlyCount: 0' +
      ', MediaPoolType: Regular, ParallelDriveSettings: {Limit: ' + (o.jobParallel !== undefined ? o.jobParallel : 1) + '}' +
      ', SourceItemsCount: 4, SourceRepositoriesCount: 0, SourceBackupJobsCount: 4'));
  }
  for (let i = 0; i < fileJobs; i++) {
    // File-to-tape jobs: hardware compression should be ON.
    L.push(line('PlatformId: ' + guid(700 + i) + ', PlatformName: VMware, JobID: ' + guid(700 + i) +
      ', Type: FileTapeBackup, TargetType: Tape, JobSourceType: Files, ScheduleEnabled: True' +
      ', RunManually: ' + manual + ', NotificationsEnabled: ' + notif +
      ', IsEncryptionEnabled: ' + enc +
      ', IsHardwareCompressionEnabled: ' + (o.fileCompressionOff ? 'False' : 'True') +
      ', IsIncrementProcessingEnabled: False' +
      ', NewMediaSetSetting: ' + mediaSet + ', RetentionPolicy: {Type: ' + retType + '}' +
      ', MediaPoolType: Regular, ParallelDriveSettings: {Limit: ' + (o.jobParallel !== undefined ? o.jobParallel : 1) + '}' +
      ', SourceItemsCount: 2'));
  }

  return L.join('\n') + '\n';
}

/**
 * Coverage fixture. Builds an estate with a known infra VM count and controllable
 * backup / replica jobs (each with an explicit VMsCount) plus an agent count, to
 * exercise combined protection and the reliability gate.
 *   platform     — 'VMware' | 'HyperV' (infra section token)
 *   infraVMs     — discovered VM count
 *   backupJobs   — array of VMsCount per backup job (IncludedSize>0 unless zeroData)
 *   replicaJobs  — array of VMsCount per replica job
 *   agents       — agent-protected machine count
 *   zeroDataIdx  — indices in backupJobs that are 0-VM AND 0-size (disabled/empty)
 */
function coverageLog(o) {
  o = o || {};
  const platform = o.platform || 'VMware';
  const infraVMs = o.infraVMs !== undefined ? o.infraVMs : 100;
  const backupJobs = o.backupJobs || [];
  const replicaJobs = o.replicaJobs || [];
  const agents = o.agents || 0;
  const zeroDataIdx = o.zeroDataIdx || [];
  const L = header();
  const infraLabel = platform === 'HyperV' ? 'Hyper-V Infrastructure' : 'VMware Infrastructure';
  L.push(line(infraLabel + ': { VirtualMachines: ' + infraVMs + ', Hosts: 3, Clusters: 1 }'));
  backupJobs.forEach(function (vms, i) {
    const size = zeroDataIdx.indexOf(i) >= 0 ? 0 : (vms > 0 ? vms * 100000000000 : 500000000000);
    L.push(line('PlatformName: ' + platform +
      ', JobID: ' + guid(800 + i) + ', Type: Backup, JobSourceType: ' + platform +
      ', ScheduleEnabled: True, Platform: E' + platform + ', VMsCount: ' + vms +
      ', IncludedSize: ' + size + ', RetentionPolicy: { Value: 14, Unit: Days }'));
  });
  replicaJobs.forEach(function (vms, i) {
    L.push(line('PlatformName: ' + platform +
      ', JobID: ' + guid(900 + i) + ', Type: Replica, JobSourceType: ' + platform +
      ', ScheduleEnabled: True, Platform: E' + platform + ', VMsCount: ' + vms +
      ', IncludedSize: ' + (vms > 0 ? vms * 100000000000 : 500000000000) + ', IsCloudTarget: False'));
  });
  // Backup-copy jobs: Type: Backup but JobSourceType: Backup (source is other backups).
  // Must NOT be counted as primary protection.
  (o.copyJobs || []).forEach(function (vms, i) {
    L.push(line('PlatformName: ' + platform +
      ', JobID: ' + guid(1100 + i) + ', Type: Backup, JobSourceType: Backup' +
      ', ScheduleEnabled: True, Platform: E' + platform + ', VMsCount: ' + vms +
      ', IncludedSize: ' + (vms * 100000000000) + ', SourceBackupJobs: [' + guid(800) + ']'));
  });
  // Agent-protected machines: managed AgentBackup jobs (ComputerType Server) — matched
  // by the jobRecords parser (JobID:..., Type: AgentBackup, ComputerType: Server).
  for (let i = 0; i < agents; i++) {
    L.push(line('JobID: ' + guid(1000 + i) + ', Type: AgentBackup, ComputerType: Server' +
      ', ScheduleEnabled: True, VMsCount: 1, IncludedSize: 100000000000'));
  }
  // Optional authoritative JOB TYPE COUNTS section for the A+ cross-check.
  if (o.jobCounts) {
    const jc = o.jobCounts;
    L.push(line('=======================JOB TYPE COUNTS=========================='));
    L.push(line('Job counts: { VDDKBackup: ' + (jc.VDDKBackup || 0) +
      ', BackupHV: ' + (jc.BackupHV || 0) +
      ', ReplicaVMware: ' + (jc.ReplicaVMware || 0) +
      ', ReplicaHV: ' + (jc.ReplicaHV || 0) + ' }'));
  }
  return L.join('\n') + '\n';
}

/** A log with no tape infrastructure at all. */
function noTapeLog() {
  return header().join('\n') + '\n' +
    line('Veeam infrastructure: {Proxies: 2, Repositories: 3, TapeServers: 0, WANAccelerators: 0}') + '\n';
}

/**
 * Orphaned-media log: media pools and cartridges exist, but no tape server, library,
 * drive or tape job — a decommissioned or imported tape estate. Each pool record is
 * emitted twice to mimic the real collector repeating per run (dedup is exercised).
 *   pools — array of {type, tapes, capacity, remaining}
 */
function orphanMediaLog(o) {
  o = o || {};
  const pools = o.pools || [
    { type: 'Retired', tapes: 1, capacity: 1520000040960, remaining: 148052639744 },
    { type: 'Imported', tapes: 77, capacity: 112480003031040, remaining: 23798750380032 },
    { type: 'Unrecognized', tapes: 12, capacity: 10640000286720, remaining: 167757479936 }
  ];
  const totalTapes = pools.reduce((a, p) => a + p.tapes, 0);
  const L = header();
  L.push(line('Veeam infrastructure: {Proxies: 2, Repositories: 3, TapeServers: 0, WANAccelerators: 0}'));
  // two collection passes, same pool ids -> dedup should collapse to one set
  for (let pass = 0; pass < 2; pass++) {
    L.push(line('Tape infrastructure: {LibrariesCount: 0, DrivesCount: 0, MediaPoolsCount: ' + pools.length +
      ', TapesCount: ' + totalTapes + ', VaultsCount: 0, WormTapesCount: 0, TapeProxiesCount: 0}'));
    pools.forEach(function (p, i) {
      L.push(line('[MediaPools] MediaPoolID: ' + guid(400 + i) + ', Type: ' + p.type +
        ', TapesCount: ' + p.tapes + ', Capacity: ' + p.capacity + ', Remaining: ' + p.remaining));
    });
  }
  return L.join('\n') + '\n';
}

/**
 * A Resiliency-map log: repositories, backup jobs targeting them, and tape jobs.
 * Used to exercise the repo -> tape edge (leg 3).
 *   repos        — number of repositories
 *   backupJobs   — number of backup jobs (round-robin across repos)
 *   vmTapeJobs   — number of VM-to-tape jobs
 *   fileTapeJobs — number of file-to-tape jobs
 *   tapeSourceGuids — if true, VM-to-tape jobs carry explicit SourceBackupJobs GUIDs
 */
function mapLog(o) {
  o = o || {};
  const repos = o.repos !== undefined ? o.repos : 1;
  const backupJobs = o.backupJobs !== undefined ? o.backupJobs : 2;
  const vmTapeJobs = o.vmTapeJobs !== undefined ? o.vmTapeJobs : 1;
  const fileTapeJobs = o.fileTapeJobs !== undefined ? o.fileTapeJobs : 0;
  const L = header();
  const repoId = i => guid(10 + i);
  const bjId = i => guid(100 + i);
  for (let i = 0; i < repos; i++) {
    L.push(line('[Repositories] Id: ' + repoId(i) + ', Name: Repo' + i + ', Type: WinLocal'));
  }
  const bjByRepo = {};
  for (let i = 0; i < backupJobs; i++) {
    const r = i % repos;
    (bjByRepo[r] = bjByRepo[r] || []).push(bjId(i));
    L.push(line('JobID: ' + bjId(i) + ', Type: Backup, BackupRepository: ' + repoId(r) +
      ', IncludedSize: ' + ((i + 1) * 1000000000000)));
  }
  for (let i = 0; i < vmTapeJobs; i++) {
    let src = '';
    if (o.tapeSourceGuids) {
      // give each VM-to-tape job the backup jobs of repo (i % repos)
      const list = bjByRepo[i % repos] || [];
      src = ', SourceBackupJobs: [' + list.join(', ') + ']';
    }
    L.push(line('JobID: ' + guid(600 + i) + ', Type: VmTapeBackup, SourceBackupJobsCount: ' +
      ((bjByRepo[i % repos] || []).length) + src));
  }
  for (let i = 0; i < fileTapeJobs; i++) {
    L.push(line('JobID: ' + guid(700 + i) + ', Type: FileTapeBackup, JobSourceType: Files'));
  }
  return { text: L.join('\n') + '\n', repoId, bjId, bjByRepo };
}

/**
 * A MapCapture Section 6 (TAPE) fixture. Resolves the source backup-job GUIDs behind
 * each VM-to-tape job, exactly as the PowerShell would emit them.
 *   tapeJobId  -> array of {id, name} source backup jobs
 */
function mapCaptureTape(tapeJobs) {
  const L = [];
  L.push('==============================================================================');
  L.push('  6. TAPE  (source job GUIDs the collection log omits live here)');
  L.push('==============================================================================');
  L.push('Tape jobs: ' + tapeJobs.length);
  tapeJobs.forEach(function (tj, i) {
    L.push('');
    L.push("  Tape job 'ToTape" + i + "'  Id: " + tj.id);
    L.push('    Type            : VmTapeBackup');
    L.push('    --- source objects (the GUIDs the collection log omits) ---');
    tj.sources.forEach(function (s) {
      L.push('      ' + s.id + '  ' + s.name);
    });
  });
  L.push('');
  L.push('Tape media pools: 0');
  L.push('');
  L.push('==============================================================================');
  L.push('  5. JOB NAME <-> JOB ID  (join key: the log has the ID, never the name)');
  L.push('==============================================================================');
  L.push('JobId,JobName,JobType,IsReplica');
  return L.join('\n') + '\n';
}

module.exports = { tapeLog, noTapeLog, orphanMediaLog, coverageLog, mapLog, mapCaptureTape, guid };
