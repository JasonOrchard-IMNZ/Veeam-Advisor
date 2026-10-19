// Builds small synthetic VMC.log texts in the field shapes seen in real VBR v12/v13 logs.
// Contains NO customer data: every id, name and number is made up.
'use strict';
const TS = '[01.10.2026 10:00:00.000]    <18>    Info (3)    ';
const G = n => `${String(n).padStart(8, '0')}-1111-2222-3333-444444444444`;
const S = n => G(n).slice(0, 8);
const ZERO = '00000000-0000-0000-0000-000000000000';

function backupJob(o) {
  o = Object.assign({ id: 1, repo: 50, vms: 2, sched: true, enc: true, size: 1099511627776, type: 'Backup', src: 'VDDK', plat: 'VMware', extra: '' }, o);
  return `${TS}PlatformId: ${ZERO}, PlatformName: ${o.plat}, JobID: ${G(o.id)}, Type: ${o.type}, IsCloudTarget: False, JobSourceType: ${o.src}, IncludedSize: ${o.size}, ScheduleEnabled: ${o.sched ? 'True' : 'False'}, Platform: EVmware, VMsCount: ${o.vms}, BackupRepository: ${G(o.repo)}, RetentionPolicy: { Value: 14, Unit: Points }, Storage: { CompressionLevel: Optimal, Encryption: { Enabled: ${o.enc ? 'True' : 'False'}, EncryptionType: Password } },${o.extra}`;
}
function repo(o) {
  o = Object.assign({ id: 50, type: 'WinLocal', total: 10995116277760, free: 5497558138880, backups: 1, extra: '' }, o);
  return `${TS}RepositoryID: ${G(o.id)}, Type: ${o.type}, TotalSpace: ${o.total}, FreeSpace: ${o.free}, NumberOfBackups: ${o.backups}, RepositoryGroupType: BackupRepository,${o.extra}`;
}
function log(o) {
  o = Object.assign({ version: '12.3.2.4854', jobs: [backupJob({})], repos: [repo({})], vms: 40, extraTop: [], extraJobs: [], extraTail: [], date: '01.10.2026', header: true }, o);
  const ts = TS.replace('01.10.2026', o.date);
  const lines = [];
  if (o.header) lines.push('Starting new log');
  lines.push(`Product: [Veeam Backup and Replication], Version: [${o.version}]`);
  lines.push('CmdLineParams: [STARTCOLLECTINFRASTATISTIC]');
  lines.push(...o.extraTop);
  lines.push(`${ts}[VMware Infrastructure] VirtualMachines: ${o.vms}, HostSystems: 3`);
  lines.push(ts + '=======================CURRENT JOBS INFO==========================');
  lines.push(...o.jobs.map(j => j.replace(TS, ts)), ...o.extraJobs);
  lines.push(ts + '[VmcStats] =CURRENT JOBS INFO= collection result: Success');
  lines.push(ts + '=======================CURRENT REPOSITORIES==========================');
  lines.push(...o.repos.map(r => r.replace(TS, ts)));
  lines.push(ts + '[VmcStats] =CURRENT REPOSITORIES= collection result: Success, Collection time: 00:00:01');
  lines.push(ts + '=======================REPOSITORY TYPE COUNTS==========================');
  lines.push(...o.extraTail);
  return lines.join('\n');
}
module.exports = { TS, G, S, ZERO, backupJob, repo, log };
