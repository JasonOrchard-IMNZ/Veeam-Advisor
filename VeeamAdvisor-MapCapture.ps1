<#
.SYNOPSIS
    Veeam Advisor — Backup Map ground-truth capture (READ ONLY)

.DESCRIPTION
    Collects the job/repository/replica linkage that VMC.log either omits or
    records only as GUIDs, so the Backup Map can be validated against a live VBR
    server and (optionally) enriched with real job names.

    This script CHANGES NOTHING. It only reads.

    Run it on the VBR server, in the same session/time window as the VMC.log
    collection, so the object IDs line up.

.NOTES
    Property names on Veeam's objects differ between v12 and v13 and between job
    types. Rather than assume, Section 0 dumps the actual property surface of one
    object of each kind. Every lookup below is wrapped so a missing property
    degrades to "n/a" instead of terminating the script.

    Output: VeeamAdvisor-MapCapture-<host>-<date>.txt in the current directory.
#>

[CmdletBinding()]
param(
    [string]$OutFile = ".\VeeamAdvisor-MapCapture-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
)

$ErrorActionPreference = 'Continue'

function Emit    { param($t) $t | Tee-Object -FilePath $OutFile -Append | Out-Null; Write-Host $t }
function Section { param($t) Emit ""; Emit ("=" * 78); Emit "  $t"; Emit ("=" * 78) }
function Try-Get {
    # Scalar lookup: returns the value, or an 'n/a (reason)' string. Never throws.
    param([scriptblock]$Block)
    try {
        $v = & $Block
        if ($null -eq $v -or "$v" -eq '') { return 'n/a (null)' }
        return $v
    } catch { return "n/a ($($_.Exception.Message))" }
}
function Try-List {
    # Collection lookup: ALWAYS returns an array, empty on failure.
    # Try-Get must not be used for collections -- @(Try-Get {...}) would wrap the
    # 'n/a (...)' error string into a one-element array and the caller would then
    # iterate over a string, reading $null from every property.
    param([scriptblock]$Block, [string]$Label = 'collection')
    try {
        $v = @(& $Block)
        return ,$v
    } catch {
        Emit "  WARNING: $Label failed: $($_.Exception.Message)"
        return ,@()
    }
}

Emit "Veeam Advisor — Backup Map capture"
Emit "Host: $env:COMPUTERNAME   Date: $(Get-Date -Format 'u')"
Emit "READ ONLY — this script does not modify the VBR configuration."

# ─────────────────────────────────────────────────────────────────────────────
if (-not (Get-Module -ListAvailable -Name Veeam.Backup.PowerShell)) {
    Emit "ERROR: Veeam.Backup.PowerShell module not found. Run this on the VBR server."
    return
}
Import-Module Veeam.Backup.PowerShell -DisableNameChecking -ErrorAction SilentlyContinue

# ─── Connection ──────────────────────────────────────────────────────────────
# This reuses the connection pattern proven in VeeamAdvisor-PowerShell.ps1:
#   1. If a session is already active (running on the server, or the console is
#      open), use it and connect nothing.
#   2. Otherwise connect to the local server. On v13 the Identity Service that
#      Connect-VBRServer authenticates against prioritises port 443, so a default
#      connect (classic 9392) can fail with "Failed to connect to Identity service"
#      even on a healthy server. So we try the machine name on 443 with
#      -ForceAcceptTlsCertificate (v13+), then fall back to localhost.
# Disconnects only the session THIS script opened.
$script:WeConnected = $false
$existing = $null
try { $existing = Get-VBRServerSession -ErrorAction Stop } catch { $existing = $null }

if ($null -ne $existing -and "$($existing.Server)" -ne '') {
    Emit "Active VBR session detected ($($existing.Server)) — reusing it, connecting nothing."
} else {
    Emit "No active VBR session — connecting to the local VBR server (read-only)…"
    # -ForceAcceptTlsCertificate exists on v13+ only; add it only if supported so
    # the script stays v12-compatible.
    $forceTls = [bool](Get-Command Connect-VBRServer -ErrorAction SilentlyContinue |
                       Where-Object { $_.Parameters.Keys -contains 'ForceAcceptTlsCertificate' })
    # Attempt order: cert-bound machine name on 443 (v13 front door), then localhost
    # on 443, then the classic localhost:9392 for v12.
    $attempts = @()
    $a1 = @{ Server = $env:COMPUTERNAME; Port = 443 }; if ($forceTls) { $a1['ForceAcceptTlsCertificate'] = $true }
    $attempts += ,@{ Desc = "$($env:COMPUTERNAME):443 (v13 Identity Service)"; P = $a1 }
    $a2 = @{ Server = 'localhost'; Port = 443 };       if ($forceTls) { $a2['ForceAcceptTlsCertificate'] = $true }
    $attempts += ,@{ Desc = 'localhost:443';           P = $a2 }
    $attempts += ,@{ Desc = 'localhost:9392 (v12)';    P = @{ Server = 'localhost'; Port = 9392 } }

    $lastErr = $null
    foreach ($att in $attempts) {
        try {
            $cp = $att.P; Connect-VBRServer @cp
            $script:WeConnected = $true
            Emit "Connected via $($att.Desc)."
            break
        } catch { $lastErr = $_ }
    }
    if (-not $script:WeConnected) {
        Emit "ERROR: could not connect to the local VBR server. Last error: $($lastErr.Exception.Message)"
        if ("$($lastErr.Exception.Message)" -match 'Identity [Ss]ervice') {
            Emit "  This is the v13 Identity Service on 443. Open the Veeam console once"
            Emit "  (which establishes a session), leave it open, and re-run this script —"
            Emit "  it will reuse that session and connect nothing itself."
        } else {
            Emit "  Run this ON the VBR server, or open the Veeam console first, then re-run."
        }
        return
    }
}

Section "VERSION"
Emit ("VBR: " + (Try-Get { (Get-VBRServerSession).Server } ))
Emit ("PS : " + $PSVersionTable.PSVersion)

# ─────────────────────────────────────────────────────────────────────────────
Section "0. PROPERTY DISCOVERY  (so nothing below has to be guessed)"

# Get-VBRJob warns that it no longer returns computer/agent backup jobs; those
# come from Get-VBRComputerBackupJob on v13. Union both so the capture is complete
# and the deprecation warning is pre-empted.
$allJobs = @()
$allJobs += Try-List { Get-VBRJob } 'Get-VBRJob'
$allJobs += Try-List { Get-VBRComputerBackupJob } 'Get-VBRComputerBackupJob'
$allJobs = @($allJobs | Where-Object { $_ } | Sort-Object Id -Unique)

$sampleBackup  = $allJobs | Where-Object { -not $_.IsReplica } | Select-Object -First 1
$sampleReplica = $allJobs | Where-Object { $_.IsReplica }      | Select-Object -First 1

foreach ($pair in @(
    @{ n = 'Backup job';  o = $sampleBackup },
    @{ n = 'Replica job'; o = $sampleReplica }
)) {
    Emit ""
    Emit "--- $($pair.n): property names ---"
    if ($null -eq $pair.o) { Emit "   (none present on this server)"; continue }
    Emit "   TypeName: $($pair.o.GetType().FullName)"
    ($pair.o | Get-Member -MemberType Property,ScriptProperty |
        Select-Object -ExpandProperty Name) -join ', ' | ForEach-Object { Emit "   $_" }
    Emit ""
    Emit "   --- .Info sub-object properties ---"
    $info = Try-Get { $pair.o.Info }
    if ($info -notlike 'n/a*') {
        ($info | Get-Member -MemberType Property | Select-Object -ExpandProperty Name) -join ', ' |
            ForEach-Object { Emit "   $_" }
    } else { Emit "   $info" }
    Emit ""
    Emit "   --- methods that look like they resolve a target ---"
    ($pair.o | Get-Member -MemberType Method |
        Where-Object { $_.Name -match 'Target|Repository|Host|Linked|Source' } |
        Select-Object -ExpandProperty Name) -join ', ' | ForEach-Object { Emit "   $_" }
}

$sampleCopy = (Try-List { Get-VBRBackupCopyJob } 'Get-VBRBackupCopyJob') | Select-Object -First 1
$sampleConf = (Try-List { Get-VBRConfigurationBackupJob } 'Get-VBRConfigurationBackupJob') | Select-Object -First 1
Emit ""
Emit "--- Configuration backup job: property names ---"
if ($sampleConf -and $sampleConf -notlike 'n/a*') {
    Emit "   TypeName: $($sampleConf.GetType().FullName)"
    ($sampleConf | Get-Member -MemberType Property,ScriptProperty |
        Select-Object -ExpandProperty Name) -join ', ' | ForEach-Object { Emit "   $_" }
} else { Emit "   (no configuration backup job on this server)" }

$sampleTenant = (Try-List { Get-VBRCloudTenant } 'Get-VBRCloudTenant') | Select-Object -First 1
Emit ""
Emit "--- Cloud tenant (provider role): property names ---"
if ($sampleTenant -and $sampleTenant -notlike 'n/a*') {
    Emit "   TypeName: $($sampleTenant.GetType().FullName)"
    ($sampleTenant | Get-Member -MemberType Property,ScriptProperty |
        Select-Object -ExpandProperty Name) -join ', ' | ForEach-Object { Emit "   $_" }
} else { Emit "   (this server hosts no cloud tenants — not a provider)" }

$sampleProvider = (Try-List { Get-VBRCloudProvider } 'Get-VBRCloudProvider') | Select-Object -First 1
Emit ""
Emit "--- Cloud provider (tenant role): property names ---"
if ($sampleProvider -and $sampleProvider -notlike 'n/a*') {
    Emit "   TypeName: $($sampleProvider.GetType().FullName)"
    ($sampleProvider | Get-Member -MemberType Property,ScriptProperty |
        Select-Object -ExpandProperty Name) -join ', ' | ForEach-Object { Emit "   $_" }
} else { Emit "   (this server backs up to no cloud provider)" }
Emit ""
Emit "--- Backup copy job: property names ---"
if ($sampleCopy -and $sampleCopy -notlike 'n/a*') {
    Emit "   TypeName: $($sampleCopy.GetType().FullName)"
    ($sampleCopy | Get-Member -MemberType Property,ScriptProperty |
        Select-Object -ExpandProperty Name) -join ', ' | ForEach-Object { Emit "   $_" }
} else { Emit "   (no backup copy jobs on this server)" }

# ─────────────────────────────────────────────────────────────────────────────
Section "1. REPOSITORIES  (simple + scale-out + external)"

$repoIndex = @{}

$simple = Try-List { Get-VBRBackupRepository } 'Get-VBRBackupRepository'
Emit "Simple repositories: $($simple.Count)"
foreach ($r in $simple) {
    $repoIndex["$($r.Id)"] = $r.Name
    Emit ("  {0,-38} {1,-28} {2}" -f $r.Id, $r.Type, $r.Name)
}

$sobrs = Try-List { Get-VBRBackupRepository -ScaleOut } 'Get-VBRBackupRepository -ScaleOut'
Emit ""
Emit "Scale-out repositories: $($sobrs.Count)"
foreach ($s in $sobrs) {
    $repoIndex["$($s.Id)"] = $s.Name
    Emit ("  {0,-38} {1,-28} {2}" -f $s.Id, 'ScaleOut', $s.Name)
    $extents = Try-List { Get-VBRRepositoryExtent -Repository $s } 'Get-VBRRepositoryExtent'
    foreach ($e in $extents) {
        Emit ("      extent -> {0,-38} {1}" -f (Try-Get { $e.Repository.Id }), (Try-Get { $e.Repository.Name }))
    }
    Emit ("      capacity tier : " + (Try-Get { $s.CapacityExtent.Repository.Name }))
    Emit ("      archive tier  : " + (Try-Get { $s.ArchiveExtent.Repository.Name }))
}

$ext = Try-List { Get-VBRExternalRepository } 'Get-VBRExternalRepository'
Emit ""
Emit "External repositories: $($ext.Count)"
foreach ($e in $ext) {
    $repoIndex["$($e.Id)"] = $e.Name
    Emit ("  {0,-38} {1,-28} {2}" -f $e.Id, (Try-Get { $e.Type }), $e.Name)
}

# The tool observes this GUID as the replica-metadata repository on every server
# it has seen. Confirm whether it is genuinely the built-in default repository.
Emit ""
$defaultGuid = '88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec'
$hit = $simple | Where-Object { "$($_.Id)" -eq $defaultGuid }
if ($hit) {
    Emit "Default-repository hypothesis: GUID $defaultGuid IS present, named '$($hit.Name)', type $($hit.Type)"
} else {
    Emit "Default-repository hypothesis: GUID $defaultGuid NOT present on this server"
}

# ─────────────────────────────────────────────────────────────────────────────
Section "2. JOB -> REPOSITORY  (the map's primary edge; VMC.log has GUIDs, no names)"

Emit ("{0,-38} {1,-22} {2,-9} {3,-38} {4}" -f 'JobId','JobType','IsReplica','TargetRepositoryId','JobName')
foreach ($j in $allJobs) {
    $repoId = Try-Get { $j.Info.TargetRepositoryId }
    if ("$repoId" -like 'n/a*') { $repoId = Try-Get { $j.FindTargetRepository().Id } }
    $repoNm = if ($repoIndex.ContainsKey("$repoId")) { $repoIndex["$repoId"] } else { '(unresolved)' }
    Emit ("{0,-38} {1,-22} {2,-9} {3,-38} {4}" -f $j.Id, $j.JobType, $j.IsReplica, $repoId, $j.Name)
    Emit ("    repo name : $repoNm")
    Emit ("    size      : " + (Try-Get { $j.Info.IncludedSize }))
}

# ─────────────────────────────────────────────────────────────────────────────
Section "3. REPLICA TARGET HOST  (VMC.log records NOTHING here — this is the gap)"

$replicas = $allJobs | Where-Object { $_.IsReplica }
Emit "Replica jobs: $($replicas.Count)"
if ($replicas.Count -eq 0) { Emit "  (none)" }
foreach ($j in $replicas) {
    Emit ""
    Emit "  Job '$($j.Name)'  Id: $($j.Id)"
    Emit ("    TargetHostId    : " + (Try-Get { $j.Info.TargetHostId }))
    Emit ("    GetTargetHost() : " + (Try-Get { $j.GetTargetHost().Name }))
    Emit ("    Target host type: " + (Try-Get { $j.GetTargetHost().Type }))
    Emit ("    TargetDir       : " + (Try-Get { $j.Info.TargetDir }))
    Emit ("    Target datastore: " + (Try-Get { $j.GetTargetDatastore().Name }))
    Emit ("    IsCloudTarget   : " + (Try-Get { $j.Info.IsCloudTarget }))
    Emit ("    Metadata repo   : " + (Try-Get { $j.Info.TargetRepositoryId }))
    Emit ("    ReplicaNameSuffx: " + (Try-Get { $j.Options.ReplicaTargetOptions.ReplicaNameSuffix }))
    Emit ("    TargetHost (raw): " + (Try-Get { $j.TargetHost }))
}

# ─────────────────────────────────────────────────────────────────────────────
Section "4. BACKUP COPY: SOURCE JOBS  (VMC.log gives SourceBackupJobs GUIDs only)"

$copyJobs = Try-List { Get-VBRBackupCopyJob } 'Get-VBRBackupCopyJob'
Emit "Backup copy jobs: $($copyJobs.Count)"
foreach ($cj in $copyJobs) {
    Emit ""
    Emit "  Copy job '$($cj.Name)'  Id: $($cj.Id)"
    Emit ("    Target repository : " + (Try-Get { $cj.Target }))
    Emit ("    TargetRepositoryId: " + (Try-Get { $cj.Info.TargetRepositoryId }))
    W  "    --- source jobs ---"
    $srcs = Try-Get { $cj.LinkedJobs }
    if ("$srcs" -like 'n/a*') { $srcs = Try-Get { $cj.GetLinkedJobs() } }
    if ("$srcs" -like 'n/a*') { $srcs = Try-Get { $cj.Backups } }
    if ("$srcs" -like 'n/a*') { Emit "      (no LinkedJobs/GetLinkedJobs/Backups property — see Section 0 dump)" }
    else { foreach ($s in $srcs) { Emit ("      {0,-38} {1}" -f (Try-Get { $s.Id }), (Try-Get { $s.Name })) } }
}

# ─────────────────────────────────────────────────────────────────────────────
Section "4b. CONFIGURATION BACKUP  (its own cmdlet — Get-VBRJob does NOT return it)"

# The config backup job appears in VMC.log as Type: ConfBackup and the map draws
# it, but it is NOT returned by Get-VBRJob. It has a dedicated cmdlet. Capture it
# so the map's config node can be validated and named.
$confJob = Try-List { Get-VBRConfigurationBackupJob } 'Get-VBRConfigurationBackupJob'
Emit "Configuration backup jobs: $($confJob.Count)"
foreach ($c in $confJob) {
    Emit ""
    Emit "  Config backup '$($c.Name)'  Id: $(Try-Get { $c.Id })"
    Emit ("    Target        : " + (Try-Get { $c.Target }))
    Emit ("    TargetRepositoryId: " + (Try-Get { $c.Info.TargetRepositoryId }))
    Emit ("    Repository    : " + (Try-Get { $c.Repository.Name }))
    Emit ("    Repository Id : " + (Try-Get { $c.Repository.Id }))
    Emit ("    Enabled       : " + (Try-Get { $c.Enabled }))
    Emit ("    Encryption    : " + (Try-Get { $c.EncryptionOptions.Enabled }))
    Emit ("    LastResult    : " + (Try-Get { $c.LastResult }))
}
if ($confJob.Count -eq 0) {
    Emit "  (Get-VBRConfigurationBackupJob returned nothing — on some builds the config"
    Emit "   backup is read via Get-VBRConfigurationBackupJob without arguments only when"
    Emit "   configured; if VMC.log shows a ConfBackup job but this is empty, note it.)"
}

Section "4c. CLOUD CONNECT — PROVIDER ROLE  (tenants THIS server hosts)"

# If this VBR is a Cloud Connect provider, its tenants are the destination for
# inbound backup/replica traffic. VMC.log records these only as aggregate counts
# on TenantID lines; the map does not yet show them. Capture the full picture so a
# provider-side node can be added.
$tenants = Try-List { Get-VBRCloudTenant } 'Get-VBRCloudTenant'
Emit "Cloud tenants hosted by this server: $($tenants.Count)"
foreach ($t in $tenants) {
    Emit ""
    Emit "  Tenant '$(Try-Get { $t.Name })'  Id: $(Try-Get { $t.Id })"
    Emit ("    Type              : " + (Try-Get { $t.Type }))
    Emit ("    Enabled           : " + (Try-Get { $t.Enabled }))
    Emit ("    Lease expiration  : " + (Try-Get { $t.LeaseExpirationDate }))
    Emit ("    Max tasks         : " + (Try-Get { $t.MaxConcurrentTask }))
    Emit ("    Backup resources  : " + (Try-Get { ($t.Resources | Measure-Object).Count }))
    foreach ($r in @(Try-Get { $t.Resources })) {
        Emit ("      repo -> {0,-38} friendly: {1}" -f (Try-Get { $r.RepositoryId }), (Try-Get { $r.RepositoryFriendlyName }))
    }
    Emit ("    Replica resources : " + (Try-Get { ($t.ReplicaResources | Measure-Object).Count }))
    Emit ("    Gateway pool      : " + (Try-Get { $t.GatewayPool.Name }))
}

Section "4d. CLOUD CONNECT — GATEWAY / SERVER"

$gws = Try-List { Get-VBRCloudGateway } 'Get-VBRCloudGateway'
Emit "Cloud gateways: $($gws.Count)"
foreach ($g in $gws) {
    Emit ("  {0,-30} host: {1,-24} port: {2}" -f (Try-Get { $g.Name }), (Try-Get { $g.IpAddress }), (Try-Get { $g.Port }))
}
$pools = Try-List { Get-VBRCloudGatewayPool } 'Get-VBRCloudGatewayPool'
Emit "Cloud gateway pools: $($pools.Count)"
foreach ($p in $pools) {
    Emit ("  pool '{0}' — gateways: {1}" -f (Try-Get { $p.Name }), (Try-Get { ($p.CloudGateways | Measure-Object).Count }))
}

Section "4e. CLOUD CONNECT — PROVIDER THIS SERVER IS A TENANT OF"

# The other direction: this VBR sending backups/replicas UP to a provider. The map
# already shows the provider's BackupStorage repo (VMC.log [CloudProviders] line);
# this confirms the host and the repository it maps to.
$providers = Try-List { Get-VBRCloudProvider } 'Get-VBRCloudProvider'
Emit "Cloud providers this server backs up to: $($providers.Count)"
foreach ($p in $providers) {
    Emit ""
    Emit "  Provider '$(Try-Get { $p.DNSName })'  Id: $(Try-Get { $p.Id })"
    Emit ("    Address           : " + (Try-Get { $p.DNSName }) + " : " + (Try-Get { $p.Port }))
    Emit ("    Backup resources  : " + (Try-Get { ($p.Resources | Measure-Object).Count }))
    foreach ($r in @(Try-Get { $p.Resources })) {
        Emit ("      cloud repo -> {0,-38} {1}" -f (Try-Get { $r.ServerId }), (Try-Get { $r.RepositoryName }))
    }
    Emit ("    Replica resources : " + (Try-Get { ($p.ReplicaResources | Measure-Object).Count }))
}

Section "5. JOB NAME <-> JOB ID  (join key: VMC.log has the ID, never the name)"
Emit "JobId,JobName,JobType,IsReplica"
foreach ($j in $allJobs) { Emit ("{0},{1},{2},{3}" -f $j.Id, $j.Name, $j.JobType, $j.IsReplica) }

Emit ""
if ($script:WeConnected) {
    try { Disconnect-VBRServer -ErrorAction SilentlyContinue; Emit "Disconnected the session this script opened." } catch {}
}
Emit "=== capture complete: $OutFile ==="
