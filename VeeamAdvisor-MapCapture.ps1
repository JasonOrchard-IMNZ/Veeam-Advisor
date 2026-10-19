<#
.SYNOPSIS
    Veeam Advisor - Backup Map ground-truth capture (READ ONLY)

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
    [string]$OutFile = ".\VeeamAdvisor-MapCapture-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt",
    # Remote VBR host to connect to. Omit to run against the local VBR server (default).
    [string]$VBRServer,
    # Port for the remote connection. Default 443 (v13 Identity Service); use 9392 for v12.
    [int]$Port = 443,
    # Credential for the remote connection. Omit to use the current Windows identity.
    [System.Management.Automation.PSCredential]$Credential,
    # Opt-in only: pass -ForceAcceptTlsCertificate to Connect-VBRServer (v13+), which
    # accepts the server's TLS certificate WITHOUT validating it. Use only when you
    # have verified the certificate thumbprint yourself (e.g. a self-signed v13 cert).
    [switch]$AcceptAnyCertificate
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
function Try-First {
    # Tries each scriptblock in turn and returns the first value that is not null,
    # empty or an 'n/a (...)' sentinel. Returns 'n/a (null)' if none resolve.
    param([scriptblock[]]$Blocks)
    foreach ($b in $Blocks) {
        $v = Try-Get $b
        if ("$v" -notlike 'n/a*') { return $v }
    }
    return 'n/a (null)'
}
function Get-TypeToken {
    # Single-word type token for a job/repository line. The parser in index.html needs
    # a \w+ token here (Section 1/2 '\S+', Section 5 '\w+'), so never return spaces or
    # 'n/a'. Order: JobType (CBackupJob), Type (VBR* types), .NET type name, 'Unknown'.
    param($Obj)
    foreach ($b in @({ $Obj.JobType }, { $Obj.Type }, { $Obj.GetType().Name })) {
        $v = ''
        try { $v = "$(& $b)" } catch { $v = '' }
        $v = $v -replace '[^A-Za-z0-9_]', ''
        if ($v) { return $v }
    }
    return 'Unknown'
}
function Get-ReplicaFlag {
    # Always 'True' or 'False' (the parser needs one of these). Objects without an
    # IsReplica member (agent jobs, backup copy jobs) are not replica jobs.
    param($Obj)
    $v = $null
    try { $v = $Obj.IsReplica } catch { $v = $null }
    if ("$v" -eq 'True') { return 'True' }
    return 'False'
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

Emit "Veeam Advisor Backup Map capture"
Emit "Host: $env:COMPUTERNAME   Date: $(Get-Date -Format 'u')"
Emit "READ ONLY - this script does not modify the VBR configuration."

# -----------------------------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name Veeam.Backup.PowerShell)) {
    Emit "ERROR: Veeam.Backup.PowerShell module not found. Run this on the VBR server."
    return
}
try {
    Import-Module Veeam.Backup.PowerShell -DisableNameChecking -ErrorAction Stop
} catch {
    # Report the real import error instead of failing later with a misleading
    # "could not connect" message.
    Emit "ERROR: Import-Module Veeam.Backup.PowerShell failed: $($_.Exception.Message)"
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Emit "  This is Windows PowerShell $($PSVersionTable.PSVersion). The VBR v13 module requires"
        Emit "  PowerShell 7 - re-run this script from pwsh.exe on a v13 server."
    }
    return
}

# --- Connection --------------------------------------------------------------
# This reuses the connection pattern proven in VeeamAdvisor-PowerShell.ps1:
#   1. If a session is already active (running on the server, or the console is
#      open), use it and connect nothing.
#   2. Otherwise connect to the local server. On v13 the Identity Service that
#      Connect-VBRServer authenticates against prioritises port 443, so a default
#      connect (classic 9392) can fail with "Failed to connect to Identity service"
#      even on a healthy server. So we try the machine name on 443, then fall back
#      to localhost. -ForceAcceptTlsCertificate (v13+) is added ONLY when the caller
#      passes -AcceptAnyCertificate, because it skips certificate validation while
#      the credential is being sent.
# Disconnects only the session THIS script opened.
$script:WeConnected = $false
$existing = $null
try { $existing = Get-VBRServerSession -ErrorAction Stop } catch { $existing = $null }

# Decide whether an existing session can be reused. An explicit -VBRServer takes
# precedence: reuse only if the current session is ALREADY to that host; otherwise
# drop it and connect to the requested server. Without -VBRServer, any local session
# is fine to reuse.
$existingServer = if ($null -ne $existing) { "$($existing.Server)" } else { '' }
$reuseOk = $false
if ($existingServer -ne '') {
    if (-not $VBRServer) {
        $reuseOk = $true
    } else {
        # match on host or its short name (session may report FQDN/IP)
        $want = $VBRServer.Split('.')[0]
        if ($existingServer -ieq $VBRServer -or $existingServer.Split('.')[0] -ieq $want) { $reuseOk = $true }
    }
}

if ($reuseOk) {
    Emit "Active VBR session detected ($existingServer) - reusing it, connecting nothing."
} else {
    if ($VBRServer -and $existingServer -ne '') {
        Emit "Existing session is to '$existingServer' but -VBRServer '$VBRServer' was requested - disconnecting and reconnecting to the requested host."
        try { Disconnect-VBRServer -ErrorAction SilentlyContinue } catch {}
    }
    if ($VBRServer) { Emit "No active VBR session - connecting to $VBRServer (read-only)..." }
    else            { Emit "No active VBR session - connecting to the local VBR server (read-only)..." }
    # -ForceAcceptTlsCertificate exists on v13+ only, and is opt-in: it is added only
    # when -AcceptAnyCertificate was passed AND the module supports it (v12-compatible).
    $supportsForceTls = [bool](Get-Command Connect-VBRServer -ErrorAction SilentlyContinue |
                       Where-Object { $_.Parameters.Keys -contains 'ForceAcceptTlsCertificate' })
    $forceTls = $AcceptAnyCertificate -and $supportsForceTls
    if ($AcceptAnyCertificate -and -not $supportsForceTls) {
        Emit "NOTE: -AcceptAnyCertificate ignored - this Connect-VBRServer has no -ForceAcceptTlsCertificate (v12)."
    }
    $attempts = @()
    if ($VBRServer) {
        # Explicit remote target. Try the requested port first; if that is the v13 default
        # (443) also fall back to 9392 for a v12 remote. Credential is passed when supplied.
        $base = @{ Server = $VBRServer; Port = $Port }
        if ($forceTls) { $base['ForceAcceptTlsCertificate'] = $true }
        if ($Credential) { $base['Credential'] = $Credential }
        $attempts += ,@{ Desc = "$VBRServer`:$Port (remote)"; P = $base }
        if ($Port -eq 443) {
            $alt = @{ Server = $VBRServer; Port = 9392 }
            if ($Credential) { $alt['Credential'] = $Credential }
            $attempts += ,@{ Desc = "$VBRServer`:9392 (remote v12)"; P = $alt }
        }
    } else {
        # Local-first (unchanged default): cert-bound machine name on 443, then localhost:443,
        # then classic localhost:9392 for v12.
        $a1 = @{ Server = $env:COMPUTERNAME; Port = 443 }; if ($forceTls) { $a1['ForceAcceptTlsCertificate'] = $true }
        $attempts += ,@{ Desc = "$($env:COMPUTERNAME):443 (v13 Identity Service)"; P = $a1 }
        $a2 = @{ Server = 'localhost'; Port = 443 };       if ($forceTls) { $a2['ForceAcceptTlsCertificate'] = $true }
        $attempts += ,@{ Desc = 'localhost:443';           P = $a2 }
        $attempts += ,@{ Desc = 'localhost:9392 (v12)';    P = @{ Server = 'localhost'; Port = 9392 } }
    }

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
        $target = if ($VBRServer) { $VBRServer } else { 'the local VBR server' }
        Emit "ERROR: could not connect to $target. Last error: $($lastErr.Exception.Message)"
        if ("$($lastErr.Exception.Message)" -match 'certificate|thumbprint|SSL|TLS|trust') {
            Emit "  The connection failed on the server's TLS certificate."
            if (-not $AcceptAnyCertificate) {
                Emit "  If you have verified the server certificate (thumbprint) yourself, re-run with"
                Emit "  -AcceptAnyCertificate to accept it without validation (v13+ only). Do not use"
                Emit "  this switch on an untrusted network: the credential is sent to whoever answers."
            }
        } elseif ("$($lastErr.Exception.Message)" -match 'Identity [Ss]ervice') {
            Emit "  This is the v13 Identity Service on 443. Open the Veeam console once"
            Emit "  (which establishes a session), leave it open, and re-run this script -"
            Emit "  it will reuse that session and connect nothing itself."
        } else {
            if ($VBRServer) { Emit "  Check the host is reachable on the port, the VBR service is running, and the credential is valid." }
            else            { Emit "  Run this ON the VBR server, or open the Veeam console first, then re-run. To target a remote host use -VBRServer <host> [-Port 9392] [-Credential (Get-Credential)]." }
        }
        return
    }
}

Section "VERSION"
Emit ("VBR: " + (Try-Get { (Get-VBRServerSession).Server } ))
Emit ("PS : " + $PSVersionTable.PSVersion)

# -----------------------------------------------------------------------------
Section "0. PROPERTY DISCOVERY  (so nothing below has to be guessed)"

# Get-VBRJob warns that it no longer returns computer/agent backup jobs; those
# come from Get-VBRComputerBackupJob on v13. Union both so the capture is complete
# and the deprecation warning is pre-empted.
$allJobs = @()
$allJobs += Try-List { Get-VBRJob } 'Get-VBRJob'
$allJobs += Try-List { Get-VBRComputerBackupJob } 'Get-VBRComputerBackupJob'
$allJobs = @($allJobs | Where-Object { $_ } | Sort-Object Id -Unique)

# Backup copy jobs are not returned by Get-VBRJob on current builds (v13 reference),
# so add them for the Section 2 / Section 5 tables. Skip any Id Get-VBRJob already
# returned (older builds list BackupSync copy jobs there) so no job appears twice.
$copyJobs = Try-List { Get-VBRBackupCopyJob } 'Get-VBRBackupCopyJob'
$knownIds = @{}
foreach ($j in $allJobs) { $knownIds["$($j.Id)"] = $true }
$mapJobs = @($allJobs) + @($copyJobs | Where-Object { $_ -and -not $knownIds.ContainsKey("$($_.Id)") })

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

$sampleCopy = $copyJobs | Select-Object -First 1
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
} else { Emit "   (this server hosts no cloud tenants - not a provider)" }

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

# -----------------------------------------------------------------------------
Section "1. REPOSITORIES  (simple + scale-out + object storage + external)"

$repoIndex = @{}

$simple = Try-List { Get-VBRBackupRepository } 'Get-VBRBackupRepository'
Emit "Simple repositories: $($simple.Count)"
foreach ($r in $simple) {
    $repoIndex["$($r.Id)"] = $r.Name
    Emit ("  {0,-38} {1,-28} {2}" -f $r.Id, $r.Type, $r.Name)
    # v2.2: per-repository at-rest protection (immutability) + any storage encryption,
    # so the encryption posture tab can show real repo names and confirm log values.
    Emit ("      immutable     : " + (Try-Get { $r.GetImmutabilitySettings().IsEnabled }) + "  days: " + (Try-Get { $r.GetImmutabilitySettings().IntervalDays }))
    Emit ("      encryption    : " + (Try-Get { $r.EncryptionEnabled }))
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

# Object storage repositories (S3, Azure Blob, Wasabi, Veeam Data Cloud Vault...) are
# NOT returned by Get-VBRBackupRepository; the Veeam reference says to use
# Get-VBRObjectStorageRepository. Guarded so builds without the cmdlet still run.
$objRepos = @()
if (Get-Command Get-VBRObjectStorageRepository -ErrorAction SilentlyContinue) {
    $objRepos = Try-List { Get-VBRObjectStorageRepository } 'Get-VBRObjectStorageRepository'
    Emit ""
    Emit "Object storage repositories: $($objRepos.Count)"
    foreach ($o in $objRepos) {
        if (-not $o -or $repoIndex.ContainsKey("$($o.Id)")) { continue }
        $repoIndex["$($o.Id)"] = $o.Name
        $oType = Get-TypeToken $o
        if ($oType -eq 'Unknown') { $oType = 'ObjectStorage' }
        Emit ("  {0,-38} {1,-28} {2}" -f $o.Id, $oType, $o.Name)
    }
} else {
    Emit ""
    Emit "Object storage repositories: n/a (Get-VBRObjectStorageRepository not available on this build)"
}

$ext = Try-List { Get-VBRExternalRepository } 'Get-VBRExternalRepository'
Emit ""
Emit "External repositories: $($ext.Count)"
foreach ($e in $ext) {
    $repoIndex["$($e.Id)"] = $e.Name
    $eType = Get-TypeToken $e
    if ($eType -eq 'Unknown') { $eType = 'External' }
    Emit ("  {0,-38} {1,-28} {2}" -f $e.Id, $eType, $e.Name)
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

# -----------------------------------------------------------------------------
Section "2. JOB -> REPOSITORY  (the map's primary edge; VMC.log has GUIDs, no names)"

Emit ("{0,-38} {1,-22} {2,-9} {3,-38} {4}" -f 'JobId','JobType','IsReplica','TargetRepositoryId','JobName')
# Every line always carries a one-word JobType and True/False IsReplica (see
# Get-TypeToken / Get-ReplicaFlag): parseMapCapture() needs both to recognise the
# header line, otherwise the next 'repo name'/'size' lines land on the previous job.
# An unknown repository prints as 'n/a', which the parser maps to "no target".
foreach ($j in $mapJobs) {
    $repoId = Try-First @({ $j.Info.TargetRepositoryId }, { $j.FindTargetRepository().Id }, { $j.Target.Id })
    if ("$repoId" -like 'n/a*') { $repoId = 'n/a' }
    $repoNm = if ($repoIndex.ContainsKey("$repoId")) { $repoIndex["$repoId"] } else { '(unresolved)' }
    Emit ("{0,-38} {1,-22} {2,-9} {3,-38} {4}" -f $j.Id, (Get-TypeToken $j), (Get-ReplicaFlag $j), $repoId, $j.Name)
    Emit ("    repo name : $repoNm")
    Emit ("    size      : " + (Try-Get { $j.Info.IncludedSize }))
    # v2.2: per-job encryption + retention, so the encryption posture tab pairs each
    # job's encryption state with its retention (unencrypted long-retention = top risk)
    # and shows real job names instead of GUIDs.
    Emit ("    encryption: " + (Try-Get { $j.GetOptions().BackupStorageOptions.StorageEncryptionEnabled }))
    Emit ("    retention : " + (Try-Get { $j.GetOptions().BackupStorageOptions.RetainCycles }) + " cycles / " + (Try-Get { $j.GetOptions().GfsPolicy.IsEnabled }) + " GFS")
}

# -----------------------------------------------------------------------------
Section "3. REPLICA TARGET HOST  (VMC.log records NOTHING here - this is the gap)"

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

# -----------------------------------------------------------------------------
Section "4. BACKUP COPY: SOURCE JOBS  (VMC.log gives SourceBackupJobs GUIDs only)"

Emit "Backup copy jobs: $($copyJobs.Count)"
foreach ($cj in $copyJobs) {
    Emit ""
    Emit "  Copy job '$($cj.Name)'  Id: $($cj.Id)"
    Emit ("    Target repository : " + (Try-Get { $cj.Target }))
    Emit ("    TargetRepositoryId: " + (Try-Get { $cj.Info.TargetRepositoryId }))
    Emit "    --- source jobs ---"
    $srcs = Try-Get { $cj.LinkedJobs }
    if ("$srcs" -like 'n/a*') { $srcs = Try-Get { $cj.GetLinkedJobs() } }
    if ("$srcs" -like 'n/a*') { $srcs = Try-Get { $cj.Backups } }
    if ("$srcs" -like 'n/a*') { Emit "      (no LinkedJobs/GetLinkedJobs/Backups property - see Section 0 dump)" }
    else { foreach ($s in $srcs) { Emit ("      {0,-38} {1}" -f (Try-Get { $s.Id }), (Try-Get { $s.Name })) } }
}

# -----------------------------------------------------------------------------
Section "4b. CONFIGURATION BACKUP  (its own cmdlet - Get-VBRJob does NOT return it)"

# The config backup job appears in VMC.log as Type: ConfBackup and the map draws
# it, but it is NOT returned by Get-VBRJob. It has a dedicated cmdlet. Capture it
# so the map's config node can be validated and named.
$confJob = Try-List { Get-VBRConfigurationBackupJob } 'Get-VBRConfigurationBackupJob'
Emit "Configuration backup jobs: $($confJob.Count)"
foreach ($c in $confJob) {
    Emit ""
    # VBRConfigurationBackupJob documents only Enabled, Repository, ScheduleOptions,
    # RestorePointsToKeep and EncryptionOptions - it has no Id, Name or LastResult,
    # so none of those are printed. There is one configuration backup job per server.
    Emit "  Config backup 'Configuration Backup'"
    Emit ("    Enabled       : " + (Try-Get { $c.Enabled }))
    Emit ("    Repository    : " + (Try-Get { $c.Repository.Name }))
    Emit ("    Repository Id : " + (Try-Get { $c.Repository.Id }))
    $sch = Try-Get { $c.ScheduleOptions }
    $schText = if ("$sch" -like 'n/a*') { $sch } else {
        # VBRConfigurationBackupScheduleOptions: Type, Enabled, DailyOptions, MonthlyOptions.
        $parts = @("Type=$(Try-Get { $sch.Type })", "Enabled=$(Try-Get { $sch.Enabled })")
        if ("$(Try-Get { $sch.Type })" -match 'Daily')   { $parts += "Daily at=$(Try-Get { $sch.DailyOptions.Period })" }
        if ("$(Try-Get { $sch.Type })" -match 'Monthly') { $parts += "Monthly at=$(Try-Get { $sch.MonthlyOptions.Period })" }
        $parts -join '; '
    }
    Emit ("    Schedule      : " + $schText)
    Emit ("    RestorePoints : " + (Try-Get { $c.RestorePointsToKeep }))
    Emit ("    Encryption    : " + (Try-Get { $c.EncryptionOptions.Enabled }))
}
if ($confJob.Count -eq 0) {
    Emit "  (Get-VBRConfigurationBackupJob returned nothing - on some builds the config"
    Emit "   backup is read via Get-VBRConfigurationBackupJob without arguments only when"
    Emit "   configured; if VMC.log shows a ConfBackup job but this is empty, note it.)"
}

Section "4c. CLOUD CONNECT - PROVIDER ROLE  (tenants THIS server hosts)"

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
    # Collections use Try-List (never @(Try-Get ...)): an empty or failed lookup must
    # give zero items, not a phantom 'n/a (null)' entry, and must let fallbacks run.
    $backupRes = @((Try-List { $t.Resources } 'tenant Resources') | Where-Object { $null -ne $_ })
    Emit ("    Backup resources  : " + $backupRes.Count)
    foreach ($r in $backupRes) {
        Emit ("      repo -> {0,-38} friendly: {1}" -f (Try-Get { $r.RepositoryId }), (Try-Get { $r.RepositoryFriendlyName }))
    }
    # Replica resources: the property surface differs by version. Try, in order:
    #   1. ReplicaResources / ReplicaResource (older object surfaces)
    #   2. ReplicationResources.HardwarePlanOptions (documented VBRCloudTenant ->
    #      VBRCloudTenantReplicationResources -> VBRCloudTenantHwPlanOptions[])
    #   3. Get-VBRCloudTenantResource -Tenant, only if that cmdlet exists here
    # Each step runs only when the previous one returned nothing.
    $replRes = @((Try-List { $t.ReplicaResources } 'tenant ReplicaResources') | Where-Object { $null -ne $_ })
    if ($replRes.Count -eq 0) { $replRes = @((Try-List { $t.ReplicaResource } 'tenant ReplicaResource') | Where-Object { $null -ne $_ }) }
    if ($replRes.Count -eq 0) { $replRes = @((Try-List { $t.ReplicationResources.HardwarePlanOptions } 'tenant ReplicationResources.HardwarePlanOptions') | Where-Object { $null -ne $_ }) }
    if ($replRes.Count -eq 0 -and (Get-Command Get-VBRCloudTenantResource -ErrorAction SilentlyContinue)) {
        $replRes = @((Try-List { Get-VBRCloudTenantResource -Tenant $t } 'Get-VBRCloudTenantResource') | Where-Object { $null -ne $_ })
    }
    Emit ("    Replica resources : " + $replRes.Count)
    foreach ($rr in $replRes) {
        $hpName = Try-First @({ $rr.HardwarePlanName }, { $rr.HardwarePlan.Name }, { $rr.Name })
        $hpId   = Try-First @({ $rr.HardwarePlanId },   { $rr.HardwarePlan.Id },   { $rr.Id })
        Emit ("      hwplan -> {0,-38} name: {1}" -f $hpId, $hpName)
    }
    Emit ("    Gateway pool      : " + (Try-Get { $t.GatewayPool.Name }))
}

Section "4d. CLOUD CONNECT - GATEWAY / SERVER"

$gws = Try-List { Get-VBRCloudGateway } 'Get-VBRCloudGateway'
Emit "Cloud gateways: $($gws.Count)"
foreach ($g in $gws) {
    Emit ("  {0,-30} host: {1,-24} port: {2}" -f (Try-Get { $g.Name }), (Try-Get { $g.IpAddress }), (Try-Get { $g.Port }))
}
$pools = Try-List { Get-VBRCloudGatewayPool } 'Get-VBRCloudGatewayPool'
Emit "Cloud gateway pools: $($pools.Count)"
foreach ($p in $pools) {
    Emit ("  pool '{0}' - gateways: {1}" -f (Try-Get { $p.Name }), (Try-Get { ($p.CloudGateways | Measure-Object).Count }))
}

Section "4e. CLOUD CONNECT - PROVIDER THIS SERVER IS A TENANT OF"

# The other direction: this VBR sending backups/replicas UP to a provider. The map
# already shows the provider's BackupStorage repo (VMC.log [CloudProviders] line);
# this confirms the host and the repository it maps to.
$providers = Try-List { Get-VBRCloudProvider } 'Get-VBRCloudProvider'
Emit "Cloud providers this server backs up to: $($providers.Count)"
foreach ($p in $providers) {
    Emit ""
    Emit "  Provider '$(Try-Get { $p.DNSName })'  Id: $(Try-Get { $p.Id })"
    Emit ("    Address           : " + (Try-Get { $p.DNSName }) + " : " + (Try-Get { $p.Port }))
    $provRes = @((Try-List { $p.Resources } 'provider Resources') | Where-Object { $null -ne $_ })
    Emit ("    Backup resources  : " + $provRes.Count)
    foreach ($r in $provRes) {
        Emit ("      cloud repo -> {0,-38} {1}" -f (Try-Get { $r.ServerId }), (Try-Get { $r.RepositoryName }))
    }
    Emit ("    Replica resources : " + (Try-Get { ($p.ReplicaResources | Measure-Object).Count }))
}


# -----------------------------------------------------------------------------
Section "6. TAPE  (VMC.log gives GUIDs + source COUNTS only; the source job GUIDs live here)"

# The map's tape edge needs the source backup-job GUIDs behind each VM-to-tape job.
# VMC.log records SourceBackupJobsCount (a number), never the GUIDs, so a repo->tape
# edge cannot be drawn from the log alone once more than one VM-to-tape job exists.
# This section resolves them, plus the media pool / library / drive / server names
# the tab otherwise shows only as GUIDs.

$tapeJobs = Try-List { Get-VBRTapeJob } 'Get-VBRTapeJob'
Emit "Tape jobs: $($tapeJobs.Count)"
foreach ($tj in $tapeJobs) {
    Emit ""
    Emit "  Tape job '$($tj.Name)'  Id: $($tj.Id)"
    Emit ("    Type            : " + (Try-Get { $tj.Type }))
    Emit ("    GFS media pool  : " + (Try-Get { $tj.FullBackupMediaPool.Name }))
    Emit ("    Incr media pool : " + (Try-Get { $tj.IncrementalBackupMediaPool.Name }))
    Emit "    --- source objects (the GUIDs VMC.log omits) ---"
    # VM-to-tape sources are backup jobs; file-to-tape sources are file/NAS objects.
    $srcJobs = Try-Get { $tj.Object }
    if ("$srcJobs" -like 'n/a*') { $srcJobs = Try-Get { $tj.GetObject() } }
    if ("$srcJobs" -like 'n/a*') { $srcJobs = Try-Get { $tj.BackupJob } }
    if ("$srcJobs" -like 'n/a*') { Emit "      (no Object/GetObject/BackupJob property -- see Section 0 dump)" }
    else {
        foreach ($s in $srcJobs) {
            Emit ("      {0,-38} {1}" -f (Try-Get { $s.Id }), (Try-Get { $s.Name }))
        }
    }
}

Emit ""
$mediaPools = Try-List { Get-VBRTapeMediaPool } 'Get-VBRTapeMediaPool'
Emit "Tape media pools: $($mediaPools.Count)"
foreach ($mp in $mediaPools) {
    Emit ("  {0,-38} {1,-12} {2}" -f (Try-Get { $mp.Id }), (Try-Get { $mp.Type }), (Try-Get { $mp.Name }))
}

Emit ""
$libraries = Try-List { Get-VBRTapeLibrary } 'Get-VBRTapeLibrary'
Emit "Tape libraries: $($libraries.Count)"
foreach ($lib in $libraries) {
    Emit ("  {0,-38} {1}" -f (Try-Get { $lib.Id }), (Try-Get { $lib.Name }))
    Emit ("      model   : " + (Try-Get { $lib.Model }))
    Emit ("      state   : " + (Try-Get { $lib.State }))
}

Emit ""
$drives = Try-List { Get-VBRTapeDrive } 'Get-VBRTapeDrive'
Emit "Tape drives: $($drives.Count)"
foreach ($dr in $drives) {
    Emit ("  {0,-38} {1}" -f (Try-Get { $dr.Id }), (Try-Get { $dr.Name }))
    Emit ("      library : " + (Try-Get { $dr.LibraryId }))
    Emit ("      cleaning: " + (Try-Get { $dr.IsCleaningRequired }))
}

Emit ""
$tapeSrv = Try-List { Get-VBRTapeServer } 'Get-VBRTapeServer'
Emit "Tape servers: $($tapeSrv.Count)"
foreach ($ts in $tapeSrv) {
    Emit ("  {0,-38} {1}" -f (Try-Get { $ts.Id }), (Try-Get { $ts.Name }))
}

# -----------------------------------------------------------------------------
Section "7. MANAGED SERVERS  (hypervisor versions for the platform support check; VMC.log has none)"
# Read-only. Get-VBRBackupServerInfo gives the build and patch level (the patch level is
# not in VMC.log, and some security fixes do not change the build number). Get-VBRServer
# lists managed hosts; ApiVersion is the vSphere API / Hyper-V server version.
$bsi = Try-Get { Get-VBRBackupServerInfo }
Emit ("Backup server build : " + (Try-Get { $bsi.Build }))
Emit ("Backup server patch : " + (Try-Get { $bsi.PatchLevel }))
$servers = Try-List { Get-VBRServer } 'Get-VBRServer'
$hv = @($servers | Where-Object { "$($_.Type)" -match '^(ESXi|VC|HvServer|HvCluster|Scvmm|VcdSystem)$' })
Emit "Virtualization servers: $($hv.Count)"
foreach ($s in $hv) {
    Emit ("  SRV | {0} | {1} | {2} | {3}" -f "$($s.Type)", (Try-Get { $s.ApiVersion }), (Try-Get { $s.Info.Info }), $s.Name)
}

Section "5. JOB NAME <-> JOB ID  (join key: VMC.log has the ID, never the name)"
Emit "JobId,JobName,JobType,IsReplica"
# Includes backup copy jobs ($mapJobs). JobType is always one \w+ token and IsReplica
# always True/False, as the parser's GUID,Name,Type,True|False pattern requires.
foreach ($j in $mapJobs) { Emit ("{0},{1},{2},{3}" -f $j.Id, $j.Name, (Get-TypeToken $j), (Get-ReplicaFlag $j)) }

Emit ""
if ($script:WeConnected) {
    try { Disconnect-VBRServer -ErrorAction SilentlyContinue; Emit "Disconnected the session this script opened." } catch {}
}
Emit "=== capture complete: $OutFile ==="
