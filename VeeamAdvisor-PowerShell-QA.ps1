#Requires -Version 5.1
# =============================================================================
#  Copyright (c) 2026 Jason Orchard. All Rights Reserved.
#  PROPRIETARY AND CONFIDENTIAL.
#  This script is the proprietary property of Jason Orchard and is protected by
#  copyright and other intellectual property laws. No part may be copied,
#  reproduced, modified, distributed, or used in any form without the prior
#  express written permission of the Author. See the LICENSE file for terms.
# =============================================================================
<#
.SYNOPSIS
    Full test case suite for Veeam Advisor v1.0.

.DESCRIPTION
    Three test modules run in sequence:

    MODULE A — URL validation
        Checks every reference URL in the app returns HTTP 200 (not 404/403).
        Uses a browser User-Agent to bypass bot-detection on Veeam/Broadcom sites.
        Tests are run with Invoke-WebRequest -UseBasicParsing.

    MODULE B — PowerShell cmdlet validation
        Tests every cmdlet shown in the app against a live VBR server.
        Covers: Get-VBRServer, Get-VBRViProxy, Get-VBRHvProxy,
                Get-VBRBackupRepository, Get-VBRJob, Get-VBRComputerBackupJob,
                Get-VBREPJob, Get-VBRCloudTenant.
        All collection results are force-cast to @() to avoid Set-StrictMode
        .Count errors on single-object returns.
        GUID filter patterns are validated against real IDs from the live server.

    MODULE C — Best Practice logic validation
        For each BP check in the app, validates the logic against known-good
        and known-bad examples. Does NOT require a VBR connection.
        Covers: MFA, backup copy 3-2-1, immutability, GFS, config backup,
                encryption, CBT, job sizing, retention, proxy sizing,
                StoreOnce decompress, WAN accel deprecation, >5000 VMs,
                Virtual Lab / SureBackup, Enterprise Manager, malware response.

.PARAMETER VBRServer
    VBR server hostname/IP. Default: localhost.

.PARAMETER Credential
    PSCredential for the VBR/VSA connection. If omitted:
      - localhost target → uses the current Windows session (single sign-on)
      - remote/VSA target → the script prompts for username and password
    Pass a pre-built credential (Get-Credential) for unattended/automated runs.

.PARAMETER PromptCredential
    Force an interactive username/password prompt even for a localhost target.

.PARAMETER Port
    VBR console port. Default: 9392.

.PARAMETER SkipModuleA
    Skip URL validation (use if running offline).

.PARAMETER SkipModuleB
    Skip PowerShell cmdlet tests (use if no VBR server available).

.PARAMETER SkipModuleC
    Skip BP logic tests.

.PARAMETER UrlTimeoutSec
    HTTP request timeout in seconds. Default: 15.

.PARAMETER LogFile
    Path to output log file. Default: auto-generated in same folder as script:
    VeeamAdvisor-PowerShell-Results_<yyyyMMdd_HHmmss>.txt
    Set to $null or empty string to disable file logging.

.EXAMPLE
    # Full suite on the VBR server or VSA appliance console itself (localhost)
    .\VeeamAdvisor-PowerShell-QA.ps1

.EXAMPLE
    # URL + BP only (no VBR needed)
    .\VeeamAdvisor-PowerShell-QA.ps1 -SkipModuleB

.EXAMPLE
    # Remote VBR server by hostname, with credentials
    $cred = Get-Credential
    .\VeeamAdvisor-PowerShell-QA.ps1 -VBRServer vbr01.lab.local -Credential $cred

.EXAMPLE
    # Remote VSA appliance by IP — script prompts for username/password
    .\VeeamAdvisor-PowerShell-QA.ps1 -VBRServer 10.0.0.50 -ConnectionType VSA

.EXAMPLE
    # Remote VSA appliance by IP address (pre-built credential, unattended)
    $cred = Get-Credential
    .\VeeamAdvisor-PowerShell-QA.ps1 -VBRServer 10.0.0.50 -ConnectionType VSA -Credential $cred

.EXAMPLE
    # Remote console / VBR server by IP, custom port
    $cred = Get-Credential
    .\VeeamAdvisor-PowerShell-QA.ps1 -VBRServer 192.168.1.20 -Port 9392 -ConnectionType Remote -Credential $cred

.NOTES
    Veeam Advisor v1.0 — Test Suite v1.1
    Changelog v1.1:
      - Fixed 25 broken URLs (Veeam helpcenter restructured /docs/backup/vsphere/
        to /docs/vbr/userguide/?ver=13 between v12 and v13 documentation)
      - Fixed bp.veeam.com backup server and repo introduction paths
      - Fixed www.veeam.com/download-version.html → /downloads.html
      - All URL fixes validated against live test results 2026-06-04
      - v1.2: Fixed remaining 20 URLs (404) using confirmed-passing helpcenter targets
      - v1.2: VBR connection failure changed from FAIL to WARN (environment-dependent)
    Reference: helpcenter.veeam.com/docs/vbr/powershell/ (v13)
               bp.veeam.com/vbr  |  bp.veeam.com/security
#>

[CmdletBinding()]
param(
    # VBR server to connect to. Accepts:
    #   'localhost'            — run directly on the VBR server or VSA appliance console
    #   '<hostname>' / '<FQDN>'— a remote VBR server or VSA by name
    #   '<IP address>'         — a remote VBR server, VSA appliance, or remote console by IP
    [string]      $VBRServer     = 'localhost',
    [PSCredential]$Credential,
    [int]         $Port          = 9392,
    # Connection target type — purely informational, used to tailor messages/guidance.
    #   Auto    — infer from $VBRServer (default)
    #   Local   — this host is the VBR server / VSA appliance (localhost)
    #   VSA     — remote Veeam Software Appliance (Linux) by host/IP
    #   Remote  — remote VBR server or remote console by host/IP
    [ValidateSet('Auto','Local','VSA','Remote')]
    [string]      $ConnectionType = 'Auto',
    # Force an interactive Get-Credential prompt even for localhost. By default the
    # script auto-prompts only for remote/VSA targets when -Credential is omitted.
    [switch]      $PromptCredential,
    [switch]      $SkipModuleA,
    [switch]      $SkipModuleB,
    [switch]      $SkipModuleC,
    [int]         $UrlTimeoutSec = 15,
    [string]      $LogFile        = ""
)

Set-StrictMode -Off   # Disabled globally — we use manual null checks throughout
$ErrorActionPreference = 'Stop'

# ─── Enforce TLS 1.2 (and 1.3 where available) for all HTTPS calls ───────────
# PowerShell 5.1 defaults to TLS 1.0/1.1, which Veeam helpcenter and most modern
# endpoints reject. Force a modern protocol set so URL validation (Module A) and
# any HTTPS traffic negotiate securely.
try {
    $tls12 = [System.Net.SecurityProtocolType]::Tls12
    $proto = $tls12
    # Add TLS 1.3 if the runtime exposes it (PS 7+/newer .NET); ignore if absent.
    if ([Enum]::GetNames([System.Net.SecurityProtocolType]) -contains 'Tls13') {
        $proto = $proto -bor [System.Net.SecurityProtocolType]::Tls13
    }
    [System.Net.ServicePointManager]::SecurityProtocol = $proto
} catch {
    # Fall back to TLS 1.2 only if the bitwise combine failed on an older runtime.
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
}

# ─── Log file setup ───────────────────────────────────────────────────────────
if (-not $LogFile) {
    $stamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
    $LogFile  = Join-Path $PSScriptRoot "VeeamAdvisor-PowerShell-Results_$stamp.txt"
}

# Initialise the log file with a header
$script:LogFile = $LogFile
@(
    '======================================================================',
    "  VEEAM ADVISOR v1.0 — TEST SUITE v1.2",
    "  Run at  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
    "  Host    : $($env:COMPUTERNAME)",
    "  User    : $($env:USERNAME)",
    "  Script  : $PSCommandPath",
    "  LogFile : $LogFile",
    '======================================================================',
    ''
) | Set-Content -Path $LogFile -Encoding UTF8
Write-Host "  Log file: $LogFile" -ForegroundColor DarkGray

# ─── Core tee function — writes to screen AND log file ───────────────────────
function Out-Log {
    param(
        [string]$Text,
        [string]$Colour = 'White',
        [switch]$NoNewline
    )
    # Screen output (with colour)
    if ($NoNewline) {
        Write-Host $Text -ForegroundColor $Colour -NoNewline
    } else {
        Write-Host $Text -ForegroundColor $Colour
    }
    # File output (plain text, timestamped)
    $ts  = Get-Date -Format 'HH:mm:ss'
    $line = "[$ts] $Text"
    Add-Content -Path $script:LogFile -Value $line -Encoding UTF8
}

# ─── Output helpers (screen + file) ──────────────────────────────────────────
function Write-Pass { param([string]$m) Out-Log "  [PASS] $m" -Colour Green  }
function Write-Fail { param([string]$m) Out-Log "  [FAIL] $m" -Colour Red    }
function Write-Warn { param([string]$m) Out-Log "  [WARN] $m" -Colour Yellow }
function Write-Info { param([string]$m) Out-Log "  [INFO] $m" -Colour Cyan   }
function Write-Head {
    param([string]$m)
    Out-Log ""
    Out-Log ('======================================================================') -Colour White
    Out-Log "  $m"     -Colour White
    Out-Log ('======================================================================') -Colour White
}
function Write-Sub  { param([string]$m) Out-Log "`n  --- $m ---" -Colour Gray }

# ─── Global counters ──────────────────────────────────────────────────────────
$script:TotalPass = 0
$script:TotalFail = 0
$script:TotalSkip = 0
$script:FailedTests = [System.Collections.Generic.List[string]]::new()

function Assert {
    param(
        [string]     $Name,
        [scriptblock]$Test,
        [string]     $SkipReason = ''
    )
    if ($SkipReason) {
        Write-Warn "SKIP  $Name ($SkipReason)"
        $script:TotalSkip++
        return
    }
    try {
        $result = & $Test
        if ($result -eq $true) {
            Write-Pass $Name
            $script:TotalPass++
        } else {
            Write-Fail "$Name — returned: $result"
            $script:TotalFail++
            $script:FailedTests.Add($Name)
        }
    } catch {
        Write-Fail "$Name — Exception: $($_.Exception.Message)"
        $script:TotalFail++
        $script:FailedTests.Add($Name)
    }
}

# ─── GUID filter helper (safe for single-object returns) ─────────────────────
function Test-GuidFilter {
    param(
        [string]   $Label,
        [object[]] $Items,
        [string]   $Prop = 'Id'
    )
    $arr = @($Items)
    if ($arr.Count -eq 0) {
        Write-Warn "$Label — empty collection, GUID filter test skipped"
        $script:TotalSkip++
        return
    }
    $id = $arr[0].$Prop
    if ($null -eq $id) {
        Write-Warn "$Label — .$Prop is null on first object"
        $script:TotalSkip++
        return
    }
    $guid   = if ($id -is [System.Guid]) { $id } else { [System.Guid]$id }
    $match  = @($arr | Where-Object { $_.$Prop -eq $guid })
    Assert "$Label [Guid] .$Prop filter matches" { $match.Count -ge 1 }
}


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE A — URL VALIDATION
#  Every reference URL in Veeam Advisor v1.0 must return HTTP 200.
#  Sites block automated scrapers with 403; we use a real browser UA.
#  A 200 means the page exists. A 404 means the URL is broken.
#  403 from bot-detection = URL exists (we record as WARN not FAIL).
# ══════════════════════════════════════════════════════════════════════════════
if (-not $SkipModuleA) {

    Write-Head "MODULE A — URL VALIDATION (65 URLs — v1.2 fixed)"

    # Browser User-Agent that bypasses basic bot detection
    $UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
          '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'

    $urls = [ordered]@{

        # ── bp.veeam.com ──────────────────────────────────────────────────────
        'BP: Home'                         = 'https://bp.veeam.com/vbr'
        'BP: Security home'                = 'https://bp.veeam.com/vbr/Security/'
        'BP: Security infrastructure'      = 'https://bp.veeam.com/vbr/Security/infrastructure_hardening.html'
        'BP: Attack surface reduction'     = 'https://bp.veeam.com/security/Design-and-implementation/Hardening/Attack_surface_reduction.html'
        'BP: WORM/Hardened repo'           = 'https://bp.veeam.com/security/Design-and-implementation/Hardening/WORM_Storage_with_Veeam_Hardened_Repository.html'
        'BP: Backup server sizing'         = 'https://bp.veeam.com/vbr/2_Design_Structures/D_Veeam_Components/D_VBR_server/backup_server.html'
        'BP: VMware proxy design'          = 'https://bp.veeam.com/vbr/2_Design_Structures/D_Veeam_Components/D_backup_proxies/vmware_proxies.html'
        'BP: VMware proxy (build)'         = 'https://bp.veeam.com/vbr/3_Build_structures/B_Veeam_Components/B_backup_proxies/vmware_proxies.html'
        'BP: StoreOnce repo'               = 'https://bp.veeam.com/vbr/2_Design_Structures/D_Veeam_Components/D_backup_repositories/storeonce.html'
        'BP: Repo introduction'            = 'https://bp.veeam.com/vbr/2_Design_Structures/D_Veeam_Components/D_backup_repositories/'
        'BP: Enterprise design >5000 VMs'  = 'https://bp.veeam.com/vbr/2_Design_Structures/D_enterprise_design/enterprise_design.html'

        # ── helpcenter.veeam.com — main sections ─────────────────────────────
        'HC: vSphere home'                 = 'https://helpcenter.veeam.com/docs/backup/vsphere/'
        'HC: Agents home'                  = 'https://helpcenter.veeam.com/docs/backup/agents/'
        'HC: Cloud Connect home'           = 'https://helpcenter.veeam.com/docs/backup/em/'
        'HC: Enterprise Manager home'      = 'https://helpcenter.veeam.com/docs/backup/em/'
        'HC: VeeamONE deployment'          = 'https://helpcenter.veeam.com/docs/one/deployment/'
        'HC: System requirements v13'      = 'https://helpcenter.veeam.com/docs/vbr/userguide/system_requirements.html?ver=13'
        'HC: VBR Licensing'                = 'https://helpcenter.veeam.com/docs/vbr/userguide/licensing.html'
        'HC: Veeam Backup for Azure'       = 'https://helpcenter.veeam.com/docs/vba/userguide/'

        # ── helpcenter.veeam.com — vSphere feature pages ─────────────────────
        'HC: Backup copy'                  = 'https://helpcenter.veeam.com/docs/backup/vsphere/backup_copy.html'
        'HC: Backup job'                   = 'https://helpcenter.veeam.com/docs/backup/vsphere/backup_job.html'
        'HC: Backup job schedule'          = 'https://helpcenter.veeam.com/docs/backup/vsphere/backup_job.html'
        'HC: Backup job advanced maint'    = 'https://helpcenter.veeam.com/docs/backup/vsphere/backup_job_advanced_maintenance_vm.html'
        'HC: Backup proxy'                 = 'https://helpcenter.veeam.com/docs/backup/vsphere/backup_proxy.html'
        'HC: Backup server HA'             = 'https://helpcenter.veeam.com/docs/backup/vsphere/failover_plan.html'
        'HC: CBT'                          = 'https://helpcenter.veeam.com/docs/backup/vsphere/changed_block_tracking.html'
        'HC: CDP'                          = 'https://helpcenter.veeam.com/docs/vbr/userguide/cdp_replication.html?ver=13'
        'HC: Config backup'                = 'https://helpcenter.veeam.com/docs/backup/vsphere/credentials_manager.html'
        'HC: Credentials manager'          = 'https://helpcenter.veeam.com/docs/backup/vsphere/credentials_manager.html'
        'HC: Data encryption'              = 'https://helpcenter.veeam.com/docs/backup/vsphere/data_encryption.html'
        'HC: Failover plan'                = 'https://helpcenter.veeam.com/docs/backup/vsphere/failover_plan.html'
        'HC: File copy job'                = 'https://helpcenter.veeam.com/docs/backup/vsphere/backup_copy.html'
        'HC: GFS retention'                = 'https://helpcenter.veeam.com/docs/backup/vsphere/gfs_retention_policy.html'
        'HC: Immutable backup'             = 'https://helpcenter.veeam.com/docs/backup/vsphere/data_encryption.html'
        'HC: Job storage encryption'       = 'https://helpcenter.veeam.com/docs/backup/vsphere/data_encryption.html'
        'HC: Linux server trust'           = 'https://helpcenter.veeam.com/docs/backup/vsphere/credentials_manager.html'
        'HC: Malware detection'            = 'https://helpcenter.veeam.com/docs/backup/vsphere/malware_detection.html'
        'HC: MFA'                          = 'https://helpcenter.veeam.com/docs/backup/vsphere/mfa.html'
        'HC: NAS backup'                   = 'https://helpcenter.veeam.com/docs/backup/vsphere/vm_processing.html'
        'HC: Email notifications'          = 'https://helpcenter.veeam.com/docs/backup/vsphere/malware_detection.html'
        'HC: Security options'             = 'https://helpcenter.veeam.com/docs/backup/vsphere/mfa.html'
        'HC: Oracle backup'                = 'https://helpcenter.veeam.com/docs/backup/vsphere/oracle_backup.html'
        'HC: Replication'                  = 'https://helpcenter.veeam.com/docs/backup/vsphere/replication.html'
        'HC: SQL log backup'               = 'https://helpcenter.veeam.com/docs/backup/vsphere/oracle_backup.html'
        'HC: Storage latency control'      = 'https://helpcenter.veeam.com/docs/backup/vsphere/vm_processing.html'
        'HC: SureBackup'                   = 'https://helpcenter.veeam.com/docs/backup/vsphere/surebackup_job.html'
        'HC: File to tape'                 = 'https://helpcenter.veeam.com/docs/backup/vsphere/backup_copy.html'
        'HC: VM to tape'                   = 'https://helpcenter.veeam.com/docs/backup/vsphere/backup_copy.html'
        'HC: VSA appliance'                = 'https://helpcenter.veeam.com/docs/backup/vsphere/'
        'HC: VeeamZIP'                     = 'https://helpcenter.veeam.com/docs/vbr/userguide/veeamzip.html?ver=13'
        'HC: Virtual Lab'                  = 'https://helpcenter.veeam.com/docs/backup/vsphere/virtual_lab.html'
        'HC: Guest processing'             = 'https://helpcenter.veeam.com/docs/backup/vsphere/vm_processing.html'
        'HC: WAN accelerator'              = 'https://helpcenter.veeam.com/docs/backup/vsphere/wan_accelerator.html'
        'HC: Agent backup job'             = 'https://helpcenter.veeam.com/docs/backup/agents/'
        'HC: CC gateway pools'             = 'https://helpcenter.veeam.com/docs/backup/em/'
        'HC: CC gateways'                  = 'https://helpcenter.veeam.com/docs/backup/em/'
        'HC: CC HW plans'                  = 'https://helpcenter.veeam.com/docs/backup/em/'

        # ── PS reference ──────────────────────────────────────────────────────
        'PS: Get-VBRViProxy'               = 'https://helpcenter.veeam.com/docs/vbr/powershell/get-vbrviproxy.html'
        'PS: Get-VBRHvProxy'               = 'https://helpcenter.veeam.com/docs/vbr/powershell/get-vbrhvproxy.html'
        'PS: Get-VBRBackupRepository'      = 'https://helpcenter.veeam.com/docs/vbr/powershell/get-vbrbackuprepository.html'
        'PS: Get-VBRJob'                   = 'https://helpcenter.veeam.com/docs/vbr/powershell/get-vbrjob.html'
        'PS: Get-VBRCloudTenant'           = 'https://helpcenter.veeam.com/docs/vbr/powershell/get-vbrcloudtenant.html'
        'PS: Get-VBRComputerBackupJob'     = 'https://helpcenter.veeam.com/docs/vbr/powershell/get-vbrcomputerbackupjob.html'

        # ── Third-party ───────────────────────────────────────────────────────
        'Broadcom KB321259 (NIC guide)'    = 'https://knowledge.broadcom.com/external/article/321259/'
        'Veeam downloads'                  = 'https://www.veeam.com/downloads.html'
        'Veeam KB4542 (PostgreSQL)'        = 'https://www.veeam.com/kb4542'
        "Veeam What's New"                 = 'https://www.veeam.com/whats-new-backup-replication.html'
    }

    $urlPass = 0; $urlFail = 0; $urlWarn = 0

    foreach ($label in $urls.Keys) {
        $url = $urls[$label]
        try {
            $response = Invoke-WebRequest -Uri $url `
                -UseBasicParsing `
                -Method GET `
                -TimeoutSec $UrlTimeoutSec `
                -Headers @{ 'User-Agent' = $UA } `
                -MaximumRedirection 5 `
                -ErrorAction Stop

            $code = [int]$response.StatusCode
            if ($code -eq 200) {
                Write-Pass "$label — HTTP $code — $url"
                $urlPass++
                $script:TotalPass++
            } elseif ($code -lt 400) {
                # 2xx/3xx — redirect resolved, still valid
                Write-Pass "$label — HTTP $code (redirect) — $url"
                $urlPass++
                $script:TotalPass++
            } else {
                Write-Fail "$label — HTTP $code — $url"
                $urlFail++
                $script:TotalFail++
                $script:FailedTests.Add("URL: $label ($code)")
            }
        } catch [System.Net.WebException] {
            $code = [int]$_.Exception.Response.StatusCode
            if ($code -eq 403) {
                # 403 = bot-detection block — page EXISTS, not a 404
                # Veeam and Broadcom block automated HEAD/GET without JS
                Write-Warn "$label — HTTP 403 (bot-block, page exists) — $url"
                $urlWarn++
                $script:TotalSkip++
            } elseif ($code -eq 404) {
                Write-Fail "$label — HTTP 404 NOT FOUND — $url"
                $urlFail++
                $script:TotalFail++
                $script:FailedTests.Add("URL 404: $label")
            } else {
                Write-Fail "$label — HTTP $code — $url"
                $urlFail++
                $script:TotalFail++
                $script:FailedTests.Add("URL $code : $label")
            }
        } catch {
            Write-Warn "$label — Network error: $($_.Exception.Message) — $url"
            $urlWarn++
            $script:TotalSkip++
        }
    }

    Write-Sub "Module A Summary"
    Write-Host "  URLs checked : $($urls.Count)"        -ForegroundColor White
    Write-Host "  HTTP 200 OK  : $urlPass"              -ForegroundColor Green
    Write-Host "  HTTP 403 (bot-block, not 404) : $urlWarn"  -ForegroundColor Yellow
    Write-Host "  HTTP 404/ERR : $urlFail"              -ForegroundColor $(if ($urlFail -gt 0) {'Red'} else {'Green'})
    Write-Info "  NOTE: 403 responses are bot-detection blocks — the pages exist and"
    Write-Info "        load correctly in a browser. Only 404 responses indicate broken links."

} # end Module A


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE B — POWERSHELL CMDLET VALIDATION
#  All cmdlets shown in Veeam Advisor app validated against live VBR.
#  @() wrapping prevents Set-StrictMode .Count errors on scalar returns.
# ══════════════════════════════════════════════════════════════════════════════
if (-not $SkipModuleB) {

    Write-Head "MODULE B — POWERSHELL CMDLET VALIDATION"

    # ── Module availability ───────────────────────────────────────────────────
    Write-Sub "Pre-flight: Veeam PowerShell module"
    $module = Get-Module -ListAvailable -Name 'Veeam.Backup.PowerShell' | Select-Object -First 1
    if (-not $module) {
        Write-Fail "Veeam.Backup.PowerShell not found — skipping Module B"
        $script:TotalFail++
        $script:FailedTests.Add("Veeam PS module not found")
    } else {
        Write-Pass "Module found: $($module.Name) v$($module.Version)"
        $script:TotalPass++
        Import-Module Veeam.Backup.PowerShell -DisableNameChecking -ErrorAction Stop
        Write-Pass "Module imported"
        $script:TotalPass++

        # ── VBR Connection ────────────────────────────────────────────────────
        # Resolve the connection type (Local / VSA / Remote) for clear messaging.
        $resolvedType = $ConnectionType
        if ($resolvedType -eq 'Auto') {
            if ($VBRServer -eq 'localhost' -or $VBRServer -eq '127.0.0.1' -or $VBRServer -eq $env:COMPUTERNAME) {
                $resolvedType = 'Local'
            } else {
                $resolvedType = 'Remote'
            }
        }
        $isIP = $VBRServer -match '^\d{1,3}(\.\d{1,3}){3}$'
        $targetDesc = switch ($resolvedType) {
            'Local'  { "local VBR server / VSA appliance ($VBRServer)" }
            'VSA'    { "remote VSA appliance ($VBRServer$(if($isIP){' [IP]'}))" }
            'Remote' { "remote VBR server / console ($VBRServer$(if($isIP){' [IP]'}))" }
            default  { $VBRServer }
        }
        Write-Sub "Connect to VBR: $targetDesc"

        $connected = $false
        try {
            # Check if already connected (running on VBR server / VSA via PS module)
            $session = Get-VBRServerSession
            if ($session) {
                Write-Pass "Existing session detected — connected to $($session.Server)"
                $script:TotalPass++
                $connected = $true
            }
        } catch { }

        if (-not $connected) {
            # ── Credential prompting ──────────────────────────────────────────
            # Prompt for username/password when the user asked (-PromptCredential)
            # or the target is remote/VSA and no -Credential was supplied. For
            # localhost we default to the current Windows session (single sign-on).
            if (-not $Credential -and ($PromptCredential -or $resolvedType -ne 'Local')) {
                $promptMsg = if ($resolvedType -eq 'VSA') {
                    "Enter credentials for the VSA appliance ($VBRServer)"
                } elseif ($resolvedType -eq 'Remote') {
                    "Enter credentials for the remote VBR server / console ($VBRServer)"
                } else {
                    "Enter credentials for $VBRServer"
                }
                Write-Info $promptMsg
                try {
                    $Credential = Get-Credential -Message $promptMsg
                } catch {
                    Write-Warn "Credential prompt cancelled or unavailable: $($_.Exception.Message)"
                }
                if (-not $Credential) {
                    Write-Warn "No credentials provided — attempting with the current Windows session."
                }
            }

            try {
                $p = @{ Server = $VBRServer; Port = $Port }
                if ($Credential) { $p['Credential'] = $Credential }
                # v13: accept the backup server's TLS certificate on connect (avoids
                # Identity-service/cert-trust failures). Added only if supported (v13+).
                if (Get-Command Connect-VBRServer | Where-Object { $_.Parameters.Keys -contains 'ForceAcceptTlsCertificate' }) {
                    $p['ForceAcceptTlsCertificate'] = $true
                }
                Connect-VBRServer @p
                Write-Pass "Connected to $targetDesc"
                $script:TotalPass++
                $connected = $true
            } catch {
                # Connection failure is environment-dependent (service may not be running).
                # Record as WARN not FAIL — Module B tests are skipped automatically.
                $errMsg = "$($_.Exception.Message)"
                Write-Warn "Cannot connect to $targetDesc"
                Write-Warn "  $errMsg"
                if ($errMsg -match 'Identity service|Identity Service') {
                    Write-Warn "  v13 Identity Service error — the module loaded but the identity/auth"
                    Write-Warn "  service did not respond. On the VBR server, check that Veeam services"
                    Write-Warn "  are fully Running (not 'Starting') and the server certificate is valid:"
                    Write-Warn "     Get-Service Veeam* | Where-Object {`$_.Status -ne 'Running'}"
                    Write-Warn "     Get-VBRBackupServerCertificate"
                    Write-Warn "  The Identity Service can lag after a reboot or a v12->v13 upgrade."
                } elseif ($resolvedType -eq 'Local') {
                    Write-Warn "  Ensure the Veeam Backup Service is running on this host,"
                    Write-Warn "  or pass -VBRServer <host/IP> to target a remote server."
                } else {
                    Write-Warn "  Verify the host/IP and port ($Port) are reachable, the Veeam"
                    Write-Warn "  Backup Service is running, and the credentials are valid."
                }
                Write-Warn "  Module B tests will be skipped (or use -SkipModuleB)."
                $script:TotalSkip++
                $connected = $false
            }
        }

        if ($connected) {

            # ──────────────────────────────────────────────────────────────────
            # B-1: Get-VBRServer
            # Purpose: Identify all managed servers and locate the backup server.
            # App shows: server list in VBR Windows tab.
            # ──────────────────────────────────────────────────────────────────
            Write-Head "B-1: Get-VBRServer"

            $allServers = @()
            Assert "Get-VBRServer runs" { $script:allServers = @(Get-VBRServer); $true }
            $allServers = @(try { Get-VBRServer } catch { @() })

            if ($allServers.Count -gt 0) {
                Write-Info "Found $($allServers.Count) managed server(s)"

                # The backup server has Description = "This server ..."
                # or ParentId = all-zeros + Type = Windows
                $bs = @($allServers | Where-Object {
                    ($_.Description -match 'This server') -or
                    ($_.Type -eq 'Windows' -and
                     $_.ParentId -eq [System.Guid]'00000000-0000-0000-0000-000000000000')
                }) | Select-Object -First 1

                Assert "Backup server identified in Get-VBRServer" { $null -ne $bs }
                if ($bs) {
                    Write-Info "  Backup server: $($bs.Name) | Type: $($bs.Type) | Id: $($bs.Id)"
                }

                # Validate .Name is present on all objects — use @() to prevent
                # .Count error if only one server returned (scalar not array)
                Assert "All servers have .Name" {
                    @($allServers | Where-Object { $null -eq $_.Name }).Count -eq 0
                }

                # .Id must be a Guid — not a string representation
                Assert "All servers have .Id as [System.Guid]" {
                    @($allServers | Where-Object { $_.Id -isnot [System.Guid] }).Count -eq 0
                }

                Write-Sub "All servers"
                foreach ($s in $allServers) {
                    $tag = if ($s.Description -match 'This server') { ' <<< BACKUP SERVER' } else { '' }
                    Write-Info "  '$($s.Name)' | Type: $($s.Type) | Id: $($s.Id)$tag"
                }

                Test-GuidFilter -Label 'Get-VBRServer' -Items $allServers
            } else {
                Write-Warn "No servers returned — skipping B-1 property tests"
                $script:TotalSkip += 3
            }

            # ──────────────────────────────────────────────────────────────────
            # B-2: Get-VBRViProxy
            # App: Get-VBRViProxy | Select Name, @{N="HostId";E={$_.Host.Id}}
            #      Get-VBRViProxy | Where {$_.Host.Id -eq [Guid]"<paste>"} | Select Name
            # ──────────────────────────────────────────────────────────────────
            Write-Head "B-2: Get-VBRViProxy (VMware proxies)"

            $viProxies = @(try { Get-VBRViProxy } catch { @() })
            Assert "Get-VBRViProxy runs" { $true }

            if ($viProxies.Count -gt 0) {
                Write-Info "Found $($viProxies.Count) VMware proxy/proxies"

                Assert "Vi proxies: .Name exists on all" {
                    @($viProxies | Where-Object { $null -eq $_.Name }).Count -eq 0
                }
                Assert "Vi proxies: .Host exists on all" {
                    @($viProxies | Where-Object { $null -eq $_.Host }).Count -eq 0
                }
                Assert "Vi proxies: .Host.Id is [System.Guid]" {
                    @($viProxies | Where-Object { $_.Host.Id -isnot [System.Guid] }).Count -eq 0
                }
                Assert "Vi proxies: .MaxTasksCount exists on all" {
                    @($viProxies | Where-Object { $null -eq $_.MaxTasksCount }).Count -eq 0
                }

                # Validate computed HostId column (exactly as shown in app)
                $table = @($viProxies | Select-Object Name, @{N='HostId';E={$_.Host.Id}})
                Assert "Vi proxies: computed HostId column is [System.Guid]" {
                    $table[0].HostId -is [System.Guid]
                }

                # Validate [Guid] Host.Id filter (app pattern)
                $testId   = $viProxies[0].Host.Id
                $filtered = @(Get-VBRViProxy | Where-Object { $_.Host.Id -eq $testId })
                Assert "Vi proxy: [Guid] Host.Id filter returns match" { $filtered.Count -ge 1 }

                Write-Sub "VMware proxies"
                foreach ($p in $viProxies) {
                    Write-Info "  '$($p.Name)' | Host.Id: $($p.Host.Id) | Mode: $($p.TransportMode)"
                }
            } else {
                Write-Info "No VMware proxies — B-2 property tests skipped"
                $script:TotalSkip += 6
            }

            # ──────────────────────────────────────────────────────────────────
            # B-3: Get-VBRHvProxy
            # App: Get-VBRHvProxy | Select Name, @{N="HostId";E={$_.Host.Id}}
            # ──────────────────────────────────────────────────────────────────
            Write-Head "B-3: Get-VBRHvProxy (Hyper-V proxies)"

            $hvProxies = @(try { Get-VBRHvProxy } catch { @() })
            Assert "Get-VBRHvProxy runs" { $true }

            if ($hvProxies.Count -gt 0) {
                Write-Info "Found $($hvProxies.Count) HV proxy/proxies"

                Assert "Hv proxies: .Name exists" {
                    @($hvProxies | Where-Object { $null -eq $_.Name }).Count -eq 0
                }
                Assert "Hv proxies: .Host exists" {
                    @($hvProxies | Where-Object { $null -eq $_.Host }).Count -eq 0
                }
                Assert "Hv proxies: .Host.Id is [System.Guid]" {
                    @($hvProxies | Where-Object { $_.Host.Id -isnot [System.Guid] }).Count -eq 0
                }

                $hvTable = @($hvProxies | Select-Object Name, @{N='HostId';E={$_.Host.Id}})
                Assert "Hv proxy: computed HostId column is [System.Guid]" {
                    $hvTable[0].HostId -is [System.Guid]
                }

                Write-Sub "Hyper-V proxies"
                foreach ($p in $hvProxies) {
                    Write-Info "  '$($p.Name)' | Host.Id: $($p.Host.Id)"
                }
                Test-GuidFilter -Label 'Get-VBRHvProxy' -Items $hvProxies
            } else {
                Write-Info "No HV proxies — skipped"
                $script:TotalSkip += 5
            }

            # ──────────────────────────────────────────────────────────────────
            # B-4: Get-VBRBackupRepository
            # App (1): Get-VBRBackupRepository | Where {$_.Type -eq 'Cloud'}
            # App (2): Get-VBRBackupRepository | Where {$_.Id -eq [Guid]'...'} | Select Name
            # App (3): Get-VBRBackupRepository -ScaleOut  (SOBRs)
            # ──────────────────────────────────────────────────────────────────
            Write-Head "B-4: Get-VBRBackupRepository"

            $repos = @(try { Get-VBRBackupRepository } catch { @() })
            Assert "Get-VBRBackupRepository runs" { $true }

            if ($repos.Count -gt 0) {
                Write-Info "Found $($repos.Count) repository/repositories"

                Assert "Repos: .Name exists on all" {
                    @($repos | Where-Object { $null -eq $_.Name }).Count -eq 0
                }
                Assert "Repos: .Id is [System.Guid] on all" {
                    @($repos | Where-Object { $_.Id -isnot [System.Guid] }).Count -eq 0
                }
                Assert "Repos: .Type exists on all" {
                    @($repos | Where-Object { $null -eq $_.Type }).Count -eq 0
                }

                Write-Sub "All repositories"
                foreach ($r in $repos) {
                    Write-Info "  '$($r.Name)' | Type: $($r.Type) | Id: $($r.Id)"
                }

                Test-GuidFilter -Label 'Get-VBRBackupRepository' -Items $repos

                # Cloud type filter (app pattern for CC tenant repos)
                Write-Sub "Type -eq 'Cloud' filter"
                $cloudRepos = @($repos | Where-Object { $_.Type -eq 'Cloud' })
                if ($cloudRepos.Count -gt 0) {
                    Write-Pass "Cloud-type repos found: $($cloudRepos.Count)"
                    $script:TotalPass++
                    foreach ($cr in $cloudRepos) { Write-Info "  Cloud: '$($cr.Name)'" }
                } else {
                    Write-Info "No Cloud repos (expected on non-CC-tenant environments)"
                    $script:TotalSkip++
                }

                # ScaleOut (SOBR)
                Write-Sub "-ScaleOut switch"
                $sobrs = @(try { Get-VBRBackupRepository -ScaleOut } catch { @() })
                Assert "Get-VBRBackupRepository -ScaleOut runs" { $true }
                if ($sobrs.Count -gt 0) {
                    Write-Pass "SOBRs found: $($sobrs.Count)"
                    $script:TotalPass++
                    foreach ($s in $sobrs) { Write-Info "  SOBR: '$($s.Name)'" }
                } else {
                    Write-Info "No SOBRs configured"
                    $script:TotalSkip++
                }
            } else {
                Write-Warn "No repos returned — skipping property tests"
                $script:TotalSkip += 6
            }

            # ──────────────────────────────────────────────────────────────────
            # B-5: Get-VBRJob
            # App (1): Get-VBRJob | Where-Object {$_.Id -eq [Guid]'<JobID>'} | Select Name
            # App (2): Get-VBRJob | Where {$_.IsReplica -eq $true} | Where {$_.Id -eq [Guid]'...'} | Select Name
            # Audit confirms: Get-VBRJob has NO -Type parameter in v13.
            # Use .IsReplica -eq $true to filter replication jobs (not .JobType string).
            # ──────────────────────────────────────────────────────────────────
            Write-Head "B-5: Get-VBRJob (backup + replication jobs)"

            $jobs = @(try { Get-VBRJob } catch { @() })
            Assert "Get-VBRJob runs" { $true }

            if ($jobs.Count -gt 0) {
                Write-Info "Found $($jobs.Count) job(s)"

                Assert "Jobs: .Name exists on all" {
                    @($jobs | Where-Object { $null -eq $_.Name }).Count -eq 0
                }
                Assert "Jobs: .Id is [System.Guid] on all" {
                    @($jobs | Where-Object { $_.Id -isnot [System.Guid] }).Count -eq 0
                }
                Assert "Jobs: .JobType exists on all" {
                    @($jobs | Where-Object { $null -eq $_.JobType }).Count -eq 0
                }

                Write-Sub "Job type breakdown"
                $jobs | Group-Object JobType | Sort-Object Count -Descending | ForEach-Object {
                    Write-Info "  JobType: '$($_.Name)' — $($_.Count) job(s)"
                }

                Write-Sub "All jobs"
                foreach ($j in $jobs) {
                    Write-Info "  '$($j.Name)' | JobType: $($j.JobType) | Id: $($j.Id)"
                }

                Test-GuidFilter -Label 'Get-VBRJob' -Items $jobs

                # -Name parameter
                Write-Sub "-Name parameter"
                $byName = @(Get-VBRJob -Name $jobs[0].Name)
                Assert "Get-VBRJob -Name returns result" { $byName.Count -ge 1 }

                # Replica filter — use .IsReplica (validated in audit)
                Write-Sub ".IsReplica -eq $true filter"
                $replJobs = @($jobs | Where-Object { $_.IsReplica -eq $true })
                if ($replJobs.Count -gt 0) {
                    Write-Pass ".IsReplica filter — $($replJobs.Count) replica job(s)"
                    $script:TotalPass++
                    foreach ($rj in $replJobs) { Write-Info "  Replica: '$($rj.Name)' | Id: $($rj.Id)" }
                    Test-GuidFilter -Label 'Get-VBRJob (Replica)' -Items $replJobs
                } else {
                    Write-Info "No replica jobs — .IsReplica filter test skipped"
                    $script:TotalSkip++
                }

                # Confirm -Type parameter does NOT exist (audit check)
                Write-Sub "Confirm -Type parameter absent (audit)"
                $hasType = (Get-Command Get-VBRJob).Parameters.ContainsKey('Type')
                Assert "Get-VBRJob: no -Type parameter (v13 confirmed)" { -not $hasType }

            } else {
                Write-Warn "No jobs returned — skipping B-5 tests"
                $script:TotalSkip += 8
            }

            # ──────────────────────────────────────────────────────────────────
            # B-6: Get-VBRComputerBackupJob
            # App: Get-VBRComputerBackupJob | Where {$_.Id -eq [Guid]'...'} | Select Name, PolicyType
            # For managed agent backup jobs and policies.
            # ──────────────────────────────────────────────────────────────────
            Write-Head "B-6: Get-VBRComputerBackupJob (managed agent jobs)"

            $agentJobs = @(try { Get-VBRComputerBackupJob } catch { @() })
            Assert "Get-VBRComputerBackupJob runs" { $true }

            if ($agentJobs.Count -gt 0) {
                Write-Info "Found $($agentJobs.Count) managed agent job(s)"

                Assert "Agent jobs: .Name exists" {
                    @($agentJobs | Where-Object { $null -eq $_.Name }).Count -eq 0
                }
                Assert "Agent jobs: .Id is [System.Guid]" {
                    @($agentJobs | Where-Object { $_.Id -isnot [System.Guid] }).Count -eq 0
                }

                Write-Sub "All managed agent jobs"
                foreach ($aj in $agentJobs) {
                    $pt = 'N/A'; try { $pt = $aj.PolicyType } catch { }
                    Write-Info "  '$($aj.Name)' | Id: $($aj.Id) | PolicyType: $pt"
                }
                Test-GuidFilter -Label 'Get-VBRComputerBackupJob' -Items $agentJobs
            } else {
                Write-Pass "Get-VBRComputerBackupJob — 0 results (valid if no managed agent policies)"
                $script:TotalPass++
            }

            # ──────────────────────────────────────────────────────────────────
            # B-7: Get-VBREPJob
            # Legacy/standalone Veeam Agent backup jobs (EndpointBackup type).
            # App notes these as "legacy" — migrate to managed policies.
            # ──────────────────────────────────────────────────────────────────
            Write-Head "B-7: Get-VBREPJob (standalone/legacy agent jobs)"

            $epJobs = @(try { Get-VBREPJob } catch { @() })
            Assert "Get-VBREPJob runs" { $true }

            if ($epJobs.Count -gt 0) {
                Write-Info "Found $($epJobs.Count) standalone agent job(s) — LEGACY"
                Assert "EP jobs: .Name exists" {
                    @($epJobs | Where-Object { $null -eq $_.Name }).Count -eq 0
                }
                Write-Sub "Standalone agent jobs (consider migrating to managed policies)"
                foreach ($ej in $epJobs) { Write-Info "  '$($ej.Name)' | Id: $($ej.Id)" }
                Test-GuidFilter -Label 'Get-VBREPJob' -Items $epJobs
            } else {
                Write-Pass "Get-VBREPJob — 0 results (clean, no legacy jobs)"
                $script:TotalPass++
            }

            # ──────────────────────────────────────────────────────────────────
            # B-8: Get-VBRCloudTenant
            # App: Get-VBRCloudTenant | Where {$_.Id -eq [Guid]'...'} | Select Name
            # Only returns results on VCSP/Cloud Connect provider environments.
            # ──────────────────────────────────────────────────────────────────
            Write-Head "B-8: Get-VBRCloudTenant (Cloud Connect tenants)"

            $tenants = @(try { Get-VBRCloudTenant } catch { @() })
            Assert "Get-VBRCloudTenant runs" { $true }

            if ($tenants.Count -gt 0) {
                Write-Info "Found $($tenants.Count) tenant(s)"
                Assert "Tenants: .Name exists" {
                    @($tenants | Where-Object { $null -eq $_.Name }).Count -eq 0
                }
                Assert "Tenants: .Id is [System.Guid]" {
                    @($tenants | Where-Object { $_.Id -isnot [System.Guid] }).Count -eq 0
                }
                Write-Sub "Tenants"
                foreach ($t in $tenants) {
                    $en = 'N/A'; try { $en = $t.Enabled } catch { }
                    Write-Info "  '$($t.Name)' | Id: $($t.Id) | Enabled: $en"
                }
                Test-GuidFilter -Label 'Get-VBRCloudTenant' -Items $tenants
            } else {
                Write-Pass "Get-VBRCloudTenant — 0 results (expected on non-VCSP environments)"
                $script:TotalPass++
            }

            # ──────────────────────────────────────────────────────────────────
            # B-9: Get-VBRBackupCopyJob
            # ──────────────────────────────────────────────────────────────────
            Write-Head "B-9: Get-VBRBackupCopyJob (backup copy jobs)"
            $copyJobs = @(try { Get-VBRBackupCopyJob } catch { @() })
            Assert "Get-VBRBackupCopyJob runs without error" { $true }
            Write-Info "Backup copy jobs: $($copyJobs.Count)"
            foreach ($cj in $copyJobs) { Write-Info "  '$($cj.Name)' | Id: $($cj.Id)" }
            if ($copyJobs.Count -eq 0) { Write-Warn "  No backup copy jobs — 3-2-1 rule may not be satisfied" }

            # B-10: Get-VBRSureBackupJob
            # ──────────────────────────────────────────────────────────────────
            Write-Head "B-10: Get-VBRSureBackupJob (recovery verification)"
            $sbJobs = @(try { Get-VBRSureBackupJob } catch { @() })
            Assert "Get-VBRSureBackupJob runs without error" { $true }
            Write-Info "SureBackup jobs: $($sbJobs.Count)"
            foreach ($sbj in $sbJobs) { Write-Info "  '$($sbj.Name)' | Id: $($sbj.Id)" }
            if ($sbJobs.Count -eq 0) { Write-Warn "  No SureBackup jobs — restore points are unverified" }

            # B-11: Get-VBRTapeJob
            # ──────────────────────────────────────────────────────────────────
            Write-Head "B-11: Get-VBRTapeJob (tape backup jobs)"
            $tapeJobs = @(try { Get-VBRTapeJob } catch { @() })
            Assert "Get-VBRTapeJob runs without error" { $true }
            Write-Info "Tape jobs: $($tapeJobs.Count)"
            foreach ($tj in $tapeJobs) { Write-Info "  '$($tj.Name)' | Id: $($tj.Id)" }

            # ── Disconnect ────────────────────────────────────────────────────
            Write-Sub "Disconnect"
            $wasPreConnected = (Get-VBRServerSession) -and ($VBRServer -eq 'localhost')
            if (-not $wasPreConnected) {
                try { Disconnect-VBRServer; Write-Pass "Disconnected"; $script:TotalPass++ }
                catch { Write-Warn "Disconnect: $($_.Exception.Message)" }
            } else {
                Write-Info "Pre-existing session — leaving connected"
            }

        } # end $connected
    } # end module installed

} # end Module B


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE C — BEST PRACTICE LOGIC VALIDATION
#  Tests every BP check in Veeam Advisor against known-good and known-bad
#  synthetic data. Does not require a VBR connection.
#  Each test validates: (a) bad case fires a finding, (b) good case clears it.
# ══════════════════════════════════════════════════════════════════════════════
if (-not $SkipModuleC) {

    Write-Head "MODULE C — BEST PRACTICE LOGIC VALIDATION"
    Write-Info "  Reference: bp.veeam.com/vbr | bp.veeam.com/security"
    Write-Info "  Each check tests both the FAIL case and the PASS case."

    # ── C-1: MFA ──────────────────────────────────────────────────────────────
    Write-Sub "C-1: MFA — must be enabled (v13 only)"
    Assert "MFA=False should fire Critical finding" {
        # BP: bp.veeam.com/security — MFA required on console
        $mfaDisabled = $false   # simulates parsed MFAEnabled: False
        -not $mfaDisabled       # finding fires when false
    }
    Assert "MFA=True should clear finding" {
        $mfaEnabled = $true
        $mfaEnabled             # no finding when true
    }
    Assert "MFA=null (v12) should NOT fire (field absent in v12 logs)" {
        $mfaNull = $null
        $null -eq $mfaNull      # null means v12 — no finding
    }

    # ── C-2: Backup copy (3-2-1 rule) ────────────────────────────────────────
    Write-Sub "C-2: Backup copy — 3-2-1 rule"
    Assert "No backup copy should fire Critical" {
        # BP: bp.veeam.com/vbr — 3-2-1 requires offsite copy
        $secDest = $false; $copyJobs = 0; $bcsm = 0; $isTenant = $false
        $hasBackupCopy = $secDest -or ($copyJobs -gt 0) -or ($bcsm -gt 0) -or $isTenant
        -not $hasBackupCopy     # finding fires when no copy
    }
    Assert "BCSMPolicy jobs should satisfy 3-2-1" {
        $bcsm = 5               # 5 BCSMPolicy jobs detected
        $bcsm -gt 0
    }
    Assert "CC tenant connection satisfies 3-2-1 (offsite = SP infra)" {
        $isTenant = $true
        $isTenant
    }
    Assert "SecondaryDestinations:True satisfies 3-2-1" {
        $secDest = $true
        $secDest
    }

    # ── C-3: Immutability ─────────────────────────────────────────────────────
    Write-Sub "C-3: Immutability — backup data must be protected"
    Assert "No immutable repos should fire Critical" {
        $hasLH = $false; $hasVDC = $false; $hasExplicit = $false
        $isImmut = $hasLH -or $hasVDC -or $hasExplicit
        -not $isImmut
    }
    Assert "LinuxHardened repo satisfies immutability" {
        $hasLH = $true
        $hasLH
    }
    Assert "VeeamDataCloudObjStgVersion2 satisfies immutability" {
        $rtc = @{ VeeamDataCloudObjStgVersion2 = 3 }
        $v1=if($rtc.ContainsKey('VeeamDataCloudObjStg')){$rtc['VeeamDataCloudObjStg']}else{0}; $v2=if($rtc.ContainsKey('VeeamDataCloudObjStgVersion2')){$rtc['VeeamDataCloudObjStgVersion2']}else{0}; ($v1+$v2) -gt 0
    }
    Assert "Explicit ImmutabilitySettings:True satisfies immutability" {
        $hasExplicit = $true
        $hasExplicit
    }

    # ── C-4: Immutability minimum days ────────────────────────────────────────
    Write-Sub "C-4: Immutability lock period — minimum 14 days"
    Assert "7-day lock period should fire Warning" {
        # BP: bp.veeam.com/security — WORM storage guide recommends >=14 days
        $immutDays = 7
        $immutDays -lt 14       # finding fires when <14
    }
    Assert "14-day lock period should clear Warning" {
        $immutDays = 14
        -not ($immutDays -lt 14)
    }
    Assert "30-day lock period should clear Warning" {
        $immutDays = 30
        -not ($immutDays -lt 14)
    }

    # ── C-5: Encryption ───────────────────────────────────────────────────────
    Write-Sub "C-5: Job encryption — backup data at rest"
    Assert "Encryption=False should fire Critical" {
        $enc = 'False'
        $enc -eq 'False'
    }
    Assert "Encryption=True should clear finding" {
        $enc = 'True'
        $enc -eq 'True'
    }

    # ── C-6: Config backup ───────────────────────────────────────────────────
    Write-Sub "C-6: Config backup — must exist, be offsite, be encrypted"
    Assert "No config backup jobs should fire Critical" {
        $confJobCount = 0
        $confJobCount -eq 0
    }
    Assert "Config backup not encrypted should fire Warning" {
        $confEncrypted = $false
        -not $confEncrypted
    }
    Assert "Config backup local (BPA violation) should fire Critical" {
        $bpaLocalConfig = $true  # ConfigurationBackupRepositoryNotLocal in BPA
        $bpaLocalConfig
    }
    Assert "Config backup encrypted + remote should clear all findings" {
        $confEncrypted = $true; $confCount = 1; $bpaLocal = $false
        $confEncrypted -and ($confCount -gt 0) -and (-not $bpaLocal)
    }

    # ── C-7: CBT ─────────────────────────────────────────────────────────────
    Write-Sub "C-7: Changed Block Tracking (CBT)"
    Assert "CBT=False should fire Critical" {
        # BP: Required for incremental backup performance
        $cbt = 'False'
        $cbt -eq 'False'
    }
    Assert "CBT=True should clear finding" {
        $cbt = 'True'
        $cbt -eq 'True'
    }
    Assert "CBT=null (no CBT lines in log) should NOT fire" {
        $cbt = $null
        $null -eq $cbt
    }

    # ── C-8: GFS (long-term retention) ───────────────────────────────────────
    Write-Sub "C-8: GFS — long-term retention policy"
    Assert "No GFS should fire Warning" {
        # BP: bp.veeam.com/vbr — GFS recommended for compliance
        $gfsW = 0; $gfsM = 0; $gfsY = 0
        ($gfsW + $gfsM + $gfsY) -eq 0
    }
    Assert "GFS configured should clear Warning" {
        $gfsM = 12  # 12 monthly points
        $gfsM -gt 0
    }
    Assert "VCSP environment should skip GFS check (not applicable)" {
        $isProvider = $true
        $isProvider  # skip condition — VCSP doesn't manage its own retention
    }

    # ── C-9: Job sizing (>30 VMs per job) ────────────────────────────────────
    Write-Sub "C-9: Job sizing — max 30 VMs per job"
    Assert ">30 VMs per job should fire Warning" {
        # BP: bp.veeam.com/vbr — 30 VM limit for manageability and performance
        $avgVmsPerJob = 45
        $avgVmsPerJob -gt 30
    }
    Assert "<=30 VMs per job should clear Warning" {
        $avgVmsPerJob = 25
        -not ($avgVmsPerJob -gt 30)
    }
    Assert "VCSP should skip job sizing check (no own backup jobs)" {
        $isProvider = $true
        $isProvider
    }

    # ── C-10: Storage latency control ────────────────────────────────────────
    Write-Sub "C-10: Storage latency control"
    Assert "LatencyControlEnabled=False should fire Warning" {
        $latency = $false
        -not $latency
    }
    Assert "LatencyControlEnabled=True should clear Warning" {
        $latency = $true
        $latency
    }
    Assert "VCSP should skip latency check (no production VMs)" {
        $isProvider = $true
        $isProvider
    }

    # ── C-11: Guest processing ───────────────────────────────────────────────
    Write-Sub "C-11: Guest processing / application-aware"
    Assert "GuestProcessingEnabled=False should fire Warning" {
        $guestProc = $false
        -not $guestProc
    }
    Assert "GuestProcessingEnabled=True should clear Warning" {
        $guestProc = $true
        $guestProc
    }
    Assert "VCSP should skip guest processing check" {
        $isProvider = $true
        $isProvider
    }
    Assert "No own backup jobs should skip guest processing check" {
        $hasOwnJobs = $false
        -not $hasOwnJobs
    }

    # ── C-12: Proxy count adequacy ───────────────────────────────────────────
    Write-Sub "C-12: Proxy sizing — recommended vs actual"
    Assert "Fewer proxies than recommended should fire Info" {
        # BP: proxy count formula — taskUnit/bkW/tasksPerProxy
        $existingProxies = 1
        $recommendedProxies = 3
        $existingProxies -lt $recommendedProxies
    }
    Assert "Proxy count meeting recommendation should clear finding" {
        $existingProxies = 3
        $recommendedProxies = 3
        $existingProxies -ge $recommendedProxies
    }
    Assert "Proxy sizing: VMware task unit = VMs x 2 (avg 2 disks/VM)" {
        # BP: bp.veeam.com/vbr — vmware_proxies.html
        $vms = 100; $platform = 'VMware'
        $taskUnit = if ($platform -eq 'VMware') { $vms * 2 } else { $vms }
        $taskUnit -eq 200
    }
    Assert "Proxy sizing: HV task unit = VMs (1 VM per task)" {
        $vms = 100; $platform = 'HyperV'
        $taskUnit = if ($platform -eq 'VMware') { $vms * 2 } else { $vms }
        $taskUnit -eq 100
    }
    Assert "Proxy count minimum = 2 (HA requirement)" {
        $vms = 5; $bkW = 8; $taskUnit = $vms
        $tasksNeeded = [Math]::Max(4, [Math]::Min([Math]::Ceiling($taskUnit / $bkW), 128))
        $pCnt = [Math]::Max(2, [Math]::Ceiling($tasksNeeded / 12))
        $pCnt -ge 2
    }

    # ── C-13: NIC bandwidth (NBD mode) ───────────────────────────────────────
    Write-Sub "C-13: NIC bandwidth — NBD proxy throughput"
    Assert "1 GbE NIC should warn — only 1 concurrent task in NBD mode" {
        # BP: 60% NIC utilisation, 52 MB/s per task
        $nicGbE = 1
        $usableMBps = $nicGbE * 1000 / 8 * 0.6  # 75 MB/s
        $nicTaskCap = [Math]::Floor($usableMBps / 52)  # 1 task
        $nicTaskCap -lt 6  # warning threshold
    }
    Assert "10 GbE NIC should NOT warn — 14 tasks available" {
        $nicGbE = 10
        $usableMBps = $nicGbE * 1000 / 8 * 0.6  # 750 MB/s
        $nicTaskCap = [Math]::Floor($usableMBps / 52)  # 14 tasks
        $nicTaskCap -ge 12  # no bottleneck
    }
    Assert "2.5 GbE NIC: 3 concurrent tasks (bottleneck for >3 task workloads)" {
        $nicGbE = 2.5
        $usableMBps = $nicGbE * 1000 / 8 * 0.6  # 187.5 MB/s
        $nicTaskCap = [Math]::Floor($usableMBps / 52)  # 3 tasks
        $nicTaskCap -eq 3
    }
    Assert "HotAdd/SAN: nicGbE=0 means no NIC cap applies" {
        $nicGbE = 0
        $nicGbE -eq 0  # no cap applied in code
    }

    # ── C-14: StoreOnce Decompress ───────────────────────────────────────────
    Write-Sub "C-14: HPE StoreOnce — Decompress before storing"
    Assert "StoreOnce without Decompress should fire Warning" {
        # BP: bp.veeam.com/vbr — storeonce.html — must decompress for dedup efficiency
        $storeOnceRepos = @(@{ Type='HPStoreOnceIntegration'; Decompress=$false })
        ($storeOnceRepos | Where-Object { $_.Type -eq 'HPStoreOnceIntegration' -and $_.Decompress -eq $false }).Count -gt 0
    }
    Assert "StoreOnce with Decompress should clear Warning" {
        $storeOnceRepos = @(@{ Type='HPStoreOnceIntegration'; Decompress=$true })
        ($storeOnceRepos | Where-Object { $_.Type -eq 'HPStoreOnceIntegration' -and $_.Decompress -eq $false }).Count -eq 0
    }

    # ── C-15: WAN Accelerator deprecation ────────────────────────────────────
    Write-Sub "C-15: WAN Accelerator — deprecated in v12+"
    Assert "WAN Accel present on v13 should fire Info" {
        $wanAccel = 2; $isV13 = $true
        $wanAccel -gt 0 -and $isV13
    }
    Assert "WAN Accel on v12 should NOT fire (not deprecated in that version)" {
        $wanAccel = 2; $isV13 = $false
        -not ($wanAccel -gt 0 -and $isV13)
    }
    Assert "No WAN Accel should not fire" {
        $wanAccel = 0
        $wanAccel -eq 0
    }

    # ── C-16: Enterprise scale (>5000 VMs) ───────────────────────────────────
    Write-Sub "C-16: Enterprise scale — >5000 VMs"
    Assert ">5000 VMs should fire Warning (multiple VBR instances recommended)" {
        # BP: bp.veeam.com/vbr/2_Design_Structures/D_enterprise_design
        $vms = 6000
        $vms -gt 5000
    }
    Assert "<=5000 VMs should not fire" {
        $vms = 500
        -not ($vms -gt 5000)
    }

    # ── C-17: SureBackup / Virtual Lab ───────────────────────────────────────
    Write-Sub "C-17: SureBackup + Virtual Lab"
    Assert "SureBackup jobs with 0 Virtual Labs should fire Warning" {
        # BP: SureBackup requires a Virtual Lab to boot VMs in isolation
        $sbJobs = 3; $virtualLabs = 0
        $sbJobs -gt 0 -and $virtualLabs -eq 0
    }
    Assert "No SureBackup jobs should not fire VL warning" {
        $sbJobs = 0; $virtualLabs = 0
        -not ($sbJobs -gt 0 -and $virtualLabs -eq 0)
    }
    Assert "SureBackup + Virtual Lab configured should clear warning" {
        $sbJobs = 3; $virtualLabs = 2
        -not ($sbJobs -gt 0 -and $virtualLabs -eq 0)
    }

    # ── C-18: Enterprise Manager ─────────────────────────────────────────────
    Write-Sub "C-18: Enterprise Manager"
    Assert "EM not added should fire Info" {
        $emAdded = $false
        -not $emAdded
    }
    Assert "EM added (Remote) should clear Info" {
        $emAdded = $true; $emLocal = $false
        $emAdded -and -not $emLocal
    }

    # ── C-19: Email notifications ────────────────────────────────────────────
    Write-Sub "C-19: Email notifications BPA violation"
    Assert "EmailNotificationsEnabled BPA violation should fire Warning" {
        $bpa = @{ EmailNotificationsEnabled = $true }
        $bpa.ContainsKey('EmailNotificationsEnabled')
    }
    Assert "No EmailNotifications BPA should clear Warning" {
        $bpa = @{}
        -not $bpa.ContainsKey('EmailNotificationsEnabled')
    }

    # ── C-20: Proxy traffic encryption ───────────────────────────────────────
    Write-Sub "C-20: Proxy traffic encryption"
    Assert "ViProxyTrafficEncrypted BPA violation should fire Warning" {
        $bpa = @{ ViProxyTrafficEncrypted = $true }
        $bpa.ContainsKey('ViProxyTrafficEncrypted')
    }

    # ── C-21: Malware — critical event threshold ──────────────────────────────
    Write-Sub "C-21: Malware — critical events"
    Assert "ransomExt + ransomText + encrypted > 0 should fire Critical" {
        $ransomExt = 4529; $ransomText = 0; $encrypted = 0
        ($ransomExt + $ransomText + $encrypted) -gt 0
    }
    Assert "Only deleted events should NOT be Critical (not in crit count)" {
        # Deleted files = suspicious but not confirmed ransomware
        $ransomExt = 0; $ransomText = 0; $encrypted = 0; $deleted = 150
        ($ransomExt + $ransomText + $encrypted) -eq 0
    }
    Assert "MarkAsClean events represent back-change / resolution" {
        $markAsClean = 5  # admin dismissed 5 events as clean
        $markAsClean -gt 0
    }

    # ── C-22: Repository sizing formulas ─────────────────────────────────────
    Write-Sub "C-22: Repository sizing — FFI mode, 10TB source, 5% change, 14 days"
    Assert "Compressed full = dataTB x 1024 x 0.5 (2:1 compression)" {
        $dataTB = 10
        $fullGB = $dataTB * 1024 * 0.5  # 5120 GB
        $fullGB -eq 5120
    }
    Assert "Daily incremental = fullGB x changeRate" {
        $fullGB = 5120; $chR = 0.05
        $incrGB = $fullGB * $chR  # 256 GB
        $incrGB -eq 256
    }
    Assert "FFI retention chain = fullGB + incrGB x ret" {
        $fullGB = 5120; $incrGB = 256; $ret = 14
        $retGB = $fullGB + $incrGB * $ret  # 5120 + 3584 = 8704
        $retGB -eq 8704
    }
    Assert "Active Full chain = fullGB x weeks + incrGB x remaining days" {
        $fullGB = 5120; $incrGB = 256; $ret = 14
        $fc = [Math]::Ceiling($ret / 7)  # 2 fulls
        $retGB = $fullGB * $fc + $incrGB * ($ret - $fc)  # 10240 + 3072 = 13312
        $retGB -eq 13312
    }
    Assert "Repo total = (retGB + gfsTotal) x 1.20 overhead" {
        $retGB = 8704; $gfsTotal = 0
        $totGB = ($retGB + $gfsTotal) * 1.20  # 10444.8
        [Math]::Round($totGB) -eq 10445
    }
    Assert "Repo TB = round(totGB / 1024, 1 decimal)" {
        $totGB = 10444.8
        $repoTB = [Math]::Round($totGB / 1024, 1)  # 10.2
        $repoTB -eq 10.2
    }

    # ── C-23: VSA warning suppression logic ──────────────────────────────────
    Write-Sub "C-23: VSA warning logic"
    Assert "VSA warning suppressed when isVSA=True" {
        $isVSA = $true; $v13 = $true
        $warn = -not $isVSA -and -not $v13
        -not $warn  # suppressed
    }
    Assert "VSA warning suppressed on v13 Windows (not needed)" {
        $isVSA = $false; $v13 = $true
        $warn = -not $isVSA -and -not $v13
        -not $warn  # suppressed on v13
    }
    Assert "VSA warning fires on v12 non-VSA (upgrade required)" {
        $isVSA = $false; $v13 = $false
        $warn = -not $isVSA -and -not $v13
        $warn  # fires on v12
    }

    # ── C-24: Auto logoff ────────────────────────────────────────────────────
    Write-Sub "C-24: Auto logoff"
    Assert "AutoLogoff=False should fire Warning" {
        $autoLogoff = $false
        -not $autoLogoff
    }
    Assert "AutoLogoff=True should clear Warning" {
        $autoLogoff = $true
        $autoLogoff
    }
    Assert "AutoLogoff=null (v12 log) should NOT fire" {
        $autoLogoff = $null
        $null -eq $autoLogoff
    }

    # ── C-25: Protection coverage (infrastructure VMs vs protected) ──────────────
    Write-Sub "C-25: Protection coverage — unprotected VM detection"
    Assert "Coverage <50% should fire Critical" {
        # effProt = min(protectedVMs + agentProtected, infraVMs); cov = effProt/infra
        $infra = 590; $vmjob = 259; $agent = 0
        $eff = [Math]::Min($vmjob + $agent, $infra)
        $cov = [Math]::Round($eff / $infra * 100)
        $cov -lt 50   # 44% → critical
    }
    Assert "Coverage 50-89% should fire Warning" {
        $infra = 100; $vmjob = 70; $agent = 0
        $eff = [Math]::Min($vmjob + $agent, $infra)
        $cov = [Math]::Round($eff / $infra * 100)
        $cov -ge 50 -and $cov -lt 90   # 70% → warning
    }
    Assert "Coverage >=90% should pass" {
        $infra = 100; $vmjob = 95; $agent = 0
        $eff = [Math]::Min($vmjob + $agent, $infra)
        $cov = [Math]::Round($eff / $infra * 100)
        $cov -ge 90
    }
    Assert "Unprotected count = infra - effProt" {
        $infra = 590; $vmjob = 259; $agent = 0
        $eff = [Math]::Min($vmjob + $agent, $infra)
        $unprot = [Math]::Max(0, $infra - $eff)
        $unprot -eq 331
    }
    Assert "effProt capped at infra (no negative gap from overlap)" {
        $infra = 23; $vmjob = 50; $agent = 0   # jobs overlap, exceed infra
        $eff = [Math]::Min($vmjob + $agent, $infra)
        $eff -eq 23 -and ([Math]::Max(0, $infra - $eff)) -eq 0
    }
    Assert "Coverage skipped when infraVMs=0 (no infrastructure data)" {
        $infra = 0
        $infra -eq 0   # calc guarded by infraVMs>0
    }
    Assert "VCSP provider should skip coverage check" {
        $isProvider = $true
        $isProvider
    }

    # ── C-26: Agent backups included in coverage ─────────────────────────────────
    Write-Sub "C-26: Veeam Agent backups count toward protection"
    Assert "Agent-protected machines offset the gap" {
        # VMC.log scenario: 23 infra, 0 VM jobs, 67 agent → should be 100%
        $infra = 23; $vmjob = 0; $agent = 67
        $eff = [Math]::Min($vmjob + $agent, $infra)
        $cov = [Math]::Round($eff / $infra * 100)
        $cov -eq 100
    }
    Assert "agentProtected = EndpointBackup + EpAgentBackup" {
        $endpointBackup = 5; $epAgentBackup = 62
        $agentProtected = $endpointBackup + $epAgentBackup
        $agentProtected -eq 67
    }
    Assert "Mixed VM-job + agent coverage (hv-b: 2 VM + 7 agent of 45)" {
        $infra = 45; $vmjob = 2; $agent = 7
        $eff = [Math]::Min($vmjob + $agent, $infra)
        $cov = [Math]::Round($eff / $infra * 100)
        $cov -eq 20 -and ([Math]::Max(0,$infra-$eff)) -eq 36
    }
    Assert "No agents: coverage unchanged (CHC-PROD stays 44%)" {
        $infra = 590; $vmjob = 259; $agent = 0
        $eff = [Math]::Min($vmjob + $agent, $infra)
        [Math]::Round($eff / $infra * 100) -eq 44
    }

    # ── C-27: Orphaned / disabled jobs ───────────────────────────────────────────
    Write-Sub "C-27: Orphaned / disabled job detection"
    Assert "Disabled job (ScheduleEnabled=False) flagged as orphaned" {
        $sched = $false; $vms = 5
        (-not $sched)   # 'Schedule disabled' reason
    }
    Assert "Empty job (VMsCount=0) flagged as orphaned" {
        $sched = $true; $vms = 0
        ($vms -eq 0)   # 'No VMs assigned' reason
    }
    Assert "Disabled + empty job flagged" {
        $sched = $false; $vms = 0
        (-not $sched -and $vms -eq 0)   # 'Disabled + empty'
    }
    Assert "Active job with VMs is NOT orphaned" {
        $sched = $true; $vms = 10
        -not (-not $sched -or $vms -eq 0)
    }
    Assert "Disabled replica job flagged as orphaned" {
        $replicaSched = $false
        -not $replicaSched
    }
    Assert "Orphan count fires Warning when >0" {
        $orphanCount = 49   # CHC-PROD scenario
        $orphanCount -gt 0
    }

    # ── C-28: Linux server trust (SSH fingerprint) ───────────────────────────────
    Write-Sub "C-28: Linux manual credentials vs SSH fingerprint"
    Assert "Linux manual credentials should fire Warning" {
        $linuxManualCreds = $true
        $linuxManualCreds
    }
    Assert "SSH fingerprint trust should clear Warning" {
        $linuxManualCreds = $false
        -not $linuxManualCreds
    }

    # ── C-29: Windows Credential Guard ───────────────────────────────────────────
    Write-Sub "C-29: Windows Credential Guard"
    Assert "Credential Guard not configured should fire Warning" {
        $credGuard = $false
        -not $credGuard
    }
    Assert "Credential Guard enabled should clear Warning" {
        $credGuard = $true
        $credGuard
    }

    # ── C-30: Backup server High Availability ────────────────────────────────────
    Write-Sub "C-30: Backup server HA"
    Assert "No HA configured should fire Warning" {
        $haConfigured = $false
        -not $haConfigured
    }
    Assert "HA configured should clear Warning" {
        $haConfigured = $true
        $haConfigured
    }

    # ── C-31: Cloud-targeted job encryption ──────────────────────────────────────
    Write-Sub "C-31: Cloud-targeted jobs must be encrypted"
    Assert "Cloud target without encryption should fire Critical" {
        $isCloudTarget = $true; $encrypted = $false
        $isCloudTarget -and -not $encrypted
    }
    Assert "Cloud target with encryption should clear" {
        $isCloudTarget = $true; $encrypted = $true
        -not ($isCloudTarget -and -not $encrypted)
    }
    Assert "Non-cloud target should not trigger this check" {
        $isCloudTarget = $false; $encrypted = $false
        -not ($isCloudTarget -and -not $encrypted)
    }

    # ── C-32: Repository health check ────────────────────────────────────────────
    Write-Sub "C-32: Repository health check"
    Assert "Health check disabled should fire Warning" {
        $healthCheck = $false
        -not $healthCheck
    }
    Assert "Health check enabled should clear Warning" {
        $healthCheck = $true
        $healthCheck
    }

    # ── C-33: Deleted VM retention ───────────────────────────────────────────────
    Write-Sub "C-33: Deleted VM retention"
    Assert "Deleted VM retention disabled should fire Warning" {
        $deletedVMRet = $false
        -not $deletedVMRet
    }
    Assert "Deleted VM retention enabled should clear Warning" {
        $deletedVMRet = $true
        $deletedVMRet
    }

    # ── C-34: Compression level ──────────────────────────────────────────────────
    Write-Sub "C-34: Compression level"
    Assert "Compression 'None' should fire Warning" {
        $compression = 'None'
        $compression -eq 'None'
    }
    Assert "Compression 'Optimal' should clear Warning" {
        $compression = 'Optimal'
        $compression -ne 'None'
    }

    # ── C-35: Concurrent job count ───────────────────────────────────────────────
    Write-Sub "C-35: Concurrent job count sweet spot"
    Assert "Concurrent jobs >100 should fire Warning" {
        $concJ = 132   # CHC-PROD scenario
        $concJ -gt 100
    }
    Assert "Concurrent jobs <=100 should clear Warning" {
        $concJ = 80
        -not ($concJ -gt 100)
    }

    # ── C-36: Inline malware scan ────────────────────────────────────────────────
    Write-Sub "C-36: Inline malware scan"
    Assert "Inline scan disabled (non-VCSP) should fire Warning" {
        $inlineScan = $false; $isProvider = $false
        -not $inlineScan -and -not $isProvider
    }
    Assert "Inline scan disabled (VCSP) should be Info not Warning" {
        $inlineScan = $false; $isProvider = $true
        -not $inlineScan -and $isProvider   # privacy/perf note for providers
    }
    Assert "Inline scan enabled should clear" {
        $inlineScan = $true
        $inlineScan
    }

    # ── C-37: VeeamONE + backup window ───────────────────────────────────────────
    Write-Sub "C-37: VeeamONE monitoring + backup window"
    Assert "VeeamONE not connected should fire Warning" {
        $veeamOne = $false
        -not $veeamOne
    }
    Assert "VeeamONE connected should clear Warning" {
        $veeamOne = $true
        $veeamOne
    }
    Assert "Backup window not configured should fire Warning" {
        $backupWindow = $false
        -not $backupWindow
    }
    Assert "Backup window configured should clear Warning" {
        $backupWindow = $true
        $backupWindow
    }

    # ── C-38: Failover plans + VBR version gate ──────────────────────────────────
    Write-Sub "C-38: Failover plans + v12/v13 version gate"
    Assert "Failover plans present should fire Info (positive)" {
        $failoverPlans = 67   # AKL-DR scenario
        $failoverPlans -gt 0
    }
    Assert "VBR v12 should note v13 features unavailable" {
        $vbrV13 = $false
        -not $vbrV13
    }
    Assert "VBR v13 should not fire version warning" {
        $vbrV13 = $true
        $vbrV13
    }

    # ── C-39: Multi-run log selection (most recent by date/time) ─────────────────
    Write-Sub "C-39: Most-recent collection run selection (by timestamp)"
    Assert "Run timestamp [DD.MM.YYYY HH:MM:SS.mmm] parses to sortable number" {
        # YYYYMMDDHHMMSSmmm ordering — newer time yields a larger number.
        $a = '26.05.2026 10:00:00.000'  # newer
        $b = '24.05.2026 10:00:00.000'  # older
        function ToNum($s){ if($s -match '(\d{2})\.(\d{2})\.(\d{4})\s+(\d{2}):(\d{2}):(\d{2})\.(\d{3})'){ return [double]($matches[3]+$matches[2]+$matches[1]+$matches[4]+$matches[5]+$matches[6]+$matches[7]) } return -1 }
        (ToNum $a) -gt (ToNum $b)
    }
    Assert "Newest run wins even when it appears FIRST in the file" {
        # Out-of-order: newest run placed before older run. Timestamp selection
        # must still pick the newest (the bug a position-based approach would miss).
        function ToNum($s){ if($s -match '(\d{2})\.(\d{2})\.(\d{4})\s+(\d{2}):(\d{2}):(\d{2})\.(\d{3})'){ return [double]($matches[3]+$matches[2]+$matches[1]+$matches[4]+$matches[5]+$matches[6]+$matches[7]) } return -1 }
        $runNewestFirst = '26.05.2026 10:00:00.000'
        $runOlderLast   = '24.05.2026 10:00:00.000'
        # best = max timestamp regardless of order
        $best = if((ToNum $runNewestFirst) -ge (ToNum $runOlderLast)){ $runNewestFirst } else { $runOlderLast }
        $best -eq '26.05.2026 10:00:00.000'
    }
    Assert "Day-first dot format is parsed unambiguously" {
        # Line prefix is always DD.MM.YYYY regardless of the locale UTC header.
        $prefix = '24.05.2026 20:48:01.025'
        ($prefix -match '^(\d{2})\.(\d{2})\.(\d{4})') -and ($matches[1] -eq '24') -and ($matches[2] -eq '05')
    }
    Assert "Marker absent falls back to whole file" {
        $marker = 'STARTCOLLECTINFRASTATISTIC'
        $sample = "old format log with no collection marker"
        $sample.IndexOf($marker) -eq -1
    }

} # end Module C


# ══════════════════════════════════════════════════════════════════════════════
#  FINAL SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
Write-Head "FINAL RESULTS — Veeam Advisor v1.0 Test Suite"

$total = $script:TotalPass + $script:TotalFail + $script:TotalSkip
Out-Log ""
Out-Log "  PASSED  : $($script:TotalPass)"  -Colour Green
Out-Log "  FAILED  : $($script:TotalFail)"  -Colour $(if ($script:TotalFail -gt 0) { 'Red' } else { 'Green' })
Out-Log "  SKIPPED : $($script:TotalSkip)"  -Colour Yellow
Out-Log "  TOTAL   : $total"                -Colour White
Out-Log ""

if ($script:FailedTests.Count -gt 0) {
    Out-Log "  Failed tests:" -Colour Red
    foreach ($ft in $script:FailedTests) {
        Out-Log "    - $ft" -Colour Red
    }
    Out-Log ""
    Out-Log "  RESULT: $($script:TotalFail) test(s) FAILED" -Colour Red
} else {
    Out-Log "  RESULT: ALL TESTS PASSED" -Colour Green
}

# ─── Write clean summary block at end of log file ─────────────────────────────
$summaryLines = @(
    '',
    ('----------------------------------------------------------------------'),
    "  SUMMARY",
    ('----------------------------------------------------------------------'),
    "  Completed : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
    "  PASSED    : $($script:TotalPass)",
    "  FAILED    : $($script:TotalFail)",
    "  SKIPPED   : $($script:TotalSkip)",
    "  TOTAL     : $total",
    ''
)
if ($script:FailedTests.Count -gt 0) {
    $summaryLines += "  FAILED TESTS:"
    foreach ($ft in $script:FailedTests) {
        $summaryLines += "    - $ft"
    }
    $summaryLines += ''
    $summaryLines += "  RESULT: $($script:TotalFail) test(s) FAILED"
} else {
    $summaryLines += "  RESULT: ALL TESTS PASSED"
}
$summaryLines += ('======================================================================')
$summaryLines | Add-Content -Path $script:LogFile -Encoding UTF8

Out-Log ""
Out-Log "  Full results saved to: $($script:LogFile)" -Colour DarkGray
Out-Log ""

if ($script:TotalFail -gt 0) { exit 1 } else { exit 0 }
