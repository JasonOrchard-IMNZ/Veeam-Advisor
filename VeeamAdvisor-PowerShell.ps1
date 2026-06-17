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
    Veeam Advisor — VBR Infrastructure Validation Script

.DESCRIPTION
    Validates all PowerShell cmdlets used in Veeam Advisor against a live VBR server.
    Designed to be run on a deployed VBR environment after initial setup.

    Tests:
        B-1  Get-VBRServer          — managed servers, backup server identity
        B-2  Get-VBRViProxy         — VMware proxy details and Host.Id filter
        B-3  Get-VBRHvProxy         — Hyper-V proxy details and Host.Id filter
        B-4  Get-VBRBackupRepository — repo types, Cloud filter, SOBR, GUID filter
        B-5  Get-VBRJob             — backup + replica jobs, IsReplica filter, -Name param
        B-6  Get-VBRComputerBackupJob — managed agent job policies
        B-7  Get-VBREPJob           — legacy standalone agent jobs
        B-8  Get-VBRCloudTenant     — Cloud Connect tenants (VCSP environments)
        B-9  Get-VBRBackupCopyJob   — backup copy jobs
        B-10 Get-VBRSureBackupJob   — SureBackup verification jobs
        B-11 Get-VBRTapeJob         — tape backup jobs
        B-12 Get-VBRUnstructuredBackupJob — unstructured data (NAS/object storage) jobs

    Analysis (mirrors the standalone app's published insights):
        A-1  Protection coverage     — infra VMs vs jobs + agents, coverage %
        A-2  Orphaned/disabled jobs  — jobs creating no restore points

    All results are written to both the console and a timestamped log file.

.PARAMETER VBRServer
    VBR server hostname or IP. Default: localhost.

.PARAMETER Credential
    PSCredential for the VBR/VSA connection. If omitted:
      - localhost target → uses the current Windows session (single sign-on)
      - remote/VSA target → the script prompts for username and password
    Pass a pre-built credential (Get-Credential) for unattended/automated runs.

.PARAMETER PromptCredential
    Force an interactive username/password prompt even for a localhost target.
    Useful when the current Windows session does not have VBR rights.

.PARAMETER Port
    VBR console port. Default: 9392.

.PARAMETER LogFile
    Output log file path. Default: auto-generated in the script folder:
    VeeamAdvisor-VBR-Validation_<yyyyMMdd_HHmmss>.txt

.EXAMPLE
    # Run on the VBR server or VSA appliance console itself (localhost)
    .\VeeamAdvisor-PowerShell.ps1

.EXAMPLE
    # Remote VBR server by hostname, with credentials and custom log path
    $cred = Get-Credential
    .\VeeamAdvisor-PowerShell.ps1 -VBRServer vbr01.lab.local -Credential $cred -LogFile C:\Logs\vbr-check.txt

.EXAMPLE
    # Remote VSA appliance by IP — script prompts for username/password
    .\VeeamAdvisor-PowerShell.ps1 -VBRServer 10.0.0.50 -ConnectionType VSA

.EXAMPLE
    # Remote VSA appliance by IP address (pre-built credential, unattended)
    $cred = Get-Credential
    .\VeeamAdvisor-PowerShell.ps1 -VBRServer 10.0.0.50 -ConnectionType VSA -Credential $cred

.EXAMPLE
    # Remote console / VBR server by IP, custom port
    $cred = Get-Credential
    .\VeeamAdvisor-PowerShell.ps1 -VBRServer 192.168.1.20 -Port 9392 -ConnectionType Remote -Credential $cred

.NOTES
    Veeam Advisor v1.3 — VBR Validation (Module B standalone)
    Reference: helpcenter.veeam.com/docs/vbr/powershell/
    Validated against: Veeam Backup & Replication v13
#>

[CmdletBinding()]
param(
    # VBR server to connect to. Accepts:
    #   'localhost'            — run directly on the VBR server or VSA appliance console
    #   '<hostname>' / '<FQDN>'— a remote VBR server or VSA by name
    #   '<IP address>'         — a remote VBR server, VSA appliance, or remote console by IP
    [string]      $VBRServer = 'localhost',
    [PSCredential]$Credential,
    # Service port for Connect-VBRServer. Default 9392 (the classic console port,
    # used by v12). On v13 the Identity Service prioritises 443 — if 9392 fails with
    # "Failed to connect to Identity service", the script automatically retries on
    # 443. Pass -Port 443 explicitly to go straight there on a v13 server.
    [int]         $Port      = 9392,
    # Connection target type — informational, tailors the connection messages.
    #   Auto    — infer from $VBRServer (default)
    #   Local   — this host is the VBR server / VSA appliance (localhost)
    #   VSA     — remote Veeam Software Appliance (Linux) by host/IP
    #   Remote  — remote VBR server or remote console by host/IP
    [ValidateSet('Auto','Local','VSA','Remote')]
    [string]      $ConnectionType = 'Auto',
    # Force an interactive Get-Credential prompt even for localhost. By default the
    # script auto-prompts only for remote/VSA targets when -Credential is omitted.
    [switch]      $PromptCredential,
    [string]      $LogFile   = ''
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

# ─── Enforce TLS 1.2 (and 1.3 where available) for all HTTPS calls ───────────
# PowerShell 5.1 defaults to TLS 1.0/1.1, which modern endpoints reject. Force a
# secure protocol set so any HTTPS traffic negotiates over TLS 1.2 or higher.
try {
    $proto = [System.Net.SecurityProtocolType]::Tls12
    if ([Enum]::GetNames([System.Net.SecurityProtocolType]) -contains 'Tls13') {
        $proto = $proto -bor [System.Net.SecurityProtocolType]::Tls13
    }
    [System.Net.ServicePointManager]::SecurityProtocol = $proto
} catch {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
}

# ─── Log file initialisation ──────────────────────────────────────────────────
if (-not $LogFile) {
    $stamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
    $LogFile = Join-Path $PSScriptRoot "VeeamAdvisor-VBR-Validation_$stamp.txt"
}
$script:LogFile = $LogFile

@(
    '======================================================================'
    '  VEEAM ADVISOR — VBR INFRASTRUCTURE VALIDATION'
    "  Run at    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    "  Host      : $($env:COMPUTERNAME)"
    "  User      : $($env:USERNAME)"
    "  VBRServer : $VBRServer"
    "  LogFile   : $LogFile"
    '======================================================================'
    ''
) | Set-Content -Path $LogFile -Encoding UTF8

Write-Host ""
Write-Host "  Veeam Advisor — VBR Infrastructure Validation" -ForegroundColor Cyan
Write-Host "  Log: $LogFile" -ForegroundColor DarkGray
Write-Host ""

# ─── Tee function — screen + file ────────────────────────────────────────────
function Out-Log {
    param([string]$Text, [string]$Colour = 'White')
    Write-Host $Text -ForegroundColor $Colour
    $ts = Get-Date -Format 'HH:mm:ss'
    Add-Content -Path $script:LogFile -Value "[$ts] $Text" -Encoding UTF8
}

function Write-Pass { param([string]$m) Out-Log "  [PASS] $m" -Colour Green  }
function Write-Fail { param([string]$m) Out-Log "  [FAIL] $m" -Colour Red    }
function Write-Warn { param([string]$m) Out-Log "  [WARN] $m" -Colour Yellow }
function Write-Info { param([string]$m) Out-Log "  [INFO] $m" -Colour Cyan   }
function Write-Data { param([string]$m) Out-Log "  [DATA] $m" -Colour Gray   }
function Write-Head {
    param([string]$m)
    Out-Log ''
    Out-Log '======================================================================' -Colour White
    Out-Log "  $m" -Colour White
    Out-Log '======================================================================' -Colour White
}
function Write-Sub  { param([string]$m) Out-Log "`n  --- $m ---" -Colour DarkGray }

# ─── Counters ─────────────────────────────────────────────────────────────────
$script:Pass  = 0
$script:Fail  = 0
$script:Skip  = 0
$script:Findings = 0
$script:Fails = [System.Collections.Generic.List[string]]::new()

function Assert {
    param([string]$Name, [scriptblock]$Test, [string]$Skip = '')
    if ($Skip) {
        Write-Warn "SKIP  $Name ($Skip)"
        $script:Skip++
        return $null
    }
    try {
        $result = & $Test
        if ($result -eq $true) {
            Write-Pass $Name
            $script:Pass++
        } else {
            Write-Fail "$Name — result: $result"
            $script:Fail++
            $script:Fails.Add($Name)
        }
    } catch {
        Write-Fail "$Name — $($_.Exception.Message)"
        $script:Fail++
        $script:Fails.Add($Name)
    }
}

# ─── GUID filter helper (safe for single-object or array returns) ─────────────
function Test-GuidFilter {
    param([string]$Label, [object[]]$Items, [string]$Prop = 'Id')
    $arr = @($Items)
    if ($arr.Count -eq 0) {
        Write-Warn "$Label — empty collection, GUID filter skipped"
        $script:Skip++
        return
    }
    $id = $arr[0].$Prop
    if ($null -eq $id) {
        Write-Warn "$Label — .$Prop is null, GUID filter skipped"
        $script:Skip++
        return
    }
    $guid  = if ($id -is [System.Guid]) { $id } else { [System.Guid]$id }
    $match = @($arr | Where-Object { $_.$Prop -eq $guid })
    Assert "$Label — [Guid] .$Prop filter returns ≥1 result" { $match.Count -ge 1 }
    if ($match.Count -ge 1) {
        $mname=if($null -ne $match[0].Name){$match[0].Name}else{$match[0].$Prop}; Write-Data "  Matched: $mname"
    }
}

# ─── SECTION SEPARATOR ────────────────────────────────────────────────────────
function Write-Section {
    param([string]$Title)
    Out-Log ''
    Out-Log "  $('------------------------------------------------------------------')" -Colour DarkGray
    Out-Log "  $Title" -Colour White
    Out-Log "  $('------------------------------------------------------------------')" -Colour DarkGray
}


# ══════════════════════════════════════════════════════════════════════════════
#  PRE-FLIGHT — MODULE + CONNECTION
# ══════════════════════════════════════════════════════════════════════════════
Write-Head "PRE-FLIGHT: Veeam PowerShell Module"

$module = Get-Module -ListAvailable -Name 'Veeam.Backup.PowerShell' |
          Sort-Object Version -Descending | Select-Object -First 1

if (-not $module) {
    Write-Fail "Veeam.Backup.PowerShell module not found"
    Write-Info "  Install from the VBR server: Import-Module 'C:\Program Files\Veeam\Backup and Replication\Console\Veeam.Backup.PowerShell.dll'"
    Add-Content -Path $script:LogFile -Value "`nRESULT: ABORTED — Veeam PS module not installed" -Encoding UTF8
    exit 1
}

Write-Pass "Module found: $($module.Name) v$($module.Version)"
Import-Module Veeam.Backup.PowerShell -DisableNameChecking -ErrorAction Stop
Write-Pass "Module imported successfully"

# ─── VBR Connection ───────────────────────────────────────────────────────────
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
Write-Head "CONNECT to VBR: $targetDesc"

$connected = $false
try {
    $session = Get-VBRServerSession
    if ($session -and ($session.Server -eq $VBRServer -or $resolvedType -eq 'Local')) {
        Write-Pass "Active VBR session detected — skipping Connect-VBRServer"
        Write-Info "  Connected to: $($session.Server)"
        $connected = $true
    }
} catch { }

if (-not $connected) {
    # ── Credential prompting ────────────────────────────────────────────────
    # Prompt for username/password when:
    #   - the user explicitly asked (-PromptCredential), OR
    #   - the target is remote/VSA and no -Credential was supplied (SSO won't
    #     apply to a Linux VSA appliance or a non-domain remote host).
    # For localhost we default to the current Windows session (single sign-on).
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
            Write-Warn "No credentials provided — attempting connection with the current Windows session."
        }
    }

    # Build the base connection parameters once.
    $baseParams = @{ Server = $VBRServer; Port = $Port }
    if ($Credential) { $baseParams['Credential'] = $Credential }
    # v13: -ForceAcceptTlsCertificate accepts the backup server's TLS certificate
    # on connect, avoiding cert-trust failures. Added only if the running module
    # supports it (v13+), so the script stays compatible with v12.
    $supportsForceTls = [bool](Get-Command Connect-VBRServer | Where-Object { $_.Parameters.Keys -contains 'ForceAcceptTlsCertificate' })
    if ($supportsForceTls) { $baseParams['ForceAcceptTlsCertificate'] = $true }

    # Try a sequence of connection variants over IPv4. First success wins.
    #
    # v13 ARCHITECTURE CHANGE: the Veeam Backup REST Service (the Identity Service
    # that Connect-VBRServer authenticates against) is hardcoded to prioritise port
    # 443 — the classic console port 9392 is no longer the front door for the v13
    # identity handshake. On a v13 server, a connect on 9392 can therefore fail with
    # "Failed to connect to Identity service" even though everything is healthy,
    # while 443 succeeds. We try the configured port first, then 443.
    $attempts = @()
    $attempts += ,@{ Desc = "$VBRServer on port $Port"; Params = $baseParams }
    # Fall back to the v13 Identity Service port (443) if a different port was used.
    if ($Port -ne 443) {
        $p443 = @{ Server = $VBRServer; Port = 443 }
        if ($Credential)       { $p443['Credential'] = $Credential }
        if ($supportsForceTls) { $p443['ForceAcceptTlsCertificate'] = $true }
        $attempts += ,@{ Desc = "$VBRServer on port 443 (v13 Identity Service port)"; Params = $p443 }
    }
    # For a local connect, also try the certificate-bound machine name on 443
    # (the v13 cert is CN=<hostname>; some hosts reject 'localhost' but accept the name).
    if ($resolvedType -eq 'Local' -and $VBRServer -ne $env:COMPUTERNAME) {
        $byName = @{ Server = $env:COMPUTERNAME; Port = 443 }
        if ($Credential)       { $byName['Credential'] = $Credential }
        if ($supportsForceTls) { $byName['ForceAcceptTlsCertificate'] = $true }
        $attempts += ,@{ Desc = "$($env:COMPUTERNAME) on port 443 (certificate-bound name)"; Params = $byName }
    }

    $lastErr = $null
    foreach ($attempt in $attempts) {
        try {
            if ($attempt.Desc -ne $attempts[0].Desc) { Write-Info "Retrying via $($attempt.Desc)..." }
            $cp = $attempt.Params
            Connect-VBRServer @cp
            Write-Pass "Connected to $targetDesc via $($attempt.Desc)"
            $connected = $true
            break
        } catch {
            $lastErr = $_
        }
    }

    if (-not $connected) {
        $errMsg = "$($lastErr.Exception.Message)"
        Write-Warn "Connection failed: $errMsg"

        # v13 introduced an Identity Service that Connect-VBRServer authenticates
        # against. "Failed to connect to Identity service" is a specific condition
        # distinct from a plain service-down or wrong-host error — run live probes.
        if ($errMsg -match 'Identity service|Identity Service') {
            Write-Warn ""
            Write-Warn "  v13 IDENTITY SERVICE error — the module loaded, but the backend"
            Write-Warn "  Identity/authentication service did not accept the connection."
            Write-Warn "  Running diagnostics..."
            Write-Warn ""

            # Probe 1: are the Veeam services actually running?
            $stopped = @(Get-Service Veeam* -ErrorAction SilentlyContinue | Where-Object { $_.Status -ne 'Running' -and $_.Name -notmatch 'Deployment|MBPDeploy|OneDeploy' })
            if ($stopped.Count -gt 0) {
                Write-Warn "  [!] These Veeam services are NOT running (may be the cause):"
                foreach ($s in $stopped) { Write-Warn "        $($s.Status)  $($s.Name)" }
            } else {
                Write-Info "  [ok] Core Veeam services are running (ignoring deployment helpers)."
            }

            # Probe 2: which ports is the Veeam Backup / REST service listening on?
            # v13's Identity Service (Veeam Backup REST Service) prioritises 443; the
            # classic 9392 is no longer the identity front door. If the connect port
            # isn't where the service is bound, the connect fails.
            try {
                $restPort443 = @(Get-NetTCPConnection -State Listen -LocalPort 443 -ErrorAction SilentlyContinue)
                $cfgPortBound = @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)
                if ($restPort443.Count -gt 0) {
                    Write-Info "  [ok] Port 443 (v13 Identity Service) IS listening."
                }
                if ($Port -ne 443 -and $cfgPortBound.Count -eq 0) {
                    Write-Warn "  [!] Port $Port is NOT listening, but 443 is. v13 moved the identity"
                    Write-Warn "      handshake to 443. Re-run on 443:"
                    Write-Warn "        .\VeeamAdvisor-PowerShell.ps1 -Port 443"
                    Write-Warn "      (this script now tries 443 automatically as a fallback)."
                }
            } catch {
                Write-Info "  [i] Could not enumerate listening ports ($($_.Exception.Message))."
            }

            Write-Warn ""
            Write-Warn "  PROVEN REMEDIATION for this v13 error (services up, cert valid):"
            Write-Warn "  1. Connect on port 443 — v13's Identity Service (Veeam Backup REST"
            Write-Warn "     Service) is hardcoded to prioritise 443, not the classic 9392:"
            Write-Warn "        .\VeeamAdvisor-PowerShell.ps1 -Port 443"
            Write-Warn "     (this script now tries 443 automatically before failing)."
            Write-Warn "  2. Ensure nothing else occupies 443 on this host — v13 requires it and"
            Write-Warn "     the VBR/REST service will not bind if 443 is already in use:"
            Write-Warn "        Get-NetTCPConnection -State Listen -LocalPort 443"
            Write-Warn "  3. If 443 is bound by Veeam yet the connect still fails, restart the"
            Write-Warn "     service and retry:  Restart-Service VeeamBackupSvc -Force"
        } elseif ($resolvedType -eq 'Local') {
            Write-Warn "  Ensure the Veeam Backup Service is running on this host:"
            Write-Warn "     Get-Service Veeam* | Where-Object {`$_.Status -ne 'Running'}"
            Write-Warn "  Or pass -VBRServer <host/IP> to target a remote server / VSA."
        } else {
            Write-Warn "  Verify the host/IP and port ($Port) are reachable, the Veeam"
            Write-Warn "  Backup Service is running, and the credentials are valid."
        }
        Add-Content -Path $script:LogFile -Value "`nRESULT: ABORTED — Could not connect to VBR ($errMsg)" -Encoding UTF8
        exit 1
    }
}


# ══════════════════════════════════════════════════════════════════════════════
#  B-1  Get-VBRServer
#  Tests: runs, count, .Name, .Id (Guid), backup server identification,
#         .Type enum values, [Guid] filter
# ══════════════════════════════════════════════════════════════════════════════
Write-Head "B-1: Get-VBRServer — All managed servers"

$allServers = @()
try {
    $allServers = @(Get-VBRServer)
    Write-Pass "Get-VBRServer runs without error"
    $script:Pass++
} catch {
    Write-Fail "Get-VBRServer threw: $($_.Exception.Message)"
    $script:Fail++
}

if ($allServers.Count -gt 0) {
    Write-Info "Found $($allServers.Count) managed server(s)"

    Assert "All servers have .Name property" {
        @($allServers | Where-Object { $null -eq $_.Name }).Count -eq 0
    }

    Assert "All servers have .Id as [System.Guid]" {
        @($allServers | Where-Object { $_.Id -isnot [System.Guid] }).Count -eq 0
    }

    Assert "All servers have .Type property" {
        @($allServers | Where-Object { $null -eq $_.Type }).Count -eq 0
    }

    # Identify backup server
    $backupServer = @($allServers | Where-Object {
        ($_.Description -match 'This server') -or
        ($_.Type -eq 'Windows' -and
         $null -ne $_.ParentId -and
         $_.ParentId -eq [System.Guid]'00000000-0000-0000-0000-000000000000')
    }) | Select-Object -First 1

    Assert "Backup server identified in server list" { $null -ne $backupServer }
    if ($backupServer) {
        Write-Data "  Backup server : $($backupServer.Name)"
        Write-Data "  Type          : $($backupServer.Type)"
        Write-Data "  Id            : $($backupServer.Id)"
        try { Write-Data "  PhysHostId    : $($backupServer.PhysHostId)" } catch { }
    }

    Write-Sub "All managed servers"
    foreach ($s in $allServers) {
        $tag = if ($s.Description -match 'This server') { ' ◄ BACKUP SERVER' } else { '' }
        Write-Data "  '$($s.Name)' | Type: $($s.Type) | Id: $($s.Id)$tag"
    }

    Test-GuidFilter -Label 'Get-VBRServer [Guid] Id filter' -Items $allServers

} else {
    Write-Warn "No servers returned — skipping B-1 property assertions"
    $script:Skip += 4
}


# ══════════════════════════════════════════════════════════════════════════════
#  B-2  Get-VBRViProxy
#  App pattern: Get-VBRViProxy | Select Name, @{N="HostId";E={$_.Host.Id}}
#               Get-VBRViProxy | Where {$_.Host.Id -eq [Guid]"<paste>"}
# ══════════════════════════════════════════════════════════════════════════════
Write-Head "B-2: Get-VBRViProxy — VMware backup proxies"

$viProxies = @()
try {
    $viProxies = @(Get-VBRViProxy)
    Write-Pass "Get-VBRViProxy runs without error"
    $script:Pass++
} catch {
    Write-Fail "Get-VBRViProxy threw: $($_.Exception.Message)"
    $script:Fail++
}

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
    Assert "Vi proxies: .TransportMode exists" {
        @($viProxies | Where-Object { $null -eq $_.TransportMode }).Count -eq 0
    }
    Assert "Vi proxies: .MaxTasksCount exists" {
        @($viProxies | Where-Object { $null -eq $_.MaxTasksCount }).Count -eq 0
    }

    # Validate computed HostId column — exact app pattern
    $table = @($viProxies | Select-Object Name, @{N='HostId'; E={$_.Host.Id}})
    Assert "Vi proxy: computed HostId column is [System.Guid]" {
        $null -ne $table[0].HostId -and $table[0].HostId -is [System.Guid]
    }

    # Validate [Guid] Host.Id filter — exact app pattern
    $testHostId = $viProxies[0].Host.Id
    $filtered   = @(Get-VBRViProxy | Where-Object { $_.Host.Id -eq $testHostId })
    Assert "Vi proxy: [Guid] Host.Id filter returns match" { $filtered.Count -ge 1 }

    Write-Sub "VMware proxies"
    foreach ($p in $viProxies) {
        Write-Data "  '$($p.Name)'"
        Write-Data "    Host.Id       : $($p.Host.Id)"
        Write-Data "    TransportMode : $($p.TransportMode)"
        Write-Data "    MaxTasks      : $($p.MaxTasksCount)"
        Write-Data "    IsDisabled    : $($p.IsDisabled)"
    }

} else {
    Write-Info "No VMware proxies configured — B-2 assertions skipped"
    $script:Skip += 7
}


# ══════════════════════════════════════════════════════════════════════════════
#  B-3  Get-VBRHvProxy
#  App pattern: Get-VBRHvProxy | Select Name, @{N="HostId";E={$_.Host.Id}}
# ══════════════════════════════════════════════════════════════════════════════
Write-Head "B-3: Get-VBRHvProxy — Hyper-V backup proxies"

$hvProxies = @()
try {
    $hvProxies = @(Get-VBRHvProxy)
    Write-Pass "Get-VBRHvProxy runs without error"
    $script:Pass++
} catch {
    Write-Fail "Get-VBRHvProxy threw: $($_.Exception.Message)"
    $script:Fail++
}

if ($hvProxies.Count -gt 0) {
    Write-Info "Found $($hvProxies.Count) Hyper-V proxy/proxies"

    Assert "Hv proxies: .Name exists on all" {
        @($hvProxies | Where-Object { $null -eq $_.Name }).Count -eq 0
    }
    Assert "Hv proxies: .Host exists on all" {
        @($hvProxies | Where-Object { $null -eq $_.Host }).Count -eq 0
    }
    Assert "Hv proxies: .Host.Id is [System.Guid]" {
        @($hvProxies | Where-Object { $_.Host.Id -isnot [System.Guid] }).Count -eq 0
    }

    # Computed HostId column
    $hvTable = @($hvProxies | Select-Object Name, @{N='HostId'; E={$_.Host.Id}})
    Assert "Hv proxy: computed HostId column is [System.Guid]" {
        $null -ne $hvTable[0].HostId -and $hvTable[0].HostId -is [System.Guid]
    }

    Write-Sub "Hyper-V proxies"
    foreach ($p in $hvProxies) {
        Write-Data "  '$($p.Name)'"
        Write-Data "    Host.Id    : $($p.Host.Id)"
        try { Write-Data "    MaxTasks   : $($p.MaxTasksCount)" } catch { }
    }

    # Host.Id is a nested property — validate it inline (helper can't resolve dotted paths)
    $hvTestId = $hvProxies[0].Host.Id
    $hvFiltered = @(Get-VBRHvProxy | Where-Object { $_.Host.Id -eq $hvTestId })
    Assert "Hv proxy: [Guid] Host.Id filter returns match" { $hvFiltered.Count -ge 1 }
    Test-GuidFilter -Label 'Get-VBRHvProxy [Guid] Id filter' -Items $hvProxies

} else {
    Write-Info "No Hyper-V proxies configured — B-3 assertions skipped"
    $script:Skip += 5
}


# ══════════════════════════════════════════════════════════════════════════════
#  B-4  Get-VBRBackupRepository
#  App patterns:
#    Get-VBRBackupRepository | Where {$_.Type -eq 'Cloud'}
#    Get-VBRBackupRepository | Where {$_.Id -eq [Guid]'...'} | Select Name
#    Get-VBRBackupRepository -ScaleOut  (SOBRs)
# ══════════════════════════════════════════════════════════════════════════════
Write-Head "B-4: Get-VBRBackupRepository — Repositories"

$repos = @()
try {
    $repos = @(Get-VBRBackupRepository)
    Write-Pass "Get-VBRBackupRepository runs without error"
    $script:Pass++
} catch {
    Write-Fail "Get-VBRBackupRepository threw: $($_.Exception.Message)"
    $script:Fail++
}

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
        $capGB = '—'; $freeGB = '—'
        try { $cont = $r.GetContainer(); $capGB = [Math]::Round($cont.CachedTotalSpace.InGigabytes,1); $freeGB = [Math]::Round($cont.CachedFreeSpace.InGigabytes,1) } catch { }
        Write-Data "  '$($r.Name)'"
        Write-Data "    Type     : $($r.Type)"
        Write-Data "    Id       : $($r.Id)"
        Write-Data "    Capacity : $capGB GB   Free: $freeGB GB"
    }

    # Type breakdown
    Write-Sub "Repository type breakdown"
    $repos | Group-Object Type | Sort-Object Count -Descending | ForEach-Object {
        Write-Data "  $($_.Name): $($_.Count)"
    }

    # Cloud type filter — app pattern for CC tenant repos
    Write-Sub "Cloud-type repos (app pattern: .Type -eq 'Cloud')"
    $cloudRepos = @($repos | Where-Object { $_.Type -eq 'Cloud' })
    if ($cloudRepos.Count -gt 0) {
        Write-Pass "Cloud repos found: $($cloudRepos.Count)"
        $script:Pass++
        foreach ($cr in $cloudRepos) {
            Write-Data "  Cloud: '$($cr.Name)' | Id: $($cr.Id)"
        }
    } else {
        Write-Info "No Cloud-type repos (expected on non-CC-tenant environments)"
        $script:Skip++
    }

    Test-GuidFilter -Label 'Get-VBRBackupRepository [Guid] Id filter' -Items $repos

    # ScaleOut repos (SOBRs)
    Write-Sub "Scale-Out repos (-ScaleOut switch)"
    try {
        $sobrs = @(Get-VBRBackupRepository -ScaleOut)
        Write-Pass "Get-VBRBackupRepository -ScaleOut runs without error"
        $script:Pass++
        if ($sobrs.Count -gt 0) {
            Write-Info "SOBRs found: $($sobrs.Count)"
            foreach ($s in $sobrs) { Write-Data "  SOBR: '$($s.Name)' | Id: $($s.Id)" }
        } else {
            Write-Info "No SOBRs configured"
        }
    } catch {
        Write-Fail "-ScaleOut threw: $($_.Exception.Message)"
        $script:Fail++
    }

} else {
    Write-Warn "No repositories returned — skipping B-4 assertions"
    $script:Skip += 5
}


# ══════════════════════════════════════════════════════════════════════════════
#  B-5  Get-VBRJob
#  App patterns:
#    Get-VBRJob | Where-Object {$_.Id -eq [Guid]'<JobID>'} | Select Name
#    Get-VBRJob | Where {$_.IsReplica -eq $true} | Where {$_.Id -eq [Guid]'...'} | Select Name
#  AUDIT NOTE: Get-VBRJob has NO -Type parameter in v13 — use .IsReplica instead
# ══════════════════════════════════════════════════════════════════════════════
Write-Head "B-5: Get-VBRJob — Backup and replication jobs"

$jobs = @()
try {
    $jobs = @(Get-VBRJob)
    Write-Pass "Get-VBRJob runs without error"
    $script:Pass++
} catch {
    Write-Fail "Get-VBRJob threw: $($_.Exception.Message)"
    $script:Fail++
}

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
    Assert "Jobs: .IsReplica property exists on all" {
        @($jobs | Where-Object { $null -eq $_.IsReplica }).Count -eq 0
    }

    # Confirm -Type parameter does NOT exist (v13 audit confirmed)
    Write-Sub "Audit: confirm -Type parameter absent from Get-VBRJob (v13)"
    $hasTypeParam = (Get-Command Get-VBRJob).Parameters.ContainsKey('Type')
    Assert "Get-VBRJob: no -Type parameter (use .IsReplica instead)" { -not $hasTypeParam }
    if ($hasTypeParam) {
        Write-Warn "  -Type parameter found — may be an older VBR version"
    }

    # JobType breakdown
    Write-Sub "Job type breakdown"
    $jobs | Group-Object JobType | Sort-Object Count -Descending | ForEach-Object {
        Write-Data "  $($_.Name): $($_.Count) job(s)"
    }

    Write-Sub "All jobs"
    foreach ($j in $jobs) {
        $schedEnabled = '—'
        try { $schedEnabled = $j.ScheduleOptions.Enabled } catch { }
        Write-Data "  '$($j.Name)'"
        Write-Data "    JobType   : $($j.JobType)"
        Write-Data "    IsReplica : $($j.IsReplica)"
        Write-Data "    Id        : $($j.Id)"
        Write-Data "    Scheduled : $schedEnabled"
    }

    # GUID lookup — app pattern
    Test-GuidFilter -Label 'Get-VBRJob [Guid] Id filter' -Items $jobs

    # -Name parameter
    Write-Sub "-Name parameter test"
    try {
        $byName = @(Get-VBRJob -Name $jobs[0].Name)
        Assert "Get-VBRJob -Name returns result" { $byName.Count -ge 1 }
        if ($byName.Count -ge 1) { Write-Data "  -Name '$($jobs[0].Name)' → found $($byName.Count)" }
    } catch {
        Write-Fail "Get-VBRJob -Name threw: $($_.Exception.Message)"
        $script:Fail++
    }

    # Replica filter — use .IsReplica (not .JobType string comparison per v13 audit)
    Write-Sub ".IsReplica -eq `$true filter (app pattern — replaces .JobType 'Replica')"
    $replJobs = @($jobs | Where-Object { $_.IsReplica -eq $true })
    if ($replJobs.Count -gt 0) {
        Write-Pass ".IsReplica filter — $($replJobs.Count) replica job(s)"
        $script:Pass++
        foreach ($rj in $replJobs) {
            Write-Data "  Replica: '$($rj.Name)' | Id: $($rj.Id)"
        }
        Test-GuidFilter -Label 'Get-VBRJob (Replica) [Guid] Id filter' -Items $replJobs
    } else {
        Write-Info "No replica jobs — .IsReplica filter test skipped"
        $script:Skip++
    }

} else {
    Write-Warn "No jobs returned — skipping B-5 assertions"
    $script:Skip += 7
}


# ══════════════════════════════════════════════════════════════════════════════
#  B-6  Get-VBRComputerBackupJob
#  App pattern: Get-VBRComputerBackupJob | Where {$_.Id -eq [Guid]'...'} | Select Name, PolicyType
#  Managed agent backup policies (modern — replaces legacy EndpointBackup)
# ══════════════════════════════════════════════════════════════════════════════
Write-Head "B-6: Get-VBRComputerBackupJob — Managed agent policies"

$agentJobs = @()
try {
    $agentJobs = @(Get-VBRComputerBackupJob)
    Write-Pass "Get-VBRComputerBackupJob runs without error"
    $script:Pass++
} catch {
    Write-Fail "Get-VBRComputerBackupJob threw: $($_.Exception.Message)"
    $script:Fail++
}

if ($agentJobs.Count -gt 0) {
    Write-Info "Found $($agentJobs.Count) managed agent job/policy"

    Assert "Agent jobs: .Name exists on all" {
        @($agentJobs | Where-Object { $null -eq $_.Name }).Count -eq 0
    }
    Assert "Agent jobs: .Id is [System.Guid] on all" {
        @($agentJobs | Where-Object { $_.Id -isnot [System.Guid] }).Count -eq 0
    }

    Write-Sub "Managed agent jobs"
    foreach ($aj in $agentJobs) {
        Write-Data "  '$($aj.Name)'"
        Write-Data "    Id         : $($aj.Id)"
        # v13's VBRComputerBackupJob schema varies; probe several candidate properties
        # for the management mode / type and show whichever are populated, rather than
        # assuming fixed names (PolicyType/JobType came back empty on a real v13 job).
        $shown = $false
        foreach ($prop in 'JobType','Type','PolicyType','BackupType','Mode','OSPlatform','OsType','BackupModeType') {
            $val = $null
            try { $val = $aj.$prop } catch { }
            if ($val -ne $null -and "$val" -ne '') {
                Write-Data ("    {0,-10} : {1}" -f $prop, $val)
                $shown = $true
            }
        }
        # The mode (managed-by-server vs policy) often lives on a nested object; surface it.
        foreach ($nested in 'OSPlatform','BackupObject','JobObjects') {
            $nv = $null
            try { $nv = $aj.$nested } catch { }
            if ($nv -ne $null -and "$nv" -ne '' -and 'JobType Type PolicyType BackupType Mode OSPlatform OsType BackupModeType' -notmatch $nested) {
                Write-Data ("    {0,-10} : {1}" -f $nested, $nv)
            }
        }
        if (-not $shown) {
            # Fall back to cross-referencing Get-VBRJob, which reliably reports JobType
            # (e.g. EpAgentBackup) for the same job by Id.
            $xref = $null
            try { $xref = Get-VBRJob | Where-Object { $_.Id -eq $aj.Id } | Select-Object -First 1 } catch { }
            if ($xref -and $xref.JobType) {
                Write-Data "    JobType    : $($xref.JobType)  (via Get-VBRJob)"
            } else {
                Write-Data "    (type properties not populated on this object — see B-5 Get-VBRJob for JobType)"
            }
        }
    }

    Test-GuidFilter -Label 'Get-VBRComputerBackupJob [Guid] Id filter' -Items $agentJobs

} else {
    Write-Pass "Get-VBRComputerBackupJob — 0 results (no managed agent policies, or none configured)"
    $script:Pass++
}


# ══════════════════════════════════════════════════════════════════════════════
#  B-7  Get-VBREPJob
#  Legacy standalone Veeam Agent backup jobs (EndpointBackup type).
#  Veeam Advisor flags these as legacy — migrate to managed policies (B-6).
# ══════════════════════════════════════════════════════════════════════════════
Write-Head "B-7: Get-VBREPJob — Legacy standalone agent jobs"

$epJobs = @()
try {
    $epJobs = @(Get-VBREPJob)
    Write-Pass "Get-VBREPJob runs without error"
    $script:Pass++
} catch {
    Write-Fail "Get-VBREPJob threw: $($_.Exception.Message)"
    $script:Fail++
}

if ($epJobs.Count -gt 0) {
    Write-Warn "Found $($epJobs.Count) LEGACY standalone agent job(s)"
    Write-Warn "  Best practice: migrate to managed agent policies (Get-VBRComputerBackupJob)"

    Assert "EP jobs: .Name exists on all" {
        @($epJobs | Where-Object { $null -eq $_.Name }).Count -eq 0
    }

    Write-Sub "Legacy agent jobs (recommend migration)"
    foreach ($ej in $epJobs) {
        Write-Data "  '$($ej.Name)' | Id: $($ej.Id)"
    }

    Test-GuidFilter -Label 'Get-VBREPJob [Guid] Id filter' -Items $epJobs

} else {
    Write-Pass "Get-VBREPJob — 0 results (no legacy standalone agent jobs — clean)"
    $script:Pass++
}


# ══════════════════════════════════════════════════════════════════════════════
#  B-8  Get-VBRCloudTenant
#  App pattern: Get-VBRCloudTenant | Where {$_.Id -eq [Guid]'...'} | Select Name
#  Only returns results on Cloud Connect Provider (VCSP) environments.
# ══════════════════════════════════════════════════════════════════════════════
Write-Head "B-8: Get-VBRCloudTenant — Cloud Connect tenants"

$tenants = @()
try {
    $tenants = @(Get-VBRCloudTenant)
    Write-Pass "Get-VBRCloudTenant runs without error"
    $script:Pass++
} catch {
    # On a non-VCSP server the cmdlet throws "Veeam Cloud Connect service provider
    # license is required" — this is EXPECTED, not a failure. Only a different error
    # is a genuine problem.
    if ($_.Exception.Message -match 'Cloud Connect service provider license') {
        Write-Pass "Get-VBRCloudTenant — Cloud Connect not licensed (expected on non-VCSP environments)"
        $script:Pass++
    } else {
        Write-Fail "Get-VBRCloudTenant threw: $($_.Exception.Message)"
        $script:Fail++
    }
}

if ($tenants.Count -gt 0) {
    Write-Info "Found $($tenants.Count) Cloud Connect tenant(s) — this is a VCSP environment"

    Assert "Tenants: .Name exists on all" {
        @($tenants | Where-Object { $null -eq $_.Name }).Count -eq 0
    }
    Assert "Tenants: .Id is [System.Guid] on all" {
        @($tenants | Where-Object { $_.Id -isnot [System.Guid] }).Count -eq 0
    }

    Write-Sub "Tenants"
    foreach ($t in $tenants) {
        $enabled = 'N/A'; $quota = 'N/A'
        try { $enabled = $t.Enabled } catch { }
        try { $quota = $t.Resources.BackupStorageQuota } catch { }
        Write-Data "  '$($t.Name)'"
        Write-Data "    Id      : $($t.Id)"
        Write-Data "    Enabled : $enabled"
        Write-Data "    Quota   : $quota"
    }

    Test-GuidFilter -Label 'Get-VBRCloudTenant [Guid] Id filter' -Items $tenants

} else {
    Write-Pass "Get-VBRCloudTenant — 0 results (expected on non-VCSP environments)"
    $script:Pass++
}


# ══════════════════════════════════════════════════════════════════════════════
#  B-9  Get-VBRBackupCopyJob
# ══════════════════════════════════════════════════════════════════════════════
Write-Head "B-9: Get-VBRBackupCopyJob — Backup copy jobs"

$copyJobs = @()
try {
    $copyJobs = @(Get-VBRBackupCopyJob)
    Write-Pass "Get-VBRBackupCopyJob runs without error"
    $script:Pass++
    Write-Info "Backup copy jobs: $($copyJobs.Count)"
    foreach ($cj in $copyJobs) {
        Write-Data "  '$($cj.Name)' | Id: $($cj.Id)"
    }
    if ($copyJobs.Count -eq 0) {
        Write-Warn "  No backup copy jobs — 3-2-1 rule may not be satisfied"
    }
} catch {
    Write-Fail "Get-VBRBackupCopyJob threw: $($_.Exception.Message)"
    $script:Fail++
}


# ══════════════════════════════════════════════════════════════════════════════
#  B-10 Get-VBRSureBackupJob
# ══════════════════════════════════════════════════════════════════════════════
Write-Head "B-10: Get-VBRSureBackupJob — Recovery verification jobs"

$sbJobs = @()
try {
    $sbJobs = @(Get-VBRSureBackupJob)
    Write-Pass "Get-VBRSureBackupJob runs without error"
    $script:Pass++
    Write-Info "SureBackup jobs: $($sbJobs.Count)"
    foreach ($sbj in $sbJobs) {
        Write-Data "  '$($sbj.Name)' | Id: $($sbj.Id)"
    }
    if ($sbJobs.Count -eq 0) {
        Write-Warn "  No SureBackup jobs — restore points are unverified"
    }
} catch {
    Write-Fail "Get-VBRSureBackupJob threw: $($_.Exception.Message)"
    $script:Fail++
}


# ══════════════════════════════════════════════════════════════════════════════
#  B-11 Get-VBRTapeJob
# ══════════════════════════════════════════════════════════════════════════════
Write-Head "B-11: Get-VBRTapeJob — Tape backup jobs"

$tapeJobs = @()
try {
    $tapeJobs = @(Get-VBRTapeJob)
    Write-Pass "Get-VBRTapeJob runs without error"
    $script:Pass++
    Write-Info "Tape jobs: $($tapeJobs.Count)"
    foreach ($tj in $tapeJobs) {
        Write-Data "  '$($tj.Name)' | Id: $($tj.Id)"
    }
} catch {
    Write-Fail "Get-VBRTapeJob threw: $($_.Exception.Message)"
    $script:Fail++
}


# ══════════════════════════════════════════════════════════════════════════════
#  B-12 Get-VBRUnstructuredBackupJob
#  Unstructured data: file (NAS) backup jobs and object storage backup jobs.
#  This is the modern cmdlet — Get-VBRNASBackupJob is obsolete and points here.
# ══════════════════════════════════════════════════════════════════════════════
Write-Head "B-12: Get-VBRUnstructuredBackupJob — Unstructured data (NAS/object storage) jobs"

$unstructJobs = @()
try {
    $unstructJobs = @(Get-VBRUnstructuredBackupJob)
    Write-Pass "Get-VBRUnstructuredBackupJob runs without error"
    $script:Pass++
    Write-Info "Unstructured data backup jobs: $($unstructJobs.Count)"

    if ($unstructJobs.Count -gt 0) {
        Assert "Unstructured jobs: .Name exists on all" {
            @($unstructJobs | Where-Object { $null -eq $_.Name }).Count -eq 0
        }

        foreach ($uj in $unstructJobs) {
            Write-Data "  '$($uj.Name)' | Id: $($uj.Id)"
        }

        Test-GuidFilter -Label 'Get-VBRUnstructuredBackupJob [Guid] Id filter' -Items $unstructJobs
    } else {
        Write-Pass "Get-VBRUnstructuredBackupJob — 0 results (no unstructured data jobs — clean)"
        $script:Pass++
    }
} catch {
    Write-Fail "Get-VBRUnstructuredBackupJob threw: $($_.Exception.Message)"
    $script:Fail++
}


# ══════════════════════════════════════════════════════════════════════════════
#  A-1  PROTECTION COVERAGE ANALYSIS
#  Mirrors the standalone app: compares infrastructure VM count against VMs
#  covered by backup jobs + agents, to publish the protection-gap picture.
# ══════════════════════════════════════════════════════════════════════════════
Write-Head "A-1: Protection Coverage Analysis"

# Discovered VMs in the virtual infrastructure (VMware + Hyper-V).
$infraVMs = 0
try {
    # Count VMs across all managed vSphere/Hyper-V servers.
    $viVMs = @(try { Find-VBRViEntity -VMsAndTemplates } catch { @() } )
    $viCount = @($viVMs | Where-Object { $_.Type -eq 'Vm' -or $_.VmHostName -or $_.Type -eq 'VirtualMachine' }).Count
    if ($viCount -eq 0) { $viCount = @($viVMs).Count }
} catch { $viCount = 0 }
try {
    $hvVMs = @(try { Find-VBRHvEntity } catch { @() })
    $hvCount = @($hvVMs | Where-Object { $_.Type -eq 'Vm' -or $_.Type -eq 'VirtualMachine' }).Count
    if ($hvCount -eq 0) { $hvCount = @($hvVMs).Count }
} catch { $hvCount = 0 }
$infraVMs = $viCount + $hvCount

# VMs covered by backup jobs — reuse $jobs from B-5. Sum object counts in each
# job's includes. This is an estimate (jobs may target containers / overlap).
$protectedVMs = 0
foreach ($j in @($jobs)) {
    try {
        $objs = @(Get-VBRJobObject -Job $j -ErrorAction Stop)
        $protectedVMs += @($objs).Count
    } catch {
        # Fallback: some job types expose GetObjectsInJob()
        try { $protectedVMs += @($j.GetObjectsInJob()).Count } catch { }
    }
}

# Agent-protected machines — managed agent jobs (B-6) + legacy agent jobs (B-7).
$agentProtected = @($agentJobs).Count + @($epJobs).Count

if ($infraVMs -gt 0) {
    $effProt = [Math]::Min($protectedVMs + $agentProtected, $infraVMs)
    $unprotected = [Math]::Max(0, $infraVMs - $effProt)
    $coveragePct = [Math]::Round($effProt / $infraVMs * 100)

    Write-Info "Infrastructure VMs discovered : $infraVMs (VMware $viCount + Hyper-V $hvCount)"
    Write-Data "  VMs in backup jobs (est.)   : $protectedVMs"
    Write-Data "  Agent-protected machines    : $agentProtected"
    Write-Data "  Effective protected (capped): $effProt"
    Write-Data "  Estimated coverage          : $coveragePct%"
    Write-Data "  Potentially unprotected     : $unprotected VM(s)"

    if ($coveragePct -lt 50) {
        # This is a CRITICAL finding about the ENVIRONMENT, not a script/cmdlet
        # assertion failure — flag it prominently but don't fail the validation run
        # (the tool worked correctly; it's the coverage that's low).
        Write-Host "  [CRITICAL FINDING] Coverage ~$coveragePct% — $unprotected VM(s) may be unprotected" -ForegroundColor Red
        Add-Content -Path $script:LogFile -Value "  [CRITICAL FINDING] Coverage ~$coveragePct% — $unprotected VM(s) may be unprotected" -Encoding UTF8
        $script:Findings++
    } elseif ($coveragePct -lt 90) {
        Write-Warn "Coverage ~$coveragePct% — $unprotected VM(s) may be unprotected"
    } else {
        Write-Pass "Coverage ~$coveragePct% — protection looks complete"
        $script:Pass++
    }
    Write-Info "  NOTE: estimate only. Verify exact gaps with the Veeam ONE Protected VMs report."
} else {
    Write-Warn "Could not determine infrastructure VM count — coverage analysis skipped"
    $script:Skip++
}


# ══════════════════════════════════════════════════════════════════════════════
#  A-2  ORPHANED / DISABLED JOB DETECTION
#  Jobs that are disabled or have no objects create no restore points.
# ══════════════════════════════════════════════════════════════════════════════
Write-Head "A-2: Orphaned / Disabled Job Detection"

$orphaned = [System.Collections.Generic.List[string]]::new()
foreach ($j in @($jobs)) {
    $enabled = $true
    try { $enabled = $j.IsScheduleEnabled } catch { try { $enabled = $j.ScheduleOptions.Enabled } catch { $enabled = $true } }
    $objCount = -1
    try { $objCount = @(Get-VBRJobObject -Job $j -ErrorAction Stop).Count } catch { }
    $reason = $null
    if (-not $enabled -and $objCount -eq 0) { $reason = 'Disabled + empty' }
    elseif (-not $enabled)                  { $reason = 'Schedule disabled' }
    elseif ($objCount -eq 0)                { $reason = 'No objects assigned' }
    if ($reason) {
        $orphaned.Add("$($j.Name) [$reason]")
    }
}

if ($orphaned.Count -gt 0) {
    Write-Warn "$($orphaned.Count) orphaned/disabled job(s) — these create no restore points:"
    foreach ($o in $orphaned) { Write-Data "  $o" }
    Write-Info "  Re-enable, assign objects, or remove (confirm nothing depends on it first)."
} else {
    Write-Pass "No orphaned or disabled jobs detected"
    $script:Pass++
}


# ══════════════════════════════════════════════════════════════════════════════
#  DISCONNECT
# ══════════════════════════════════════════════════════════════════════════════
Write-Sub "Disconnecting from VBR"
try {
    # Only disconnect if we connected ourselves (not a pre-existing session on localhost)
    $currentSession = Get-VBRServerSession
    if ($currentSession -and $VBRServer -ne 'localhost') {
        Disconnect-VBRServer
        Write-Pass "Disconnected from $VBRServer"
        $script:Pass++
    } else {
        Write-Info "Pre-existing session retained (localhost)"
    }
} catch {
    Write-Warn "Disconnect: $($_.Exception.Message)"
}


# ══════════════════════════════════════════════════════════════════════════════
#  FINAL SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
Write-Head "RESULTS — Veeam Advisor VBR Validation"

$total = $script:Pass + $script:Fail + $script:Skip
Out-Log ''
Out-Log "  PASSED  : $($script:Pass)"  -Colour $(if ($script:Pass -gt 0) { 'Green'  } else { 'White' })
Out-Log "  FAILED  : $($script:Fail)"  -Colour $(if ($script:Fail -gt 0) { 'Red'    } else { 'Green' })
Out-Log "  SKIPPED : $($script:Skip)"  -Colour $(if ($script:Skip -gt 0) { 'Yellow' } else { 'White' })
Out-Log "  TOTAL   : $total"           -Colour White
if ($script:Findings -gt 0) {
    Out-Log ''
    Out-Log "  ENVIRONMENT FINDINGS : $($script:Findings) (advisory — see [CRITICAL FINDING] above)" -Colour Red
}
Out-Log ''

if ($script:Fails.Count -gt 0) {
    Out-Log "  Failed assertions:" -Colour Red
    foreach ($f in $script:Fails) {
        Out-Log "    ✗ $f" -Colour Red
    }
    Out-Log ''
}

$resultText = if ($script:Fail -eq 0) { 'ALL ASSERTIONS PASSED' } else { "$($script:Fail) ASSERTION(S) FAILED" }
Out-Log "  RESULT: $resultText" -Colour $(if ($script:Fail -eq 0) { 'Green' } else { 'Red' })

# Write clean summary block to log file
@(
    ''
    '----------------------------------------------------------------------'
    '  SUMMARY'
    '----------------------------------------------------------------------'
    "  Completed : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    "  VBR Server: $VBRServer"
    "  PASSED    : $($script:Pass)"
    "  FAILED    : $($script:Fail)"
    "  SKIPPED   : $($script:Skip)"
    "  TOTAL     : $total"
    $(if ($script:Findings -gt 0) { "  ENV FINDINGS: $($script:Findings) (advisory)" })
    ''
) | Add-Content -Path $script:LogFile -Encoding UTF8

if ($script:Fails.Count -gt 0) {
    "  FAILED ASSERTIONS:" | Add-Content -Path $script:LogFile -Encoding UTF8
    foreach ($f in $script:Fails) {
        "    - $f" | Add-Content -Path $script:LogFile -Encoding UTF8
    }
    '' | Add-Content -Path $script:LogFile -Encoding UTF8
}

"  RESULT: $resultText"  | Add-Content -Path $script:LogFile -Encoding UTF8
'======================================================================' | Add-Content -Path $script:LogFile -Encoding UTF8
''                        | Add-Content -Path $script:LogFile -Encoding UTF8

Out-Log ''
Out-Log "  Full results saved to: $($script:LogFile)" -Colour DarkGray
Out-Log ''

if ($script:Fail -gt 0) { exit 1 } else { exit 0 }
