#Requires -Version 5.1
<#
CyberPatriot Windows 11 fixed-items launcher. DEFAULT: Apply (modifies eligible fixed policies).
Right-click THIS file -> Run with PowerShell, not the _Core.ps1 file.
The window waits for ENTER even when an error occurs after the launcher begins.
If Windows blocks a .ps1 before it starts, use 01_Apply_KEEP_OPEN.cmd instead.
#>
[CmdletBinding()]
param([ValidateSet('Apply','Audit')][string]$Mode='Apply')
$ErrorActionPreference='Stop'
$launchedAsAdmin=$false
$transcriptStarted=$false
$traceFile=$null

try {
    Write-Host '==========================================================' -ForegroundColor Cyan
    Write-Host ' CyberPatriot Windows 11 Fixed v3 - KEEP WINDOW OPEN' -ForegroundColor Cyan
    Write-Host (' Mode: '+$Mode+'  (Apply=make changes, Audit=check only)') -ForegroundColor Yellow
    Write-Host '==========================================================' -ForegroundColor Cyan
    $core = Join-Path $PSScriptRoot 'CyberPatriot_Win11_Fixed_v3_Core.ps1'
    if (-not (Test-Path -LiteralPath $core)) {
        throw ('Core file missing! Extract the whole ZIP to ONE folder. Expected: '+$core)
    }
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($id)
    $launchedAsAdmin=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $launchedAsAdmin) {
        Write-Host '[INFO] Not elevated. Requesting administrator permission (UAC)...' -ForegroundColor Yellow
        # Use -NoExit to keep the *elevated* console on screen even if parser fails.
        $quotedScript='"'+$PSCommandPath.Replace('"','')+'"'
        $argsLine='-NoExit -NoProfile -ExecutionPolicy Bypass -File '+$quotedScript+' -Mode '+$Mode
        Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -ArgumentList $argsLine -ErrorAction Stop | Out-Null
        Write-Host '[INFO] Opened an elevated PowerShell window. Check THAT window for results.' -ForegroundColor Green
        Write-Host 'If no elevated window appeared, verify the Windows UAC prompt was accepted.' -ForegroundColor Yellow
    } else {
        $base=Join-Path $env:ProgramData 'CyberPatriotFixed'
        if (-not (Test-Path -LiteralPath $base)) { New-Item -ItemType Directory -Path $base -Force -ErrorAction Stop | Out-Null }
        $traceFile=Join-Path $base ('launcher_v3_'+(Get-Date -Format 'yyyyMMdd_HHmmss_fff')+'.txt')
        Start-Transcript -LiteralPath $traceFile -ErrorAction Stop | Out-Null
        $transcriptStarted=$true
        Write-Host ('[INFO] Launcher log: '+$traceFile) -ForegroundColor Gray
        Write-Host ('[START] Running Core, Mode='+$Mode+' ...') -ForegroundColor Green
        # Invocation through &, not a new transient PowerShell process.
        & $core -Mode $Mode
        Write-Host '[DONE] Core returned to launcher. Inspect the summary above.' -ForegroundColor Cyan
        Write-Host '[NOTE] Score changes require validation in the competition Scoring Report.' -ForegroundColor Yellow
    }
} catch {
    Write-Host ''
    Write-Host '[LAUNCH ERROR] The launcher failed:' -ForegroundColor Red
    Write-Host ($_ | Out-String) -ForegroundColor Red
    Write-Host 'For machine-policy/AV script blocks, use the .cmd file; it always has PAUSE.' -ForegroundColor Yellow
} finally {
    if ($transcriptStarted) {
        try { Stop-Transcript -ErrorAction Stop | Out-Null } catch { Write-Host ('Transcript stop failed: '+$_.Exception.Message) -ForegroundColor Yellow }
    }
    if ($traceFile) { Write-Host ('Launcher log: '+$traceFile) }
    Write-Host ''
    Write-Host 'The window is intentionally kept open for diagnosis.' -ForegroundColor Cyan
    Write-Host 'Press ENTER only after reading results or taking a screenshot.' -ForegroundColor Yellow
    try { [void](Read-Host 'Press ENTER to close this script') } catch {
        Write-Host 'No interactive stdin available. Use 01_Apply_KEEP_OPEN.cmd.' -ForegroundColor Yellow
    }
}