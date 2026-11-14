#Requires -Version 5.1
<#
 CyberPatriot - Windows 11 fixed checks (standalone workstation)
 Default: report only (Audit DOES NOT CHANGE OR SCORE). -Mode Apply: backup first, then apply selected fixed settings.
 -Mode Restore -BackupPath <directory>: restore captured local settings.
 Does NOT remove accounts, shares, apps, forensic evidence, or critical services.
 Use Run_CyberPatriot_Apply.cmd to launch an administrator console that stays open.
 Author's intent: minimize changes outside stable, repeatable hardening actions.

 Examples (run in an elevated Windows PowerShell 5.1 console):
   .\CyberPatriot_Win11_Fixed_v2.ps1
   .\CyberPatriot_Win11_Fixed_v2.ps1 -Mode Apply
   .\CyberPatriot_Win11_Fixed_v2.ps1 -Mode Apply -MinPasswordLength 30
   .\CyberPatriot_Win11_Fixed_v2.ps1 -Mode Restore -BackupPath 'C:\ProgramData\CyberPatriotFixed\20261113_180000'
#>
[CmdletBinding()]
param(
    [ValidateSet('Audit','Apply','Restore')][string]$Mode = 'Audit',
    [ValidateRange(8,128)][int]$MinPasswordLength = 14,
    [string]$BackupPath = '',
    [switch]$UpdateSignatures,
    [switch]$QuickScan,
    [switch]$DisableRemoteRegistry,
    [switch]$DisableLegacyFeatures
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# All checks report to the screen and run.log, including failures.
$script:Results = New-Object 'System.Collections.Generic.List[object]'
$script:StepNumber = 0
$script:Phase = 0
$script:PhaseCount = 5
$script:LogFile = $null
function Log([string]$Message, [string]$Level = 'INFO') {
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'HH:mm:ss'),$Level,$Message
    Write-Host $line
    if ($script:LogFile) { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 }
}
function Phase([int]$Number, [string]$Name) {
    $script:Phase = $Number
    $pct = [int][math]::Min(98, (($Number - 1) * 100 / $script:PhaseCount))
    Write-Host ""
    Write-Host ("=" * 73) -ForegroundColor Cyan
    Write-Host ("  Phase {0}/{1}: {2}" -f $Number, $script:PhaseCount, $Name) -ForegroundColor Cyan
    Write-Host ("=" * 73) -ForegroundColor Cyan
    Write-Progress -Activity 'CyberPatriot Windows 11 fixed checks' -Status "Phase $Number/$($script:PhaseCount): $Name" -PercentComplete $pct
    if ($script:LogFile) { Add-Content -LiteralPath $script:LogFile -Value "PHASE $Number/$($script:PhaseCount): $Name" -Encoding UTF8 }
}
function Result([string]$Name,[string]$State,[string]$Detail) {
    $script:StepNumber++
    $script:Results.Add([pscustomobject]@{No=$script:StepNumber;Item=$Name;State=$State;Detail=$Detail}) | Out-Null
    $color = switch ($State) {
        {$_ -in @('OK','Verified','Changed','Done')} {'Green';break}
        'Error' {'Red';break}
        {$_ -in @('Skipped','Review','Check','Not changed')} {'Yellow';break}
        default {'Gray'}
    }
    $label = switch ($State) {
        'Verified' {'已验证/Verified'}
        'OK' {'已符合/OK'}
        'Changed' {'已修改/Changed'}
        'Done' {'完成/Done'}
        'Checked' {'仅检查/Checked'}
        'Review' {'待核对/Review'}
        'Check' {'需检查/Check'}
        'Skipped' {'已跳过/Skipped'}
        'Not changed' {'未修改/Not changed'}
        'Error' {'失败/Error'}
        default {$State}
    }
    $headline="[{0:00}] [{1}] {2}" -f $script:StepNumber, $label, $Name
    Write-Host $headline -ForegroundColor $color
    Write-Host "     $Detail"
    if ($script:LogFile) {
        Add-Content -LiteralPath $script:LogFile -Value ("{0} | {1}" -f $headline,$Detail) -Encoding UTF8
    }
    if ($script:Phase -ge 1) {
        Write-Progress -Activity 'CyberPatriot Windows 11 fixed checks' -Status "Phase $($script:Phase)/$($script:PhaseCount): $Name" -CurrentOperation "$State - item $($script:StepNumber)" -PercentComplete ([int][math]::Min(99,((($script:Phase - 1) * 100 + 60) / $script:PhaseCount)))
    }
}
function Run-Native([string]$File,[string[]]$Arguments) {
    Log "Running: $File $($Arguments -join ' ')" 'CMD'
    $output = & $File @Arguments 2>&1
    $code = $LASTEXITCODE
    foreach ($line in @($output)) { if ($null -ne $line) { Log ([string]$line) 'CMD' } }
    if ($code -ne 0) { throw "$File failed (exit code $code). See run.log and related security logs." }
}
function Get-RegistryValue([string]$Path,[string]$Name) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{Path=$Path;Name=$Name;Exists=$false;Value=$null;Kind='DWord'}
    }
    $key=Get-Item -LiteralPath $Path
    if ($key.GetValueNames() -contains $Name) {
        return [pscustomobject]@{Path=$Path;Name=$Name;Exists=$true;Value=$key.GetValue($Name);Kind=([string]$key.GetValueKind($Name))}
    }
    return [pscustomobject]@{Path=$Path;Name=$Name;Exists=$false;Value=$null;Kind='DWord'}
}
function Set-DWord([string]$Path,[string]$Name,[int]$Value) {
    $old=Get-RegistryValue $Path $Name
    if ($old.Exists -and [int]$old.Value -eq $Value) { Result "Registry: $Name" 'OK' "Already $Value"; return }
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
    $actual=Get-RegistryValue $Path $Name
    if ($actual.Exists -and [int]$actual.Value -eq $Value) {
        Result "Registry: $Name" 'Verified' "Readback=$Value (previous=$($old.Value))"
    } else { Result "Registry: $Name" 'Error' "Readback mismatch: expected $Value; actual=$($actual.Value)" }
}
function Set-OptionalService([string]$Name,[string]$StartupType) {
    $service=Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $service) { Result "Service: $Name" 'Skipped' 'Not installed'; return }
    Set-Service -Name $Name -StartupType $StartupType
    Result "Service: $Name" 'Changed' "StartupType=$StartupType (service not force-stopped)"
}
function Collect-SoftwareReport([string]$Folder) {
    $entries = New-Object System.Collections.Generic.List[object]
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach($root in $roots) {
        $all=@(Get-ItemProperty -Path $root -ErrorAction SilentlyContinue)
        foreach($app in $all) {
            if (-not $app.DisplayName) { continue }
            $name=[string]$app.DisplayName
            if ($name -match '(?i)nmap|zenmap|ccleaner|bittorrent|utorrent|qbittorrent|brutus|john the ripper|hashcat|steam|epic games launcher|battle\.net|roblox|minecraft|wireshark|chrome|firefox|inkscape') {
                $decision = if ($name -match '(?i)wireshark') { 'KEEP unless README says otherwise' }
                            elseif ($name -match '(?i)chrome|firefox|inkscape') { 'UPDATE IN PLACE / CHECK README' }
                            else { 'REVIEW README BEFORE REMOVAL' }
                $entries.Add([pscustomobject]@{Name=$name;Version=$app.DisplayVersion;Publisher=$app.Publisher;Disposition=$decision}) | Out-Null
            }
        }
    }
    $file=Join-Path $Folder 'software-review.csv'
    if ($entries.Count -gt 0) {
        $entries | Sort-Object Name -Unique | Export-Csv -LiteralPath $file -Encoding UTF8 -NoTypeInformation
    } else { Set-Content -LiteralPath $file -Value 'Name,Version,Publisher,Disposition' -Encoding UTF8 }
    Result 'Installed software review' 'Review' "$($entries.Count) relevant entries. See $file. Nothing uninstalled."
    foreach($e in @($entries | Sort-Object Name -Unique | Select-Object -First 20)) {
        Write-Host ("     REVIEW APP: {0} | {1}" -f $e.Name,$e.Disposition) -ForegroundColor Yellow
    }
}
function Collect-DesktopReport([string]$Folder) {
    $found=New-Object System.Collections.Generic.List[object]
    $dirs=New-Object System.Collections.Generic.List[string]
    if (Test-Path "$env:SystemDrive\Users") {
        foreach($profile in @(Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue)) {
            $desktop=Join-Path $profile.FullName 'Desktop'
            if (Test-Path -LiteralPath $desktop) { $dirs.Add($desktop) | Out-Null }
        }
    }
    if (Test-Path "$env:PUBLIC\Desktop") { $dirs.Add("$env:PUBLIC\Desktop") | Out-Null }
    if (Test-Path "$env:PUBLIC\Downloads") { $dirs.Add("$env:PUBLIC\Downloads") | Out-Null }
    foreach($dir in @($dirs | Sort-Object -Unique)) {
        foreach($file in @(Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue)) {
            if ($file.Extension -match '(?i)^\.(exe|com|scr|msi|bat|cmd|ps1|vbs|js|zip|rar|7z)$') {
                $found.Add([pscustomobject]@{Path=$file.FullName;Extension=$file.Extension;Size=$file.Length;LastWrite=$file.LastWriteTime;Disposition='REVIEW BEFORE DELETE OR QUARANTINE'}) | Out-Null
            }
        }
    }
    $file=Join-Path $Folder 'desktop-files-review.csv'
    if ($found.Count -gt 0) {
        $found | Export-Csv -LiteralPath $file -Encoding UTF8 -NoTypeInformation
    } else { Set-Content -LiteralPath $file -Value 'Path,Extension,Size,LastWrite,Disposition' -Encoding UTF8 }
    Result 'Desktop suspicious file review' 'Review' "$($found.Count) files listed in $file. No files deleted or moved."
    foreach($e in @($found | Select-Object -First 20)) {
        Write-Host ("     REVIEW FILE: {0}" -f $e.Path) -ForegroundColor Yellow
    }
}
function Collect-ReadOnlyChecks([string]$Folder) {
    try {
        $passText=(& net.exe accounts | Out-String)
        $passText | Set-Content -LiteralPath (Join-Path $Folder 'password-summary.txt') -Encoding UTF8
        if ($LASTEXITCODE -ne 0) { throw "net.exe accounts exit code $LASTEXITCODE" }
        Result 'Password summary' 'Checked' 'Current values saved in password-summary.txt; check scoring separately'
    } catch { Result 'Password summary' 'Error' $_.Exception.Message }
    try {
        Get-NetFirewallProfile -ErrorAction Stop |
            Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction |
            Export-Csv (Join-Path $Folder 'firewall-report.csv') -NoTypeInformation -Encoding UTF8
        Result 'Firewall profiles' 'Checked' 'See firewall-report.csv'
    } catch { Result 'Firewall profiles' 'Error' $_.Exception.Message }
    try {
        $status=Get-MpComputerStatus -ErrorAction Stop
        $status | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,IsTamperProtected |
            Format-List | Out-File -FilePath (Join-Path $Folder 'defender-status.txt') -Encoding UTF8
        $pref=Get-MpPreference -ErrorAction Stop
        $pref | Select-Object ExclusionPath,ExclusionExtension,ExclusionProcess |
            Format-List | Out-File -FilePath (Join-Path $Folder 'defender-exclusions-REVIEW.txt') -Encoding UTF8
        Result 'Defender checks' 'Checked' 'Status and exclusions saved; exclusions NOT removed'
    } catch { Result 'Defender checks' 'Error' $_.Exception.Message }
    try {
        (& auditpol.exe /get '/category:*' | Out-String) | Out-File (Join-Path $Folder 'audit-policy.txt') -Encoding UTF8
        if ($LASTEXITCODE -ne 0) { throw "auditpol.exe exit code $LASTEXITCODE" }
        Result 'Audit policies report' 'Checked' 'Full audit policy saved in audit-policy.txt'
    } catch { Result 'Audit policies report' 'Error' $_.Exception.Message }
    try {
        Get-SmbShare -ErrorAction Stop | Select-Object Name,Path,Description,Special |
            Export-Csv (Join-Path $Folder 'shares-README-check.csv') -NoTypeInformation -Encoding UTF8
        Result 'Network shares' 'Review' 'See shares-README-check.csv; no shares changed'
    } catch { Result 'Network shares' 'Error' $_.Exception.Message }
    try {
        Get-LocalUser | Select-Object Name,Enabled,Description |
            Export-Csv (Join-Path $Folder 'users-README-check.csv') -NoTypeInformation -Encoding UTF8
        Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop |
            Select-Object Name,ObjectClass,PrincipalSource |
            Export-Csv (Join-Path $Folder 'admins-README-check.csv') -NoTypeInformation -Encoding UTF8
        Result 'Local users and admins' 'Review' 'Two CSV lists produced; no accounts changed'
    } catch { Result 'Local users and admins' 'Review' "Manual verification required: $($_.Exception.Message)" }
}
function Backup-CurrentState([string]$Folder, [object[]]$RegTargets) {
    Log 'Exporting security policy and audit policy before any changes'
    Run-Native 'secedit.exe' @('/export','/cfg',(Join-Path $Folder 'security-before.inf'),'/areas','SECURITYPOLICY','/quiet')
    Run-Native 'auditpol.exe' @('/backup',('/file:'+(Join-Path $Folder 'audit-before.csv')))
    Get-NetFirewallProfile | Select-Object Name,Enabled |
        ConvertTo-Json -Depth 5 | Set-Content (Join-Path $Folder 'firewall-before.json') -Encoding UTF8
    $registry=foreach($x in $RegTargets) { Get-RegistryValue $x.Path $x.Name }
    @($registry) | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $Folder 'registry-before.json') -Encoding UTF8
    $r=Get-Service -Name 'RemoteRegistry' -ErrorAction SilentlyContinue
    $startup='Unknown'
    if ($null -ne $r) {
        try { $startup=[string](Get-CimInstance Win32_Service -Filter "Name='RemoteRegistry'").StartMode } catch {}
    }
    [pscustomobject]@{Exists=($null -ne $r);StartMode=$startup} |
        ConvertTo-Json | Set-Content (Join-Path $Folder 'remote-registry-before.json') -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $Folder 'backup-complete.marker') -Value 'Captured before Apply' -Encoding ASCII
    Log "Backup saved: $Folder"
    Result 'Backup before Apply' 'Verified' "Security policy, audit policy, firewall and registry exported: $Folder"
}
function Restore-CurrentState([string]$Folder) {
    if (-not (Test-Path (Join-Path $Folder 'backup-complete.marker'))) { throw 'No verified backup marker at the supplied BackupPath.' }
    if (-not (Test-Path (Join-Path $Folder 'security-before.inf'))) { throw 'Missing security-before.inf' }
    Log 'Restoring local security policy from exported template'
    Run-Native 'secedit.exe' @('/configure','/db',(Join-Path $Folder 'restore.sdb'),'/cfg',(Join-Path $Folder 'security-before.inf'),'/overwrite','/areas','SECURITYPOLICY','/log',(Join-Path $Folder 'restore-security.log'),'/quiet')
    Run-Native 'auditpol.exe' @('/restore',('/file:'+(Join-Path $Folder 'audit-before.csv')))
    foreach($e in @(Get-Content -LiteralPath (Join-Path $Folder 'registry-before.json') -Raw | ConvertFrom-Json)) {
        if ($e.Exists) {
            if (-not (Test-Path -LiteralPath $e.Path)) { New-Item -Path $e.Path -Force | Out-Null }
            New-ItemProperty -Path $e.Path -Name $e.Name -PropertyType ([string]$e.Kind) -Value $e.Value -Force | Out-Null
        } elseif (Test-Path -LiteralPath $e.Path) {
            Remove-ItemProperty -Path $e.Path -Name $e.Name -ErrorAction SilentlyContinue
        }
    }
    foreach($profile in @(Get-Content -LiteralPath (Join-Path $Folder 'firewall-before.json') -Raw | ConvertFrom-Json)) {
        $wasEnabled = ([string]$profile.Enabled -eq 'True')
        Set-NetFirewallProfile -Profile $profile.Name -Enabled $wasEnabled
    }
    $rr = Get-Content -LiteralPath (Join-Path $Folder 'remote-registry-before.json') -Raw | ConvertFrom-Json
    if ($rr.Exists) {
        switch([string]$rr.StartMode) {
            'Auto' { Set-Service -Name RemoteRegistry -StartupType Automatic }
            'Manual' { Set-Service -Name RemoteRegistry -StartupType Manual }
            'Disabled' { Set-Service -Name RemoteRegistry -StartupType Disabled }
        }
    }
    Log 'Restore attempted. Defender protection/updates and optional features require manual verification.'
    Result 'Restore' 'Done' 'Review results; policy may require sign-out or restart.'
}

# --- prepare report FIRST; even a preflight failure must be visible and saved ---
$root=Join-Path $env:ProgramData 'CyberPatriotFixed'
if (-not (Test-Path -LiteralPath $root)) { New-Item -Path $root -ItemType Directory -Force | Out-Null }
$stamp=Get-Date -Format 'yyyyMMdd_HHmmss_fff'
$session=Join-Path $root $stamp
New-Item -Path $session -ItemType Directory -Force | Out-Null
$script:LogFile=Join-Path $session 'run.log'
Phase 1 'System and permissions checks (Preflight)'
Log "CyberPatriot Windows 11 Fixed v2 - Mode=$Mode - Session=$session"
$preflightOK=$true
try {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=[Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Not elevated. Use Run_CyberPatriot_Apply.cmd and accept the UAC prompt.'
    }
    $os=Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    if (([int]$os.BuildNumber -lt 22000) -or ($os.Caption -notmatch 'Windows 11')) {
        throw "Only Windows 11 is supported. Found: $($os.Caption), build $($os.BuildNumber)"
    }
    if ($Mode -eq 'Restore' -and [string]::IsNullOrWhiteSpace($BackupPath)) {
        throw 'Restore requires -BackupPath pointing to a verified session folder.'
    }
    $cs=Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ($Mode -eq 'Apply' -and $cs.PartOfDomain) {
        throw 'Domain joined: local policy can conflict with domain GPO. Use Audit mode.'
    }
    Result 'System and permissions' 'Verified' "Mode=$Mode; $($os.Caption); build=$($os.BuildNumber); Admin=Yes; Domain=$($cs.PartOfDomain)"
} catch {
    $preflightOK=$false
    Result 'System and permissions' 'Error' $_.Exception.Message
}
if (-not $preflightOK) {
    $script:Results | Export-Csv -LiteralPath (Join-Path $session 'summary.csv') -Encoding UTF8 -NoTypeInformation
    Write-Host "PRECHECK FAILED. No changes were made. Log: $session" -ForegroundColor Red
    Write-Progress -Activity 'CyberPatriot Windows 11 fixed checks' -Completed
    Write-Host 'Press ENTER to close this PowerShell window.' -ForegroundColor Yellow
    try { [void](Read-Host 'Press ENTER') } catch {}
    return
}

$regTargets=@(
    @{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced';Name='HideFileExt';Desired=0},
    @{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced';Name='Hidden';Desired=1},
    @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';Name='LimitBlankPasswordUse';Desired=1},
    @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';Name='RestrictAnonymousSAM';Desired=1},
    @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';Name='EveryoneIncludesAnonymous';Desired=0},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';Name='EnableLUA';Desired=1},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';Name='PromptOnSecureDesktop';Desired=1},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';Name='ConsentPromptBehaviorAdmin';Desired=2},
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';Name='ConsentPromptBehaviorUser';Desired=1},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU';Name='NoAutoUpdate';Desired=0},
    @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU';Name='AUOptions';Desired=3}
)
if ($MinPasswordLength -gt 14) {
    $regTargets+=@{Path='HKLM:\SYSTEM\CurrentControlSet\Control\SAM';Name='RelaxMinimumPasswordLengthLimits';Desired=1}
}

try {
    if ($Mode -eq 'Restore') {
        Phase 2 'Restore from backup'
        Restore-CurrentState -Folder $BackupPath
    } else {
        Phase 2 'Backup before change / read-only mode'
        if ($Mode -eq 'Apply') { Backup-CurrentState -Folder $session -RegTargets $regTargets }
        else { Result 'Backup' 'Skipped' 'Audit only: no changes; no backup needed' }
        Phase 3 'Applying or checking fixed security policies'
        if ($Mode -eq 'Audit') { Log 'AUDIT MODE: READ ONLY. No score change is expected!' 'WARN' }
        foreach($entry in $regTargets) {
            try {
                if ($Mode -eq 'Apply') { Set-DWord -Path $entry.Path -Name $entry.Name -Value ([int]$entry.Desired) }
                else {
                    $current=Get-RegistryValue $entry.Path $entry.Name
                    $state=if($current.Exists -and [int]$current.Value -eq [int]$entry.Desired){'OK'}else{'Check'}
                    $value=if($current.Exists){[string]$current.Value}else{'Not configured'}
                    Result "Registry: $($entry.Name)" $state "Now=$value; target=$($entry.Desired)"
                }
            } catch { Result "Registry: $($entry.Name)" 'Error' $_.Exception.Message }
        }
        if ($Mode -eq 'Apply') {
            $canSetPasswordPolicy = $true
            if ($MinPasswordLength -gt 14) {
                $checkRelax = Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SAM' 'RelaxMinimumPasswordLengthLimits'
                if (-not $checkRelax.Exists -or [int]$checkRelax.Value -ne 1) {
                    Result 'Long password length precondition' 'Error' 'RelaxMinimumPasswordLengthLimits was not enabled. Skipping password policy to avoid an inconsistent configuration.'
                    $canSetPasswordPolicy = $false
                }
            }
            # Partial secedit template: no users/groups, permissions, or services touched.
            $inf = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
PasswordHistorySize = 12
MaximumPasswordAge = 30
MinimumPasswordAge = 10
MinimumPasswordLength = $MinPasswordLength
PasswordComplexity = 1
ClearTextPassword = 0
LockoutBadCount = 5
ResetLockoutCount = 30
LockoutDuration = 30
"@
            $cfg=Join-Path $session 'fixed-password-policy.inf'
            $inf | Set-Content -LiteralPath $cfg -Encoding Unicode
            if ($canSetPasswordPolicy) {
                try {
                    Run-Native 'secedit.exe' @('/validate',$cfg)
                    Run-Native 'secedit.exe' @('/configure','/db',(Join-Path $session 'fixedpolicy.sdb'),'/cfg',$cfg,'/overwrite','/areas','SECURITYPOLICY','/log',(Join-Path $session 'secedit-apply.log'),'/quiet')
                    $after = Join-Path $session 'security-after.inf'
                    Run-Native 'secedit.exe' @('/export','/cfg',$after,'/areas','SECURITYPOLICY','/quiet')
                    $actual=Get-Content -LiteralPath $after -Raw
                    $expected=@{
                        'PasswordHistorySize'='12'; 'MaximumPasswordAge'='30'; 'MinimumPasswordAge'='10';
                        'MinimumPasswordLength'=[string]$MinPasswordLength; 'PasswordComplexity'='1';
                        'ClearTextPassword'='0'; 'LockoutBadCount'='5';
                        'ResetLockoutCount'='30'; 'LockoutDuration'='30'
                    }
                    $missing=New-Object 'System.Collections.Generic.List[string]'
                    foreach($k in $expected.Keys) {
                        $pattern='(?m)^\s*'+[regex]::Escape($k)+'\s*=\s*'+[regex]::Escape($expected[$k])+'\s*$'
                        if ($actual -notmatch $pattern) { $missing.Add("$k=$($expected[$k])") | Out-Null }
                    }
                    if ($missing.Count -eq 0) {
                        Result 'Password and lockout policies' 'Verified' "All nine exported values match; min=$MinPasswordLength; lockout 5/30/30."
                    } else {
                        Result 'Password and lockout policies' 'Review' "Apply returned success but exported values differ: $($missing -join ', ')"
                    }
                } catch { Result 'Password and lockout policies' 'Error' $_.Exception.Message }
            }
            try {
                Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -ErrorAction Stop
                $fw=@(Get-NetFirewallProfile -Name Domain,Private,Public -ErrorAction Stop)
                $disabled=@($fw | Where-Object { -not $_.Enabled })
                if ($fw.Count -eq 3 -and $disabled.Count -eq 0) {
                    Result 'Windows Firewall' 'Verified' 'Domain, Private and Public all Enabled=True; firewall rules preserved'
                } else { Result 'Windows Firewall' 'Error' "Readback failed. Disabled profiles: $($disabled.Name -join ', ')" }
            } catch { Result 'Windows Firewall' 'Error' $_.Exception.Message }
            foreach($audit in @(
                @{Name='Security State Change';Success='enable';Failure='enable'},
                @{Name='Security Group Management';Success='enable';Failure='enable'},
                @{Name='User Account Management';Success='enable';Failure='enable'},
                @{Name='Logon';Success='enable';Failure='enable'}
            )) {
                try {
                    Run-Native 'auditpol.exe' @('/set',('/subcategory:'+$audit.Name),('/success:'+$audit.Success),('/failure:'+$audit.Failure))
                    $auditReadback=(& auditpol.exe /get (('/subcategory:'+$audit.Name)) /r 2>&1 | Out-String)
                    if ($LASTEXITCODE -ne 0) {
                        Result "Audit: $($audit.Name)" 'Review' "Set command succeeded, but verification command failed (exit $LASTEXITCODE)"
                    } elseif ($auditReadback -match 'Success and Failure') {
                        Result "Audit: $($audit.Name)" 'Verified' 'Success and Failure confirmed by auditpol /get'
                    } else {
                        Result "Audit: $($audit.Name)" 'Review' "Set succeeded but readback not recognized: $($auditReadback.Trim())"
                    }
                } catch { Result "Audit: $($audit.Name)" 'Error' $_.Exception.Message }
            }
            try {
                if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
                    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
                    $mp=Get-MpComputerStatus -ErrorAction Stop
                    if ($mp.RealTimeProtectionEnabled) {
                        Result 'Defender realtime protection' 'Verified' 'RealTimeProtectionEnabled=True after request'
                    } else {
                        Result 'Defender realtime protection' 'Review' 'Enable command succeeded but protection is still not active (tamper protection, third-party AV, or policy may apply)'
                    }
                } else { Result 'Defender realtime protection' 'Skipped' 'Cmdlet unavailable' }
            } catch { Result 'Defender realtime protection' 'Error' $_.Exception.Message }
            if ($UpdateSignatures) {
                try { Update-MpSignature -ErrorAction Stop; Result 'Defender signatures' 'Done' 'Update requested' }
                catch { Result 'Defender signatures' 'Error' $_.Exception.Message }
            } else { Result 'Defender signature update' 'Skipped' 'Opt-in only: -UpdateSignatures (network may be unavailable)' }
            if ($QuickScan) {
                try { Start-MpScan -ScanType QuickScan -ErrorAction Stop; Result 'Defender quick scan' 'Done' 'Scan requested' }
                catch { Result 'Defender quick scan' 'Error' $_.Exception.Message }
            } else { Result 'Defender quick scan' 'Skipped' 'Opt-in only: -QuickScan' }
            if ($DisableRemoteRegistry) {
                try { Set-OptionalService -Name 'RemoteRegistry' -StartupType 'Disabled' }
                catch { Result 'RemoteRegistry' 'Error' $_.Exception.Message }
            } else { Result 'RemoteRegistry change' 'Skipped' 'Opt-in only: -DisableRemoteRegistry; check README before changing services' }
            if ($DisableLegacyFeatures) {
                foreach($feature in @('SMB1Protocol','TelnetClient','TFTP')) {
                    try {
                        $f=Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction Stop
                        if ($f.State -eq 'Enabled') {
                            Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction Stop | Out-Null
                            Result "OptionalFeature: $feature" 'Changed' 'Disabled; reboot may be needed'
                        } else { Result "OptionalFeature: $feature" 'OK' "State=$($f.State)" }
                    } catch { Result "OptionalFeature: $feature" 'Review' $_.Exception.Message }
                }
            } else { Result 'Legacy features change' 'Skipped' 'Opt-in only: -DisableLegacyFeatures; check README for required SMB/Telnet/TFTP components' }
            # Do not force GPUPDATE, reboot or Windows Update installation during competition.
        }
        Phase 4 'Verify effective settings and collect review lists'
        Collect-ReadOnlyChecks -Folder $session
        Collect-SoftwareReport -Folder $session
        Collect-DesktopReport -Folder $session
        if ($Mode -eq 'Apply') {
            Log "Backup folder for -Mode Restore: $session"
            Result 'README dependent items' 'Not changed' 'Accounts, admins, shares, RDP, IIS, Defender exclusions, forensic files and software removal'
        }
    }
} catch {
    Result 'Unexpected error' 'Error' $_.Exception.Message
} finally {
    Phase 5 'Final result and next actions'
    $csv=Join-Path $session 'summary.csv'
    $script:Results | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
    $errors=@($script:Results | Where-Object { $_.State -eq 'Error' })
    $verified=@($script:Results | Where-Object { $_.State -in @('Verified','OK','Changed','Done') })
    $review=@($script:Results | Where-Object { $_.State -in @('Review','Check','Skipped','Not changed') })
    $checked=@($script:Results | Where-Object { $_.State -eq 'Checked' })
    Write-Host ""
    Write-Host '====================== RUN SUMMARY ======================' -ForegroundColor Cyan
    Write-Host "Mode: $Mode" -ForegroundColor White
    Write-Host "Verified/OK/Changed: $($verified.Count)" -ForegroundColor Green
    Write-Host "Checked (report only): $($checked.Count)" -ForegroundColor Gray
    Write-Host "Review/Skipped/Check: $($review.Count)" -ForegroundColor Yellow
    Write-Host "Errors: $($errors.Count)" -ForegroundColor Red
    if ($errors.Count -gt 0) {
        Write-Host 'FAILED ITEMS (失败):' -ForegroundColor Red
        foreach($item in $errors) { Write-Host "  - $($item.Item): $($item.Detail)" -ForegroundColor Red }
    }
    if ($review.Count -gt 0) {
        Write-Host 'NOT FINISHED / REVIEW REQUIRED (未自动完成，需检查):' -ForegroundColor Yellow
        foreach($item in $review) { Write-Host "  - [$($item.State)] $($item.Item): $($item.Detail)" -ForegroundColor Yellow }
    }
    Write-Host "Report: $csv"
    Write-Host "Log: $script:LogFile"
    Write-Host "Session folder: $session"
    if ($Mode -eq 'Audit') {
        Write-Host 'AUDIT ONLY: THIS RUN DID NOT APPLY ANY FIXES. Use Apply mode to make changes.' -ForegroundColor Yellow
    } elseif ($Mode -eq 'Apply') {
        Write-Host 'Settings were applied where possible, but CyberPatriot score is NOT guaranteed.' -ForegroundColor Yellow
        Write-Host 'Check the scoring report, README, and security policy overrides.' -ForegroundColor Yellow
        Write-Host "To restore: .\CyberPatriot_Win11_Fixed_v2.ps1 -Mode Restore -BackupPath '$session'"
    }
    Log "Finished. Summary=$csv; errors=$($errors.Count)"
    Write-Progress -Activity 'CyberPatriot Windows 11 fixed checks' -Completed
}
# Do not call 'exit' here: -NoExit launchers must keep the console available for diagnostics.
if (@($script:Results | Where-Object { $_.State -eq 'Error' }).Count -gt 0) {
    Write-Host 'Finished with errors. PowerShell window will remain open.' -ForegroundColor Red
    $global:LASTEXITCODE=1
} else {
    Write-Host 'Finished. PowerShell window will remain open.' -ForegroundColor Green
    $global:LASTEXITCODE=0
}

Write-Host ''
Write-Host 'Execution ended. Press ENTER to close (or inspect above errors).' -ForegroundColor Cyan
try { [void](Read-Host 'Press ENTER') } catch {}