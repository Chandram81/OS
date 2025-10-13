
<#
.SYNOPSIS
  Windows 10/11 Workstation Hardening Audit – v9 (expanded)
.DESCRIPTION
  Performs a broad set of checks (High/Medium/Low/Info) and outputs CSV + JSON plus console table.
.PARAMETER FailOnHighFindings
  Exit with code 2 if any High priority findings are FAIL.
.PARAMETER WithRemediation
  Add a concise remediation hint column for failing checks.
#>

[CmdletBinding()]
param(
  [switch]$FailOnHighFindings,
  [switch]$WithRemediation
)

# ------------------ Helpers ------------------
function Format-Val { param($v) if ($null -eq $v -or ($v -is [string] -and $v.ToString().Trim() -eq '')) { return 'Not Set' } return $v }

function Get-Reg {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [ValidateSet('HKLM','HKCU','HKU','HKCR','HKCC')]
    [string]$Hive = 'HKLM'
  )
  try {
    $full = Join-Path "$($Hive):\" $Path
    # Use -ErrorAction Stop so we return $null on missing property
    $v = Get-ItemProperty -LiteralPath $full -ErrorAction Stop | Select-Object -ExpandProperty $Name -ErrorAction Stop
    return $v
  } catch {
    return $null
  }
}

function Test-ValueEq {
  param(
    [AllowNull()][Parameter()]$Actual,
    [Parameter(Mandatory)]$Expected
  )
  if ($null -eq $Actual) { return $false }
  # numeric comparison when possible
  if ($Actual -isnot [string] -and $Expected -isnot [string]) { return ($Actual -eq $Expected) }
  try {
    if (($Actual -as [int]) -ne $null -and (($Expected -as [int]) -ne $null)) {
      return ([int]$Actual -eq [int]$Expected)
    }
  } catch {}
  return ($Actual.ToString().Trim() -eq $Expected.ToString().Trim())
}

function Get-RemediationHint {
  param([string]$Id,[string]$Area)
  switch -regex ($Id) {
    '^HP-01' { return 'Set HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon CachedLogonsCount=1' }
    '^HP-02' { return 'Set HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa DisableDomainCreds=1' }
    '^HP-03' { return 'Set HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest UseLogonCredential=0' }
    '^HP-04' { return 'Enable LSASS PPL (RunAsPPL=1, RunAsPPLBoot=1).' }
    '^HP-05' { return 'Enable Credential Guard via Device Guard configuration (LsaCfgFlags=1 or 2).' }
    '^HP-06' { return 'Enable VBS and HVCI from Windows Security / Group Policy or Intune.' }
    '^HP-10' { return 'Enable Attack Surface Reduction (ASR) rules via Set-MpPreference.' }
    '^HP-11' { return 'Enable Defender Network Protection (GPO/Intune).' }
    '^HP-12' { return 'Enable Controlled Folder Access (Defender).' }
    '^HP-13' { return 'Enable Secure Boot and ensure TPM 2.0 is provisioned.' }
    '^HP-14' { return 'Enable BitLocker on OS drive with XTS-AES and protect keys with TPM+PIN.' }
    '^MP-01' { return 'Configure account lockout: net accounts /lockoutthreshold:5 /lockoutwindow:15.' }
    '^MP-03' { return 'Harden Defender: enable PUA block, cloud protection, MAPS advanced.' }
    '^MP-05' { return 'Disable AutoRun/AutoPlay via policy.' }
    '^MP-06' { return 'Disable NetBIOS on NICs (set TcpipNetbiosOptions=2).' }
    '^MP-09' { return 'Enable SmartScreen and configure Edge defenses.' }
    '^MP-10' { return 'Enable PowerShell ScriptBlock, Module and Transcription logging.' }
    '^MP-11' { return 'Enable Firewall profiles, set inbound block and logging.' }
    '^MP-12' { return 'Require NLA for RDP and disable redirections/save-password.' }
    '^MP-13' { return 'Set event log sizes and retention to recommended values.' }
    '^MP-23' { return 'Remove/disable PowerShell v2 optional feature.' }
    '^MP-24' { return 'Disable TLS 1.0/1.1; enable TLS 1.2/1.3.' }
    default { return $Area }
  }
}

function Add-Result {
  param(
    [string]$Id,
    [ValidateSet('High','Medium','Low','Info')][string]$Priority,
    [string]$Area,
    [string]$Check,
    [string]$Expected,
    [Parameter()][AllowNull()][object]$Actual,
    [bool]$Compliant
  )
  # Normalize actual value for display: convert $null / empty → "Not Set"
  if ($null -eq $Actual -or ($Actual -is [string] -and $Actual.ToString().Trim() -eq '')) {
    $actualDisplay = 'Not Set'
  } else {
    $actualDisplay = $Actual
  }
  $row = [pscustomobject]@{
    Id        = $Id
    Priority  = $Priority
    Area      = $Area
    Check     = $Check
    Expected  = $Expected
    Actual    = $actualDisplay
    Compliant = if ($Compliant) {'PASS'} else {'FAIL'}
  }
  if ($WithRemediation -and $row.Compliant -eq 'FAIL') {
    $row | Add-Member -NotePropertyName Remediation -NotePropertyValue (Get-RemediationHint -Id $Id -Area $Area)
  }
  $script:Results += $row
}

# Initialize
$Results = @()

# ------------------ Environment ------------------
try {
  $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
  $osCaption = $os.Caption
  $osVersion = $os.Version
  $buildInfo = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name CurrentBuild,UBR,ReleaseId,DisplayVersion -ErrorAction SilentlyContinue
  $edition = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID -ErrorAction SilentlyContinue).EditionID
  $actualEnv = "$osCaption ($edition) v$osVersion build $($buildInfo.CurrentBuild).$($buildInfo.UBR)"
  Add-Result -Id 'ENV-01' -Priority 'Info' -Area 'OS' -Check 'Windows Version/Build' -Expected 'Win10/11 supported release' -Actual $actualEnv -Compliant $true
} catch {
  Add-Result -Id 'ENV-01' -Priority 'Info' -Area 'OS' -Check 'Windows Version/Build' -Expected 'Win10/11 supported release' -Actual 'OS query failed' -Compliant $false
}

# =================== HIGH PRIORITY ===================

# HP-01 Cached logons
$cachedLogons = Get-Reg -Path 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'CachedLogonsCount'
Add-Result -Id 'HP-01' -Priority 'High' -Area 'CredProt' -Check 'Cached logons limited' -Expected 'CachedLogonsCount=1' -Actual ("CachedLogonsCount={0}" -f $cachedLogons) -Compliant (Test-ValueEq $cachedLogons 1)

# HP-02 Disable cached network creds
$disableCreds = Get-Reg -Path 'SYSTEM\CurrentControlSet\Control\Lsa' -Name 'DisableDomainCreds'
Add-Result -Id 'HP-02' -Priority 'High' -Area 'CredProt' -Check 'No cached network creds' -Expected 'DisableDomainCreds=1' -Actual ("DisableDomainCreds={0}" -f $disableCreds) -Compliant (Test-ValueEq $disableCreds 1)

# HP-03 WDigest
$wdigest = Get-Reg -Path 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential'
if ($null -eq $wdigest) { $wdigest = 0 }
Add-Result -Id 'HP-03' -Priority 'High' -Area 'CredProt' -Check 'WDigest disabled' -Expected 'UseLogonCredential=0' -Actual ("UseLogonCredential={0}" -f $wdigest) -Compliant (Test-ValueEq $wdigest 0)

# HP-04 LSASS PPL
$runAsPPL = Get-Reg -Path 'SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL'
$runAsPPLBoot = Get-Reg -Path 'SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPLBoot'
Add-Result -Id 'HP-04a' -Priority 'High' -Area 'LSASS' -Check 'LSASS Protected Process' -Expected 'RunAsPPL=1' -Actual ("RunAsPPL={0}" -f $runAsPPL) -Compliant (Test-ValueEq $runAsPPL 1)
Add-Result -Id 'HP-04b' -Priority 'High' -Area 'LSASS' -Check 'LSASS PPL (boot)' -Expected 'RunAsPPLBoot=1' -Actual ("RunAsPPLBoot={0}" -f $runAsPPLBoot) -Compliant (Test-ValueEq $runAsPPLBoot 1)

# HP-05 Credential Guard
$lsaCfg = Get-Reg -Path 'SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LsaCfgFlags'
Add-Result -Id 'HP-05' -Priority 'High' -Area 'CredGuard' -Check 'Credential Guard enabled' -Expected 'LsaCfgFlags=1 or 2' -Actual ("LsaCfgFlags={0}" -f $lsaCfg) -Compliant ($lsaCfg -in 1,2)

# HP-06 VBS / HVCI / Secure Launch / KSS / ELAM
$dgEnabled = Get-Reg -Path 'SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name 'EnableVirtualizationBasedSecurity'
$hvci = Get-Reg -Path 'SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name 'Enabled'
$sl = Get-Reg -Path 'SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SecureLaunch' -Name 'Enabled'
$kss = Get-Reg -Path 'SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks' -Name 'Enabled'
$elam = Get-Reg -Path 'SYSTEM\CurrentControlSet\Policies\EarlyLaunch' -Name 'DriverLoadPolicy'
Add-Result -Id 'HP-06a' -Priority 'High' -Area 'VBS' -Check 'VBS enabled' -Expected 'EnableVirtualizationBasedSecurity=1' -Actual $dgEnabled -Compliant (Test-ValueEq $dgEnabled 1)
Add-Result -Id 'HP-06b' -Priority 'High' -Area 'Code Integrity' -Check 'HVCI (Memory Integrity)' -Expected 'Enabled=1' -Actual $hvci -Compliant (Test-ValueEq $hvci 1)
Add-Result -Id 'HP-07' -Priority 'High' -Area 'VBS' -Check 'Secure Launch' -Expected 'Enabled=1' -Actual $sl -Compliant (Test-ValueEq $sl 1)
Add-Result -Id 'HP-08' -Priority 'High' -Area 'Exploit Protection' -Check 'Kernel Shadow Stacks' -Expected 'Enabled=1' -Actual $kss -Compliant (Test-ValueEq $kss 1)
Add-Result -Id 'HP-09' -Priority 'High' -Area 'ELAM' -Check 'ELAM Boot driver policy' -Expected '3' -Actual $elam -Compliant (Test-ValueEq $elam 3)

# HP-10 Attack Surface Reduction rules (ASR)
# Map known ASR GUIDs to friendly rule names for clearer output.
$ASRNames = @{
  '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block executable content from email and webmail clients'
  '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block process creations originating from PSExec and WMI commands'
  'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block credential stealing from LSASS'
  '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block Office applications from creating child processes'
  'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from Office files downloaded from the internet'
  '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block Win32 API calls from Office macros'
  '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block Office applications from creating child processes (alternate)'
  'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block executable files from running unless approved'
  '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office macros using VBA'
  '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block untrusted and unsigned processes'
  '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block all Office applications from creating child processes'
  'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block process creation from AppLocker bypass methods'
  'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block Office from loading COM objects'
  'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted executable content'
  '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block executable content from email attachments'
  'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Block execution of scripts'
}
# List the ASR rules we care about (GUIDs).
$neededASR = $ASRNames.Keys

# Query ASR state and report with friendly names
function Get-ASRState {
  try {
    $prefs = Get-MpPreference -ErrorAction Stop
    $ids = $prefs.AttackSurfaceReductionRules_Ids
    $acts = $prefs.AttackSurfaceReductionRules_Actions
    $res = @()
    for ($i=0; $i -lt $ids.Count; $i++) {
      $res += [pscustomobject]@{ Id = $ids[$i].ToString().ToLower(); State = [int]$acts[$i] }
    }
    return $res
  } catch { return @() }
}
$asr = Get-ASRState
foreach ($id in $neededASR) {
  $row = $asr | Where-Object { $_.Id -eq $id }
  $state = if ($row) { [int]$row.State } else { -1 }
  $ok = ($state -eq 1)
  $friendly = $ASRNames[$id]
  $shortId = $id.Substring(0,8).ToUpper()
  Add-Result -Id ("HP-10-{0}" -f $shortId) -Priority 'High' -Area 'ASR' -Check ("ASR: {0} ({1})" -f $friendly, $id) -Expected 'Enabled (1)' -Actual ("State={0}" -f $state) -Compliant $ok
}
# HP-11 Defender Network Protection
try {
  $np = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' -Name EnableNetworkProtection -ErrorAction Stop).EnableNetworkProtection
  Add-Result -Id 'HP-11' -Priority 'High' -Area 'Defender' -Check 'Network Protection' -Expected '1 (Block)' -Actual $np -Compliant (Test-ValueEq $np 1)
} catch { Add-Result -Id 'HP-11' -Priority 'High' -Area 'Defender' -Check 'Network Protection' -Expected '1 (Block)' -Actual 'Not configured' -Compliant $false }

# HP-12 Controlled Folder Access
try {
  $cfa = (Get-MpPreference -ErrorAction Stop).EnableControlledFolderAccess
  Add-Result -Id 'HP-12' -Priority 'High' -Area 'Ransomware' -Check 'Controlled Folder Access' -Expected '1 (Block)' -Actual $cfa -Compliant (Test-ValueEq $cfa 1)
} catch { Add-Result -Id 'HP-12' -Priority 'High' -Area 'Ransomware' -Check 'Controlled Folder Access' -Expected '1 (Block)' -Actual 'Get-MpPreference failed' -Compliant $false }

# HP-13 Secure Boot / TPM
try {
  $sb = Confirm-SecureBootUEFI -ErrorAction Stop
  Add-Result -Id 'HP-13a' -Priority 'High' -Area 'Boot Security' -Check 'Secure Boot' -Expected 'Enabled' -Actual $sb -Compliant ([bool]$sb)
} catch { Add-Result -Id 'HP-13a' -Priority 'High' -Area 'Boot Security' -Check 'Secure Boot' -Expected 'Enabled' -Actual 'Unsupported/No UEFI' -Compliant $false }

try {
  $tpm = Get-Tpm -ErrorAction Stop
  Add-Result -Id 'HP-13b' -Priority 'High' -Area 'Boot Security' -Check 'TPM Ready' -Expected 'Present & Ready' -Actual ("Present={0}; Ready={1}" -f $tpm.TpmPresent,$tpm.TpmReady) -Compliant (($tpm.TpmPresent) -and ($tpm.TpmReady))
} catch { Add-Result -Id 'HP-13b' -Priority 'High' -Area 'Boot Security' -Check 'TPM Ready' -Expected 'Present & Ready' -Actual 'Get-Tpm failed' -Compliant $false }

# HP-14 BitLocker OS drive encryption
try {
  $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
  $ok = ($bl.VolumeStatus -eq 'FullyEncrypted') -and ($bl.EncryptionMethod -match 'XtsAes')
  Add-Result -Id 'HP-14' -Priority 'High' -Area 'BitLocker' -Check 'OS Drive Encryption' -Expected 'FullyEncrypted XTS-AES' -Actual ("{0}, {1}" -f $bl.VolumeStatus,$bl.EncryptionMethod) -Compliant $ok
} catch { Add-Result -Id 'HP-14' -Priority 'High' -Area 'BitLocker' -Check 'OS Drive Encryption' -Expected 'FullyEncrypted XTS-AES' -Actual 'BitLocker not available' -Compliant $false }

# HP-15 SMB hardening
try {
  $smb1 = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop).State
} catch { $smb1 = 'QueryFailed' }
Add-Result -Id 'HP-15a' -Priority 'High' -Area 'SMB' -Check 'SMBv1 feature' -Expected 'Disabled' -Actual $smb1 -Compliant ($smb1 -eq 'Disabled')

$svrReq = Get-Reg -Path 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature'
$svrEn  = Get-Reg -Path 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'EnableSecuritySignature'
$cliReq = Get-Reg -Path 'SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature'
$cliEn  = Get-Reg -Path 'SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'EnableSecuritySignature'
$insecureGuest = Get-Reg -Path 'SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'AllowInsecureGuestAuth'

Add-Result -Id 'HP-15b' -Priority 'High' -Area 'SMB' -Check 'Server require signing' -Expected '1' -Actual $svrReq -Compliant (Test-ValueEq $svrReq 1)
Add-Result -Id 'HP-15c' -Priority 'High' -Area 'SMB' -Check 'Server enable signing' -Expected '1' -Actual $svrEn -Compliant (Test-ValueEq $svrEn 1)
Add-Result -Id 'HP-15d' -Priority 'High' -Area 'SMB' -Check 'Client require signing' -Expected '1' -Actual $cliReq -Compliant (Test-ValueEq $cliReq 1)
Add-Result -Id 'HP-15e' -Priority 'High' -Area 'SMB' -Check 'Client enable signing' -Expected '1' -Actual $cliEn -Compliant (Test-ValueEq $cliEn 1)
Add-Result -Id 'HP-15f' -Priority 'High' -Area 'SMB' -Check 'Disable insecure guest' -Expected 'AllowInsecureGuestAuth=0' -Actual $insecureGuest -Compliant (Test-ValueEq $insecureGuest 0)

# HP-16 RDP crypto
$minEnc = Get-Reg -Path 'SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'MinEncryptionLevel'
$secLayer = Get-Reg -Path 'SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'SecurityLayer'
Add-Result -Id 'HP-16a' -Priority 'High' -Area 'RDP' -Check 'MinEncryptionLevel' -Expected '3 (High)' -Actual $minEnc -Compliant (Test-ValueEq $minEnc 3)
Add-Result -Id 'HP-16b' -Priority 'High' -Area 'RDP' -Check 'SecurityLayer' -Expected '2 (SSL/TLS)' -Actual $secLayer -Compliant (Test-ValueEq $secLayer 2)

# HP-17 Exploit Protection (system)
try {
  $mit = Get-ProcessMitigation -System -ErrorAction Stop
  $dep = $mit.Dep.Enable; $seh = $mit.SEHOP.Enable; $aslr = $mit.ASLR.ForceRelocateImages; $cfg = $mit.CFG.Enable
  Add-Result -Id 'HP-17a' -Priority 'High' -Area 'Exploit Protection' -Check 'DEP (Always On)' -Expected 'Enabled' -Actual $dep -Compliant ($dep -eq 'ON' -or $dep -eq $true)
  Add-Result -Id 'HP-17b' -Priority 'High' -Area 'Exploit Protection' -Check 'SEHOP' -Expected 'Enabled' -Actual $seh -Compliant ($seh -eq 'ON' -or $seh -eq $true)
  Add-Result -Id 'HP-17c' -Priority 'High' -Area 'Exploit Protection' -Check 'ASLR ForceRelocate' -Expected 'Enabled' -Actual $aslr -Compliant ($aslr -eq 'ON' -or $aslr -eq $true)
  Add-Result -Id 'HP-17d' -Priority 'High' -Area 'Exploit Protection' -Check 'CFG' -Expected 'Enabled' -Actual $cfg -Compliant ($cfg -eq 'ON' -or $cfg -eq $true)
} catch { Add-Result -Id 'HP-17' -Priority 'High' -Area 'Exploit Protection' -Check 'System mitigations' -Expected 'Enabled' -Actual 'Get-ProcessMitigation failed' -Compliant $false }

# =================== MEDIUM PRIORITY ===================

# MP-01 Account lockout
$netAccounts = net accounts 2>&1 | Out-String
$thresh = if ($netAccounts -match 'Lockout threshold:\s+(\d+)') { [int]$matches[1] } else { -1 }
$reset = if ($netAccounts -match 'Lockout observation window:\s+(\d+)\s+minutes') { [int]$matches[1] } else { -1 }
Add-Result -Id 'MP-01a' -Priority 'Medium' -Area 'Account Lockout' -Check 'Threshold' -Expected '5' -Actual $thresh -Compliant ($thresh -eq 5)
Add-Result -Id 'MP-01b' -Priority 'Medium' -Area 'Account Lockout' -Check 'Reset window' -Expected '15 minutes' -Actual ("{0} minutes" -f $reset) -Compliant ($reset -eq 15)

# MP-02 Anonymous/LSA settings
$everyoneAnon = Get-Reg -Path 'SYSTEM\CurrentControlSet\Control\Lsa' -Name 'EveryoneIncludesAnonymous'
$sidName = Get-Reg -Path 'SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LsaAnonymousNameLookup'
$restrictAnon = Get-Reg -Path 'SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous'
$restrictAnonSAM = Get-Reg -Path 'SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM'
Add-Result -Id 'MP-02a' -Priority 'Medium' -Area 'Anonymous' -Check 'EveryoneIncludesAnonymous' -Expected '0' -Actual $everyoneAnon -Compliant (Test-ValueEq $everyoneAnon 0)
Add-Result -Id 'MP-02b' -Priority 'Medium' -Area 'Anonymous' -Check 'LsaAnonymousNameLookup' -Expected '0' -Actual $sidName -Compliant (Test-ValueEq $sidName 0)
Add-Result -Id 'MP-02c' -Priority 'Medium' -Area 'Anonymous' -Check 'RestrictAnonymous' -Expected '1 or 2' -Actual $restrictAnon -Compliant ($restrictAnon -in 1,2)
Add-Result -Id 'MP-02d' -Priority 'Medium' -Area 'Anonymous' -Check 'RestrictAnonymousSAM' -Expected '1' -Actual $restrictAnonSAM -Compliant (Test-ValueEq $restrictAnonSAM 1)

# MP-03 Defender core (already handled earlier in many environments)
try {
  $prefs = Get-MpPreference -ErrorAction Stop
  Add-Result -Id 'MP-03a' -Priority 'Medium' -Area 'Defender' -Check 'PUA' -Expected '1 (Block)' -Actual $prefs.PUAProtection -Compliant (Test-ValueEq $prefs.PUAProtection 1)
  Add-Result -Id 'MP-03b' -Priority 'Medium' -Area 'Defender' -Check 'Cloud Block Level' -Expected 'High/HighPlus' -Actual $prefs.CloudBlockLevel -Compliant ($prefs.CloudBlockLevel -in 2,4)
  Add-Result -Id 'MP-03c' -Priority 'Medium' -Area 'Defender' -Check 'MAPS' -Expected 'Advanced (2)' -Actual $prefs.MAPSReporting -Compliant (Test-ValueEq $prefs.MAPSReporting 2)
  Add-Result -Id 'MP-03d' -Priority 'Medium' -Area 'Defender' -Check 'SubmitSamples' -Expected 'SendAll (3)' -Actual $prefs.SubmitSamplesConsent -Compliant (Test-ValueEq $prefs.SubmitSamplesConsent 3)
  Add-Result -Id 'MP-03e' -Priority 'Medium' -Area 'Defender' -Check 'RealTime' -Expected 'DisableRealtimeMonitoring=0' -Actual $prefs.DisableRealtimeMonitoring -Compliant (Test-ValueEq $prefs.DisableRealtimeMonitoring 0)
  Add-Result -Id 'MP-03f' -Priority 'Medium' -Area 'Defender' -Check 'IOAV' -Expected 'DisableIOAVProtection=0' -Actual $prefs.DisableIOAVProtection -Compliant (Test-ValueEq $prefs.DisableIOAVProtection 0)
  Add-Result -Id 'MP-03g' -Priority 'Medium' -Area 'Defender' -Check 'ScriptScanning' -Expected 'DisableScriptScanning=0' -Actual $prefs.DisableScriptScanning -Compliant (Test-ValueEq $prefs.DisableScriptScanning 0)
  try { $mcs = Get-MpComputerStatus -ErrorAction Stop; Add-Result -Id 'MP-03h' -Priority 'Medium' -Area 'Defender' -Check 'Tamper Protection' -Expected 'On' -Actual $mcs.TamperProtection -Compliant (Test-ValueEq $mcs.TamperProtection 'On') } catch {}
} catch { Add-Result -Id 'MP-03' -Priority 'Medium' -Area 'Defender' -Check 'Core settings' -Expected 'Configured' -Actual 'Get-MpPreference failed' -Compliant $false }

# MP-04 Attachment Manager
$saveZone = Get-Reg -Hive HKCU -Path 'Software\Microsoft\Windows\CurrentVersion\Policies\Attachments' -Name 'SaveZoneInformation'
$hideZone = Get-Reg -Hive HKCU -Path 'Software\Microsoft\Windows\CurrentVersion\Policies\Attachments' -Name 'HideZoneInfoOnProperties'
Add-Result -Id 'MP-04a' -Priority 'Medium' -Area 'Attachment' -Check 'Preserve zone info' -Expected '2' -Actual $saveZone -Compliant (Test-ValueEq $saveZone 2)
Add-Result -Id 'MP-04b' -Priority 'Medium' -Area 'Attachment' -Check 'Hide remove-zone options' -Expected '1' -Actual $hideZone -Compliant (Test-ValueEq $hideZone 1)

# MP-05 AutoPlay/Autorun
$noAutoRun = Get-Reg -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoAutorun'
$noDriveType = Get-Reg -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun'
$noNonVol = Get-Reg -Path 'SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoAutoplayfornonVolume'
Add-Result -Id 'MP-05a' -Priority 'Medium' -Area 'AutoPlay' -Check 'NoAutorun' -Expected '1' -Actual $noAutoRun -Compliant (Test-ValueEq $noAutoRun 1)
Add-Result -Id 'MP-05b' -Priority 'Medium' -Area 'AutoPlay' -Check 'NoDriveTypeAutoRun' -Expected '255' -Actual $noDriveType -Compliant (Test-ValueEq $noDriveType 255)
Add-Result -Id 'MP-05c' -Priority 'Medium' -Area 'AutoPlay' -Check 'NoAutoplayfornonVolume' -Expected '1' -Actual $noNonVol -Compliant (Test-ValueEq $noNonVol 1)

# MP-06 Disable NetBIOS over TCP/IP on NICs
$adapters = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true}
$nbFails = 0
if ($adapters) {
  foreach ($a in $adapters) { if ($a.TcpipNetbiosOptions -ne 2) { $nbFails++ } }
}
$nbOk = ($nbFails -eq 0 -and ($adapters.Count -gt 0))
Add-Result -Id 'MP-06' -Priority 'Medium' -Area 'NetBIOS' -Check 'Disable NetBIOS over TCP/IP' -Expected '2 on all NICs' -Actual ("Non-compliant NICs={0}" -f $nbFails) -Compliant $nbOk

# MP-07 LmCompatibilityLevel
$lmLevel = Get-Reg -Path 'SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel'
Add-Result -Id 'MP-07' -Priority 'Medium' -Area 'Network Auth' -Check 'LmCompatibilityLevel' -Expected '5' -Actual $lmLevel -Compliant (Test-ValueEq $lmLevel 5)

# MP-08 Do not store LM hash
$noLm = Get-Reg -Path 'SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash'
Add-Result -Id 'MP-08' -Priority 'Medium' -Area 'Password' -Check 'Do not store LM hash' -Expected '1' -Actual $noLm -Compliant (Test-ValueEq $noLm 1)

# MP-09 SmartScreen and Edge
$ss1 = Get-Reg -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableSmartScreen'
$ss2 = Get-Reg -Path 'SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableSmartScreen'
Add-Result -Id 'MP-09a' -Priority 'Medium' -Area 'SmartScreen' -Check 'Windows SmartScreen' -Expected 'Enabled' -Actual ("Sys={0}; PolSys={1}" -f $ss1,$ss2) -Compliant ( ($ss1 -eq 1) -or ($ss2 -eq 1) )
$edgeSS = Get-Reg -Path 'SOFTWARE\Policies\Microsoft\Edge' -Name 'SmartScreenEnabled'
$edgePUA = Get-Reg -Path 'SOFTWARE\Policies\Microsoft\Edge' -Name 'SmartScreenPuaEnabled'
$edgePwd = Get-Reg -Path 'SOFTWARE\Policies\Microsoft\Edge' -Name 'PasswordManagerEnabled'
$edgeRCI = Get-Reg -Path 'SOFTWARE\Policies\Microsoft\Edge' -Name 'RendererCodeIntegrityEnabled'
Add-Result -Id 'MP-09b' -Priority 'Medium' -Area 'Edge' -Check 'SmartScreen' -Expected '1' -Actual $edgeSS -Compliant (Test-ValueEq $edgeSS 1)
Add-Result -Id 'MP-09c' -Priority 'Medium' -Area 'Edge' -Check 'PUA' -Expected '1' -Actual $edgePUA -Compliant (Test-ValueEq $edgePUA 1)
Add-Result -Id 'MP-09d' -Priority 'Medium' -Area 'Edge' -Check 'Password Manager disabled' -Expected '0' -Actual $edgePwd -Compliant (Test-ValueEq $edgePwd 0)
Add-Result -Id 'MP-09e' -Priority 'Medium' -Area 'Edge' -Check 'Renderer Code Integrity' -Expected '1' -Actual $edgeRCI -Compliant (Test-ValueEq $edgeRCI 1)

# MP-10 PowerShell logging
$psSBL = Get-Reg -Path 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging'
$psML  = Get-Reg -Path 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging'
$psTR  = Get-Reg -Path 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableTranscripting'
Add-Result -Id 'MP-10a' -Priority 'Medium' -Area 'PowerShell' -Check 'Script Block Logging' -Expected '1' -Actual $psSBL -Compliant (Test-ValueEq $psSBL 1)
Add-Result -Id 'MP-10b' -Priority 'Medium' -Area 'PowerShell' -Check 'Module Logging' -Expected '1' -Actual $psML -Compliant (Test-ValueEq $psML 1)
Add-Result -Id 'MP-10c' -Priority 'Medium' -Area 'PowerShell' -Check 'Transcription' -Expected '1' -Actual $psTR -Compliant (Test-ValueEq $psTR 1)

# MP-11 Firewall profiles and logging
try {
  $profiles = Get-NetFirewallProfile -ErrorAction Stop
  foreach ($p in $profiles) {
    $ok = ($p.Enabled -and $p.DefaultInboundAction -eq 'Block')
    Add-Result -Id ("MP-11-{0}" -f $p.Name) -Priority 'Medium' -Area 'Firewall' -Check ("Profile {0}" -f $p.Name) -Expected 'Enabled & Inbound Block' -Actual ("Enabled={0}; InBound={1}" -f $p.Enabled,$p.DefaultInboundAction) -Compliant $ok
    Add-Result -Id ("MP-11log-{0}" -f $p.Name) -Priority 'Medium' -Area 'Firewall' -Check ("Logging {0}" -f $p.Name) -Expected 'Log dropped=Enabled, File set' -Actual ("LogDropped={0}; LogFile={1}; MaxKB={2}" -f $p.LogBlocked,$p.LogFileName,$p.LogMaxSizeKilobytes) -Compliant ( ($p.LogBlocked -eq $true -or $p.LogBlocked -eq 'True') -and ($p.LogFileName -ne $null) )
  }
} catch { Add-Result -Id 'MP-11' -Priority 'Medium' -Area 'Firewall' -Check 'Profiles/Logging' -Expected 'Enabled' -Actual 'Get-NetFirewallProfile failed' -Compliant $false }

# MP-12 RDP hardening (NLA, redirection, saved creds)
$rdpEnabled = Get-Reg -Path 'SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections'
$rdpNLA = Get-Reg -Path 'SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication'
$rdpOn = ($rdpEnabled -eq 0)
Add-Result -Id 'MP-12a' -Priority 'Medium' -Area 'RDP' -Check 'RDP enabled?' -Expected 'Disabled or NLA enforced' -Actual ("fDenyTSConnections={0}" -f $rdpEnabled) -Compliant (-not $rdpOn -or ($rdpOn -and (Test-ValueEq $rdpNLA 1)))
Add-Result -Id 'MP-12b' -Priority 'Medium' -Area 'RDP' -Check 'NLA required' -Expected 'UserAuthentication=1 if RDP on' -Actual $rdpNLA -Compliant (-not $rdpOn -or (Test-ValueEq $rdpNLA 1))
$tsPol = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$redir = @{'fDisableCdm'='Disable drive redirection';'fDisableCcm'='Disable clipboard redirection';'fDisableCpm'='Disable LPT port redirection';'fDisablePNPRedir'='Disable PnP redirection'}
foreach ($k in $redir.Keys) { $val = Get-Reg -Path $tsPol -Name $k; Add-Result -Id ("MP-12c-{0}" -f $k) -Priority 'Medium' -Area 'RDP' -Check $redir[$k] -Expected '1' -Actual $val -Compliant (Test-ValueEq $val 1) }
$rdpPwdHKCU = Get-Reg -Hive HKCU -Path 'Software\Microsoft\Terminal Server Client' -Name 'DisablePasswordSaving'
$rdpPwdHKLM = Get-Reg -Path 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'DisablePasswordSaving'
Add-Result -Id 'MP-12d' -Priority 'Medium' -Area 'RDP' -Check 'Disable password saving (HKCU/HKLM)' -Expected '1' -Actual ("HKCU={0}; HKLM={1}" -f $rdpPwdHKCU,$rdpPwdHKLM) -Compliant ( (Test-ValueEq $rdpPwdHKCU 1) -or (Test-ValueEq $rdpPwdHKLM 1) )

try {
  $rdpEnabledVal = Get-Reg -Path 'SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections'
  $rdpOff = ($rdpEnabledVal -ne 0)
  $rdpFwEnabled = (Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop)
  $anyEnabled = ($rdpFwEnabled | Measure-Object).Count -gt 0
  Add-Result -Id 'MP-12e' -Priority 'Medium' -Area 'RDP/Firewall' -Check 'Inbound rules disabled when RDP off' -Expected 'No enabled allow rules if RDP disabled' -Actual ("RDPOff={0}; AnyEnabled={1}" -f $rdpOff,$anyEnabled) -Compliant ( -not $rdpOff -or (-not $anyEnabled) )
} catch { Add-Result -Id 'MP-12e' -Priority 'Medium' -Area 'RDP/Firewall' -Check 'Inbound rules disabled when RDP off' -Expected 'No enabled allow rules if RDP disabled' -Actual 'Rule query failed' -Compliant $false }

# MP-13 Event log sizes & retention
$secLog = Get-Reg -Path 'SYSTEM\CurrentControlSet\Services\EventLog\Security' -Name 'MaxSize'
$secRet = Get-Reg -Path 'SYSTEM\CurrentControlSet\Services\EventLog\Security' -Name 'Retention'
Add-Result -Id 'MP-13a' -Priority 'Medium' -Area 'Event Log' -Check 'Security log size' -Expected '>= 196608 KB' -Actual ("{0}" -f $secLog) -Compliant ( ($secLog -ne $null) -and ([int]$secLog -ge 196608) )
Add-Result -Id 'MP-13b' -Priority 'Medium' -Area 'Event Log' -Check 'Security retention' -Expected 'Overwrite as needed (0)' -Actual $secRet -Compliant (Test-ValueEq $secRet 0)
$appLog = Get-Reg -Path 'SYSTEM\CurrentControlSet\Services\EventLog\Application' -Name 'MaxSize'
$sysLog = Get-Reg -Path 'SYSTEM\CurrentControlSet\Services\EventLog\System' -Name 'MaxSize'
Add-Result -Id 'MP-13c' -Priority 'Medium' -Area 'Event Log' -Check 'Application log size' -Expected '>= 65536 KB' -Actual $appLog -Compliant ( ($appLog -ne $null) -and ([int]$appLog -ge 65536) )
Add-Result -Id 'MP-13d' -Priority 'Medium' -Area 'Event Log' -Check 'System log size' -Expected '>= 65536 KB' -Actual $sysLog -Compliant ( ($sysLog -ne $null) -and ([int]$sysLog -ge 65536) )

# MP-14 LLMNR disabled
$llmnr = Get-Reg -Path 'SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast'
Add-Result -Id 'MP-14' -Priority 'Medium' -Area 'Name Resolution' -Check 'Disable LLMNR' -Expected 'EnableMulticast=0' -Actual $llmnr -Compliant (Test-ValueEq $llmnr 0)

# MP-15 Session/Screen lock
$ssSecure = Get-Reg -Hive HKCU -Path 'Control Panel\Desktop' -Name 'ScreenSaverIsSecure'
$ssTimeout = Get-Reg -Hive HKCU -Path 'Control Panel\Desktop' -Name 'ScreenSaveTimeOut'
$machIdle = Get-Reg -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs'
Add-Result -Id 'MP-15a' -Priority 'Medium' -Area 'Session' -Check 'Require password on resume' -Expected 'ScreenSaverIsSecure=1' -Actual $ssSecure -Compliant (Test-ValueEq $ssSecure 1)
Add-Result -Id 'MP-15b' -Priority 'Medium' -Area 'Session' -Check 'User idle timeout (<=900s)' -Expected '<= 900' -Actual $ssTimeout -Compliant ( ($ssTimeout -ne $null) -and ([int]$ssTimeout -le 900) )
Add-Result -Id 'MP-15c' -Priority 'Medium' -Area 'Session' -Check 'Machine inactivity limit' -Expected 'InactivityTimeoutSecs <= 900' -Actual $machIdle -Compliant ( ($machIdle -ne $null) -and ([int]$machIdle -le 900) )

# MP-16 Logon UX
$dontLast = Get-Reg -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DontDisplayLastUserName'
$disableCAD = Get-Reg -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DisableCAD'
Add-Result -Id 'MP-16a' -Priority 'Medium' -Area 'Logon' -Check 'Do not display last user name' -Expected '1' -Actual $dontLast -Compliant (Test-ValueEq $dontLast 1)
Add-Result -Id 'MP-16b' -Priority 'Medium' -Area 'Logon' -Check 'Require Ctrl+Alt+Del' -Expected 'DisableCAD=0' -Actual $disableCAD -Compliant (Test-ValueEq $disableCAD 0)

# MP-17 Remote UAC restrictions
$latfp = Get-Reg -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy'
Add-Result -Id 'MP-17' -Priority 'Medium' -Area 'UAC Remote' -Check 'Remote UAC restrictions' -Expected '0 or missing' -Actual $latfp -Compliant ( ($latfp -eq $null) -or (Test-ValueEq $latfp 0) )

# MP-18 Disable consumer features
$cons = Get-Reg -Path 'SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableConsumerFeatures'
Add-Result -Id 'MP-18' -Priority 'Medium' -Area 'Bloat' -Check 'Disable Consumer Features' -Expected '1' -Actual $cons -Compliant (Test-ValueEq $cons 1)

# MP-19 Telemetry
$tele = Get-Reg -Path 'SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry'
Add-Result -Id 'MP-19' -Priority 'Medium' -Area 'Telemetry' -Check 'Diagnostic data level' -Expected '0/1' -Actual $tele -Compliant ( ($tele -ne $null) -and ([int]$tele -le 1) )

# MP-20 Advertising ID
$adid = Get-Reg -Path 'SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' -Name 'Disabled'
Add-Result -Id 'MP-20' -Priority 'Medium' -Area 'Privacy' -Check 'Advertising ID' -Expected '1' -Actual $adid -Compliant (Test-ValueEq $adid 1)

# MP-21 Remote Assistance disabled
$ra = Get-Reg -Path 'SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp'
Add-Result -Id 'MP-21' -Priority 'Medium' -Area 'Remote Assistance' -Check 'Disable Remote Assistance' -Expected '0' -Actual $ra -Compliant (Test-ValueEq $ra 0)

# MP-22 Services: WinRM & RemoteRegistry
$svcWinRM = Get-Service -Name WinRM -ErrorAction SilentlyContinue
$svcRemoteReg = Get-Service -Name RemoteRegistry -ErrorAction SilentlyContinue
if ($svcWinRM) { Add-Result -Id 'MP-22a' -Priority 'Medium' -Area 'Services' -Check 'WinRM service' -Expected 'Disabled/Stopped' -Actual ("Status={0}; StartType={1}" -f $svcWinRM.Status,$svcWinRM.StartType) -Compliant ( ($svcWinRM.Status -eq 'Stopped') -and ($svcWinRM.StartType -eq 'Disabled') ) }
if ($svcRemoteReg) { Add-Result -Id 'MP-22b' -Priority 'Medium' -Area 'Services' -Check 'RemoteRegistry service' -Expected 'Disabled/Stopped' -Actual ("Status={0}; StartType={1}" -f $svcRemoteReg.Status,$svcRemoteReg.StartType) -Compliant ( ($svcRemoteReg.Status -eq 'Stopped') -and ($svcRemoteReg.StartType -eq 'Disabled') ) }

# MP-23 PowerShell v2 optional feature
try { $psv2 = (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction Stop).State } catch { $psv2 = 'QueryFailed' }
Add-Result -Id 'MP-23' -Priority 'Medium' -Area 'PowerShell' -Check 'PowerShell v2 feature' -Expected 'Disabled' -Actual $psv2 -Compliant ($psv2 -eq 'Disabled')

# MP-24 TLS protocols (Client & Server checks for TLS 1.0..1.3)
function Test-TLS {
  param([string]$Proto,[string]$Role,[int]$Expected)
  $key = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Proto\$Role"
  $enabled = Get-Reg -Path $key -Name 'Enabled'
  if ($Expected -eq 0) {
    $__tmpId = ("MP-24-{0}-{1}" -f $Proto,$Role) -replace ' ',''
    Add-Result -Id $__tmpId -Priority 'Medium' -Area 'TLS' -Check ("$Proto/$Role disabled") -Expected 'Enabled=0' -Actual ("Enabled={0}" -f $enabled) -Compliant (Test-ValueEq $enabled 0)
  } else {
    $__tmpId = ("MP-24-{0}-{1}" -f $Proto,$Role) -replace ' ',''
    Add-Result -Id $__tmpId -Priority 'Medium' -Area 'TLS' -Check ("$Proto/$Role enabled") -Expected 'Enabled=1' -Actual ("Enabled={0}" -f $enabled) -Compliant (Test-ValueEq $enabled 1)
  }
}
foreach ($role in @('Client','Server')) { Test-TLS 'TLS 1.0' $role 0 }
foreach ($role in @('Client','Server')) { Test-TLS 'TLS 1.1' $role 0 }
foreach ($role in @('Client','Server')) { Test-TLS 'TLS 1.2' $role 1 }
foreach ($role in @('Client','Server')) { Test-TLS 'TLS 1.3' $role 1 }

# MP-25 Device control (removable storage)
$denExe = Get-Reg -Path 'SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices' -Name 'Deny_Execute'
$denWri = Get-Reg -Path 'SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices' -Name 'Deny_Write'
$denAll = Get-Reg -Path 'SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices' -Name 'Deny_All'
Add-Result -Id 'MP-25a' -Priority 'Medium' -Area 'Device Control' -Check 'Deny Execute' -Expected '1' -Actual $denExe -Compliant (Test-ValueEq $denExe 1)
Add-Result -Id 'MP-25b' -Priority 'Medium' -Area 'Device Control' -Check 'Deny Write' -Expected '1' -Actual $denWri -Compliant (Test-ValueEq $denWri 1)
Add-Result -Id 'MP-25c' -Priority 'Medium' -Area 'Device Control' -Check 'Deny All' -Expected '1' -Actual $denAll -Compliant (Test-ValueEq $denAll 1)

# MP-26 User rights assignments (Deny network/RDP logon for local accounts)
$cfg = Join-Path $env:TEMP ('secpol_{0}.inf' -f ([guid]::NewGuid())); secedit /export /cfg $cfg | Out-Null
$lines = @(); try { $lines = Get-Content $cfg -ErrorAction SilentlyContinue } catch {}
Remove-Item $cfg -Force -ErrorAction SilentlyContinue
function Get-UserRight { param([string]$Right) return ($lines | Where-Object { $_ -match "^$Right\s*=" } | Select-Object -First 1) }
function Has-SID { param($line,$sid) if ($null -eq $line) { return $false } return ($line -match $sid) }
$denyNet   = Get-UserRight 'SeDenyNetworkLogonRight'
$denyRDP   = Get-UserRight 'SeDenyRemoteInteractiveLogonRight'
Add-Result -Id 'MP-26a' -Priority 'Medium' -Area 'User Rights' -Check 'Deny network logon - local accounts' -Expected 'S-1-5-113 & S-1-5-114 present' -Actual $denyNet -Compliant ( (Has-SID $denyNet 'S-1-5-113') -and (Has-SID $denyNet 'S-1-5-114') )
Add-Result -Id 'MP-26b' -Priority 'Medium' -Area 'User Rights' -Check 'Deny RDP logon - local accounts' -Expected 'S-1-5-113 & S-1-5-114 present' -Actual $denyRDP -Compliant ( (Has-SID $denyRDP 'S-1-5-113') -and (Has-SID $denyRDP 'S-1-5-114') )

# MP-27 Local accounts (Guest disabled, Admin renamed)
try { Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop } catch {}
try {
  $guest = Get-LocalUser -Name 'Guest' -ErrorAction Stop
  Add-Result -Id 'MP-27a' -Priority 'Medium' -Area 'Accounts' -Check 'Guest account disabled' -Expected 'Disabled' -Actual ("Enabled={0}" -f $guest.Enabled) -Compliant (-not $guest.Enabled)
} catch { Add-Result -Id 'MP-27a' -Priority 'Medium' -Area 'Accounts' -Check 'Guest account disabled' -Expected 'Disabled' -Actual 'Guest missing/handled' -Compliant $true }
try {
  $admin = Get-LocalUser | Where-Object { $_.SID.Value -match '-500$' } | Select-Object -First 1
  $renamed = ($admin -and $admin.Name -ne 'Administrator')
  Add-Result -Id 'MP-27b' -Priority 'Medium' -Area 'Accounts' -Check 'Administrator account renamed' -Expected 'Not "Administrator"' -Actual ("{0}" -f ($admin.Name)) -Compliant $renamed
} catch { Add-Result -Id 'MP-27b' -Priority 'Medium' -Area 'Accounts' -Check 'Administrator account renamed' -Expected 'Not "Administrator"' -Actual 'Query failed' -Compliant $false }

# MP-28 Force subcategory auditing
$sceNoLegacy = Get-Reg -Path 'SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy'
Add-Result -Id 'MP-28' -Priority 'Medium' -Area 'Auditing' -Check 'Force subcategory settings' -Expected 'SCENoApplyLegacyAuditPolicy=1' -Actual $sceNoLegacy -Compliant (Test-ValueEq $sceNoLegacy 1)

# MP-29 Limit blank passwords
$lbpu = Get-Reg -Path 'SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LimitBlankPasswordUse'
Add-Result -Id 'MP-29' -Priority 'Medium' -Area 'Accounts' -Check 'Limit blank passwords' -Expected '1' -Actual $lbpu -Compliant (Test-ValueEq $lbpu 1)

# MP-30 UAC related
$enableInstaller = Get-Reg -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableInstallerDetection'
$filterAdmin = Get-Reg -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'FilterAdministratorToken'
$secureUIA = Get-Reg -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableSecureUIAPaths'
$virt = Get-Reg -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableVirtualization'
Add-Result -Id 'MP-30a' -Priority 'Medium' -Area 'UAC' -Check 'Installer detection' -Expected '1' -Actual $enableInstaller -Compliant (Test-ValueEq $enableInstaller 1)
Add-Result -Id 'MP-30b' -Priority 'Medium' -Area 'UAC' -Check 'FilterAdministratorToken' -Expected '1' -Actual $filterAdmin -Compliant (Test-ValueEq $filterAdmin 1)
Add-Result -Id 'MP-30c' -Priority 'Medium' -Area 'UAC' -Check 'EnableSecureUIAPaths' -Expected '1' -Actual $secureUIA -Compliant (Test-ValueEq $secureUIA 1)
Add-Result -Id 'MP-30d' -Priority 'Medium' -Area 'UAC' -Check 'Virtualization' -Expected '1' -Actual $virt -Compliant (Test-ValueEq $virt 1)

# MP-31 Windows Installer AlwaysInstallElevated checks
$aieHKLM = Get-Reg -Path 'SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated'
$aieHKCU = Get-Reg -Hive HKCU -Path 'Software\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated'
Add-Result -Id 'MP-31a' -Priority 'Medium' -Area 'Windows Installer' -Check 'AlwaysInstallElevated (HKLM)' -Expected '0 or missing' -Actual $aieHKLM -Compliant ( ($aieHKLM -eq $null) -or (Test-ValueEq $aieHKLM 0) )
Add-Result -Id 'MP-31b' -Priority 'Medium' -Area 'Windows Installer' -Check 'AlwaysInstallElevated (HKCU)' -Expected '0 or missing' -Actual $aieHKCU -Compliant ( ($aieHKCU -eq $null) -or (Test-ValueEq $aieHKCU 0) )

# MP-32 BitLocker policy checks
$polBase = 'SOFTWARE\Policies\Microsoft\FVE'
$encOs = Get-Reg -Path $polBase -Name 'EncryptionMethodWithXtsOs'
$reqAuth = Get-Reg -Path $polBase -Name 'RequireAdditionalAuthenticationAtStartup'
Add-Result -Id 'MP-32a' -Priority 'Medium' -Area 'BitLocker' -Check 'OS XTS method (policy)' -Expected '>= 3 (XTS 128+)' -Actual $encOs -Compliant ( ($encOs -ne $null) -and ([int]$encOs -ge 3) )
Add-Result -Id 'MP-32b' -Priority 'Medium' -Area 'BitLocker' -Check 'Require additional auth at startup' -Expected '1' -Actual $reqAuth -Compliant (Test-ValueEq $reqAuth 1)

# MP-33 DMA DeviceEnumerationPolicy
$dmaPol = Get-Reg -Path 'SYSTEM\CurrentControlSet\Control\DmaSecurity' -Name 'DeviceEnumerationPolicy'
Add-Result -Id 'MP-33' -Priority 'Medium' -Area 'DMA' -Check 'DeviceEnumerationPolicy' -Expected '0 (Block under lock)' -Actual $dmaPol -Compliant (Test-ValueEq $dmaPol 0)

# MP-34 Windows Hello / FIDO2
$whfb = Get-Reg -Path 'SOFTWARE\Policies\Microsoft\PassportForWork' -Name 'Enabled'
$fido = Get-Reg -Path 'SOFTWARE\Policies\Microsoft\FIDO' -Name 'EnableFIDODeviceSignon'
Add-Result -Id 'MP-34a' -Priority 'Medium' -Area 'WHfB' -Check 'Windows Hello for Business' -Expected 'Enabled=1 (if org uses WHfB)' -Actual $whfb -Compliant (Test-ValueEq $whfb 1)
Add-Result -Id 'MP-34b' -Priority 'Medium' -Area 'FIDO2' -Check 'Security Keys sign-in' -Expected 'EnableFIDODeviceSignon=1' -Actual $fido -Compliant (Test-ValueEq $fido 1)

# MP-35 LAPS (legacy & Windows LAPS)
$admBase = 'SOFTWARE\Policies\Microsoft Services\AdmPwd'
$admEnabled = Get-Reg -Path $admBase -Name 'AdmPwdEnabled'
$admLen = Get-Reg -Path $admBase -Name 'PasswordLength'
$admAge = Get-Reg -Path $admBase -Name 'PasswordAgeDays'
$admComp = Get-Reg -Path $admBase -Name 'PasswordComplexity'
Add-Result -Id 'MP-35a' -Priority 'Medium' -Area 'LAPS (Legacy)' -Check 'AdmPwdEnabled' -Expected '1' -Actual $admEnabled -Compliant (Test-ValueEq $admEnabled 1)
Add-Result -Id 'MP-35b' -Priority 'Medium' -Area 'LAPS (Legacy)' -Check 'PasswordLength >= 15' -Expected '>= 15' -Actual $admLen -Compliant ( ($admLen -ne $null) -and ([int]$admLen -ge 15) )
Add-Result -Id 'MP-35c' -Priority 'Medium' -Area 'LAPS (Legacy)' -Check 'PasswordAgeDays <= 30' -Expected '<= 30' -Actual $admAge -Compliant ( ($admAge -ne $null) -and ([int]$admAge -le 30) )
Add-Result -Id 'MP-35d' -Priority 'Medium' -Area 'LAPS (Legacy)' -Check 'PasswordComplexity >= 3' -Expected '>= 3' -Actual $admComp -Compliant ( ($admComp -ne $null) -and ([int]$admComp -ge 3) )

$wlapsBase = 'SOFTWARE\Policies\Microsoft\Windows\LAPS'
$wEnable = Get-Reg -Path $wlapsBase -Name 'EnableLAPS'
$wLen = Get-Reg -Path $wlapsBase -Name 'PasswordLength'
$wAge = Get-Reg -Path $wlapsBase -Name 'PasswordAgeDays'
$wComp = Get-Reg -Path $wlapsBase -Name 'PasswordComplexity'
$wBackup = Get-Reg -Path $wlapsBase -Name 'BackupDirectory'
Add-Result -Id 'MP-35e' -Priority 'Medium' -Area 'Windows LAPS' -Check 'EnableLAPS' -Expected '1' -Actual $wEnable -Compliant (Test-ValueEq $wEnable 1)
Add-Result -Id 'MP-35f' -Priority 'Medium' -Area 'Windows LAPS' -Check 'PasswordLength >= 15' -Expected '>= 15' -Actual $wLen -Compliant ( ($wLen -ne $null) -and ([int]$wLen -ge 15) )
Add-Result -Id 'MP-35g' -Priority 'Medium' -Area 'Windows LAPS' -Check 'PasswordAgeDays <= 30' -Expected '<= 30' -Actual $wAge -Compliant ( ($wAge -ne $null) -and ([int]$wAge -le 30) )
Add-Result -Id 'MP-35h' -Priority 'Medium' -Area 'Windows LAPS' -Check 'PasswordComplexity >= 3' -Expected '>= 3' -Actual $wComp -Compliant ( ($wComp -ne $null) -and ([int]$wComp -ge 3) )
Add-Result -Id 'MP-35i' -Priority 'Medium' -Area 'Windows LAPS' -Check 'BackupDirectory set' -Expected '1 (AD) or 2 (AAD)' -Actual $wBackup -Compliant ( ($wBackup -in 1,2) )

# MP-36 Hardened UNC paths (SYSVOL/NETLOGON)
try {
  $hpKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
  $hpProps = Get-ItemProperty -Path $hpKey -ErrorAction Stop
  $sysvol = $hpProps.'\\*\SYSVOL'; $netlogon = $hpProps.'\\*\NETLOGON'
  $sysOk = ($sysvol -and $sysvol -match 'RequireMutualAuthentication=1' -and $sysvol -match 'RequireIntegrity=1')
  $netOk = ($netlogon -and $netlogon -match 'RequireMutualAuthentication=1' -and $netlogon -match 'RequireIntegrity=1')
  Add-Result -Id 'MP-36a' -Priority 'Medium' -Area 'UNC Hardening' -Check '\\*\SYSVOL hardened' -Expected 'RequireMutualAuth, RequireIntegrity' -Actual $sysvol -Compliant $sysOk
  Add-Result -Id 'MP-36b' -Priority 'Medium' -Area 'UNC Hardening' -Check '\\*\NETLOGON hardened' -Expected 'RequireMutualAuth, RequireIntegrity' -Actual $netlogon -Compliant $netOk
} catch { Add-Result -Id 'MP-36' -Priority 'Medium' -Area 'UNC Hardening' -Check 'Policy exists' -Expected 'Values present' -Actual 'HardenedPaths key missing' -Compliant $false }

# MP-37 Printing lockdown
$rpcPriv = Get-Reg -Path 'SYSTEM\CurrentControlSet\Control\Print' -Name 'RpcAuthnLevelPrivacyEnabled'
Add-Result -Id 'MP-37a' -Priority 'Medium' -Area 'Printing' -Check 'RPC privacy required' -Expected '1' -Actual $rpcPriv -Compliant (Test-ValueEq $rpcPriv 1)
$pnBase = 'SOFTWARE\Policies\Microsoft\Windows NT\Printers'
$disableHttp = Get-Reg -Path $pnBase -Name 'DisableHTTPPrinting'
$disableWebPnP = Get-Reg -Path $pnBase -Name 'DisableWebPnPDownload'
Add-Result -Id 'MP-37b' -Priority 'Medium' -Area 'Printing' -Check 'Disable HTTP printing' -Expected '1' -Actual $disableHttp -Compliant (Test-ValueEq $disableHttp 1)
Add-Result -Id 'MP-37c' -Priority 'Medium' -Area 'Printing' -Check 'Disable WebPnP download' -Expected '1' -Actual $disableWebPnP -Compliant (Test-ValueEq $disableWebPnP 1)
$spool = Get-Service -Name Spooler -ErrorAction SilentlyContinue
if ($spool) { Add-Result -Id 'MP-37d' -Priority 'Medium' -Area 'Printing' -Check 'Spooler service stopped' -Expected 'Stopped (if not printing)' -Actual ("{0}" -f $spool.Status) -Compliant ($spool.Status -eq 'Stopped') }

# MP-38 Windows Update policy
$wauNo = Get-Reg -Path 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate'
$wauOpt = Get-Reg -Path 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'AUOptions'
Add-Result -Id 'MP-38a' -Priority 'Medium' -Area 'Windows Update' -Check 'NoAutoUpdate' -Expected '0 or missing' -Actual $wauNo -Compliant ( ($wauNo -eq $null) -or (Test-ValueEq $wauNo 0) )
Add-Result -Id 'MP-38b' -Priority 'Medium' -Area 'Windows Update' -Check 'AUOptions' -Expected '4 (Auto download & schedule install)' -Actual $wauOpt -Compliant (Test-ValueEq $wauOpt 4)

# MP-39 Office macro policies
$owBaseHKLM = 'SOFTWARE\Policies\Microsoft\Office\16.0\word\Security'
$owBaseHKCU = 'Software\Policies\Microsoft\Office\16.0\word\Security'
$vbWarnLM = Get-Reg -Path $owBaseHKLM -Name 'VBAWarnings'
$vbWarnCU = Get-Reg -Hive HKCU -Path $owBaseHKCU -Name 'VBAWarnings'
$blockFromNetLM = Get-Reg -Path $owBaseHKLM -Name 'BlockContentExecutionFromInternet'
$blockFromNetCU = Get-Reg -Hive HKCU -Path $owBaseHKCU -Name 'BlockContentExecutionFromInternet'
Add-Result -Id 'MP-39a' -Priority 'Medium' -Area 'Office' -Check 'VBAWarnings (HKLM/HKCU)=4' -Expected '4 (Disable w/ notification)' -Actual ("HKLM={0}; HKCU={1}" -f $vbWarnLM,$vbWarnCU) -Compliant ( ($vbWarnLM -eq 4) -or ($vbWarnCU -eq 4) )
Add-Result -Id 'MP-39b' -Priority 'Medium' -Area 'Office' -Check 'Block macros from internet' -Expected '1' -Actual ("HKLM={0}; HKCU={1}" -f $blockFromNetLM,$blockFromNetCU) -Compliant ( ($blockFromNetLM -eq 1) -or ($blockFromNetCU -eq 1) )
$pvBlockNet = Get-Reg -Path 'SOFTWARE\Policies\Microsoft\Office\16.0\word\security\protectedview' -Name 'DisableInternetFilesInPV'
Add-Result -Id 'MP-39c' -Priority 'Medium' -Area 'Office' -Check 'Protected View for internet files' -Expected 'DisableInternetFilesInPV=0' -Actual $pvBlockNet -Compliant (Test-ValueEq $pvBlockNet 0)

# MP-40 USB mass storage disabled (service)
$usbstor = Get-Service -Name USBSTOR -ErrorAction SilentlyContinue
if ($usbstor) { Add-Result -Id 'MP-40' -Priority 'Medium' -Area 'Device Control' -Check 'USB mass storage disabled' -Expected 'Stopped/Disabled' -Actual ("Status={0}; StartType={1}" -f $usbstor.Status,$usbstor.StartType) -Compliant ( ($usbstor.Status -eq 'Stopped') -and ($usbstor.StartType -eq 'Disabled') ) }

# MP-41 Windows Script Host disabled (optional)
$wshLM = Get-Reg -Path 'SOFTWARE\Microsoft\Windows Script Host\Settings' -Name 'Enabled'
$wshCU = Get-Reg -Hive HKCU -Path 'Software\Microsoft\Windows Script Host\Settings' -Name 'Enabled'
Add-Result -Id 'MP-41' -Priority 'Medium' -Area 'Scripting' -Check 'Disable WSH (optional)' -Expected 'Enabled=0 (HKLM/HKCU)' -Actual ("HKLM={0}; HKCU={1}" -f $wshLM,$wshCU) -Compliant ( ($wshLM -eq 0) -or ($wshCU -eq 0) )

# MP-42 SNMP services
$snmp = Get-Service -Name SNMP -ErrorAction SilentlyContinue
$snmpTrap = Get-Service -Name SNMPTRAP -ErrorAction SilentlyContinue
if ($snmp) { Add-Result -Id 'MP-42a' -Priority 'Medium' -Area 'Services' -Check 'SNMP service' -Expected 'Disabled/Stopped' -Actual ("Status={0}; StartType={1}" -f $snmp.Status,$snmp.StartType) -Compliant ( ($snmp.Status -eq 'Stopped') -and ($snmp.StartType -eq 'Disabled') ) }
if ($snmpTrap) { Add-Result -Id 'MP-42b' -Priority 'Medium' -Area 'Services' -Check 'SNMP Trap service' -Expected 'Disabled/Stopped' -Actual ("Status={0}; StartType={1}" -f $snmpTrap.Status,$snmpTrap.StartType) -Compliant ( ($snmpTrap.Status -eq 'Stopped') -and ($snmpTrap.StartType -eq 'Disabled') ) }

# MP-43 SMB Server configuration
try {
  $sc = Get-SmbServerConfiguration -ErrorAction Stop
  Add-Result -Id 'MP-43a' -Priority 'Medium' -Area 'SMB Server' -Check 'EnableSMB1Protocol=False' -Expected 'False' -Actual $sc.EnableSMB1Protocol -Compliant (-not $sc.EnableSMB1Protocol)
  Add-Result -Id 'MP-43b' -Priority 'Medium' -Area 'SMB Server' -Check 'EnableSMB2Protocol=True' -Expected 'True' -Actual $sc.EnableSMB2Protocol -Compliant ($sc.EnableSMB2Protocol)
  Add-Result -Id 'MP-43c' -Priority 'Medium' -Area 'SMB Server' -Check 'RequireSecuritySignature=True' -Expected 'True' -Actual $sc.RequireSecuritySignature -Compliant ($sc.RequireSecuritySignature)
  Add-Result -Id 'MP-43d' -Priority 'Medium' -Area 'SMB Server' -Check 'EnableSecuritySignature=True' -Expected 'True' -Actual $sc.EnableSecuritySignature -Compliant ($sc.EnableSecuritySignature)
  Add-Result -Id 'MP-43e' -Priority 'Medium' -Area 'SMB Server' -Check 'RejectUnencryptedAccess=True' -Expected 'True' -Actual $sc.RejectUnencryptedAccess -Compliant ($sc.RejectUnencryptedAccess)
} catch { Add-Result -Id 'MP-43' -Priority 'Medium' -Area 'SMB Server' -Check 'Server configuration' -Expected 'Accessible' -Actual 'Get-SmbServerConfiguration failed' -Compliant $false }

# MP-44 SMB Client configuration
try {
  $clientConf = Get-SmbClientConfiguration -ErrorAction Stop
  Add-Result -Id 'MP-44' -Priority 'Medium' -Area 'SMB Client' -Check 'Client configuration accessible' -Expected 'Accessible' -Actual $clientConf -Compliant $true
  Add-Result -Id 'MP-44a' -Priority 'Medium' -Area 'SMB Client' -Check 'EnableInsecureGuestLogons=False' -Expected 'False' -Actual $clientConf.EnableInsecureGuestLogons -Compliant (-not $clientConf.EnableInsecureGuestLogons)
  Add-Result -Id 'MP-44b' -Priority 'Medium' -Area 'SMB Client' -Check 'RequireSecuritySignature=True' -Expected 'True' -Actual $clientConf.RequireSecuritySignature -Compliant ($clientConf.RequireSecuritySignature)
  Add-Result -Id 'MP-44c' -Priority 'Medium' -Area 'SMB Client' -Check 'EnableSecuritySignature=True' -Expected 'True' -Actual $clientConf.EnableSecuritySignature -Compliant ($clientConf.EnableSecuritySignature)
} catch { Add-Result -Id 'MP-44' -Priority 'Medium' -Area 'SMB Client' -Check 'Client configuration' -Expected 'Accessible' -Actual 'Get-SmbClientConfiguration failed' -Compliant $false }

# MP-45 Kernel SafeDllSearchMode
$sd = Get-Reg -Path 'SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'SafeDllSearchMode'
Add-Result -Id 'MP-45' -Priority 'Medium' -Area 'Kernel' -Check 'SafeDllSearchMode' -Expected '1' -Actual $sd -Compliant (Test-ValueEq $sd 1)

# MP-46 NullSessionPipes empty
try {
  $ns = Get-Reg -Path 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'NullSessionPipes'
  $count = if ($ns -is [array]) { $ns.Count } elseif ($ns) { 1 } else { 0 }
  Add-Result -Id 'MP-46' -Priority 'Medium' -Area 'SMB' -Check 'NullSessionPipes empty' -Expected '0 entries' -Actual ("Count={0}" -f $count) -Compliant ($count -eq 0)
} catch { Add-Result -Id 'MP-46' -Priority 'Medium' -Area 'SMB' -Check 'NullSessionPipes' -Expected '0 entries' -Actual 'Query failed' -Compliant $false }

# =================== AUDITING (MP-AUD) ===================
# Use auditpol to read subcategory audit settings; if auditpol output is messy, return Not configured
try {
  $audit = auditpol /get /category:* 2>&1 | Out-String
  # parse lines like: "Account Logon    Logon Success and Failure"
  $lines = $audit -split "`r?`n" | Where-Object { $_ -match '\S' }
  foreach ($target in @('Audit Policy Change','Authentication Policy Change','Authorization Policy Change','Credential Validation','DPAPI Activity','File Share','Logoff','Logon','Object Access','Other Logon/Logoff Events','Plug and Play Events','Process Creation','Process Termination','Registry','Removable Storage','Security Group Management','Sensitive Privilege Use','Special Logon','System Integrity','User Account Management')) {
    $match = $lines | Where-Object { $_ -match [regex]::Escape($target) } | Select-Object -First 1
    if ($match) {
      $setting = ($match -replace ' +',' ') -replace '^\s+',''
      Add-Result -Id ("MP-AUD-{0}" -f ($target -replace '\s+','_')) -Priority 'Medium' -Area 'Auditing' -Check ("Audit {0}" -f $target) -Expected 'Success and Failure' -Actual $setting -Compliant ($setting -match 'Success' -and $setting -match 'Failure')
    } else {
      Add-Result -Id ("MP-AUD-{0}" -f ($target -replace '\s+','_')) -Priority 'Medium' -Area 'Auditing' -Check ("Audit {0}" -f $target) -Expected 'Success and Failure' -Actual 'No Auditing/Not Set' -Compliant $false
    }
  }
} catch { Add-Result -Id 'MP-AUD' -Priority 'Medium' -Area 'Auditing' -Check 'AuditPol query' -Expected 'Readable' -Actual 'auditpol failed' -Compliant $false }

# =================== LOW PRIORITY ===================

Add-Result -Id 'LP-01' -Priority 'Low' -Area 'UX' -Check 'Display file extensions' -Expected 'HideFileExt=0' -Actual (Get-Reg -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt') -Compliant (Test-ValueEq (Get-Reg -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt') 0)
Add-Result -Id 'LP-02' -Priority 'Low' -Area 'Store' -Check 'Disable Microsoft Store' -Expected '1' -Actual (Get-Reg -Path 'SOFTWARE\Policies\Microsoft\WindowsStore' -Name 'RemoveWindowsStore') -Compliant (Test-ValueEq (Get-Reg -Path 'SOFTWARE\Policies\Microsoft\WindowsStore' -Name 'RemoveWindowsStore') 1)
Add-Result -Id 'LP-03' -Priority 'Low' -Area 'Search' -Check 'Disable Cortana' -Expected '0' -Actual (Get-Reg -Path 'SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortana') -Compliant (Test-ValueEq (Get-Reg -Path 'SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortana') 0)
Add-Result -Id 'LP-04' -Priority 'Low' -Area 'AutoPlay' -Check 'Per-user NoDriveTypeAutoRun' -Expected '255' -Actual (Get-Reg -Hive HKCU -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun') -Compliant (Test-ValueEq (Get-Reg -Hive HKCU -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun') 255)
Add-Result -Id 'LP-05' -Priority 'Low' -Area 'WER' -Check 'Windows Error Reporting' -Expected 'Disabled=1' -Actual (Get-Reg -Path 'SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' -Name 'Disabled') -Compliant (Test-ValueEq (Get-Reg -Path 'SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' -Name 'Disabled') 1)

# ------------------ Finalize and Output ------------------
$Results = $Results | Sort-Object @{Expression='Priority';Descending=$false}, Id
# Print nicely to console
$Results | Format-Table -AutoSize

# Persist CSV and JSON
$now = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$JsonPath = Join-Path (Get-Location) ("WinHardening_Audit_$now.json")
$CsvPath  = Join-Path (Get-Location) ("WinHardening_Audit_$now.csv")
try {
  $Results | ConvertTo-Json -Depth 4 | Out-File -Encoding UTF8 $JsonPath
  
# =====================[ Extra Checks Integration ]=====================

# =====================[ BEGIN: Extra Hardening Checks (merged) ]=====================
function Invoke-ExtraChecks {
  Write-Host "[+] Running extra hardening checks (EX-001..EX-023)"

  function _GetRegVal([string]$Path,[string]$Name) {
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
  }
  function _IsOn($v) { try { return [string]$v -match '^(On|True|1)$' } catch { return $false } }

  # EX-001 Credential Guard
  $val = _GetRegVal 'HKLM:\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard' 'Enabled'
  $ok = $null -ne $val -and ($val -in 1,2)
  Add-Result -Id 'EX-001' -Priority 'High' -Area 'Credential Protection' -Check 'Credential Guard enabled' -Expected 'Enabled (1 or 2)' -Actual ($val) -Compliant $ok

  # EX-002 LSA Protection (RunAsPPL)
  $val = _GetRegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
  $ok  = $val -in 1,2
  Add-Result -Id 'EX-002' -Priority 'High' -Area 'Credential Protection' -Check 'LSA Protection (RunAsPPL)' -Expected '1 or 2' -Actual ($val) -Compliant $ok

  # EX-003 WDigest
  $val = _GetRegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
  $ok  = ($val -eq 0) -or ($null -eq $val)
  Add-Result -Id 'EX-003' -Priority 'High' -Area 'Credential Protection' -Check 'Disable WDigest cleartext caching' -Expected '0 or Not Present' -Actual ($val) -Compliant $ok

  # EX-004 SMBv1 disabled
  $state = 'Unknown'
  try { $state = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop).State } catch {}
  Add-Result -Id 'EX-004' -Priority 'High' -Area 'SMB' -Check 'SMBv1 protocol disabled' -Expected 'Disabled' -Actual $state -Compliant ($state -eq 'Disabled')

  # EX-005 Server SMB signing
  $v = _GetRegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature'
  Add-Result -Id 'EX-005' -Priority 'High' -Area 'SMB' -Check 'Server: Require SMB signing' -Expected '1' -Actual $v -Compliant ($v -eq 1)

  # EX-006 Client SMB signing
  $v = _GetRegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature'
  Add-Result -Id 'EX-006' -Priority 'High' -Area 'SMB' -Check 'Client: Require SMB signing' -Expected '1' -Actual $v -Compliant ($v -eq 1)

  # EX-007 Script Block Logging
  $v = _GetRegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
  Add-Result -Id 'EX-007' -Priority 'Medium' -Area 'Logging' -Check 'PowerShell Script Block Logging' -Expected '1' -Actual $v -Compliant ($v -eq 1)

  # EX-008 Module Logging
  $v = _GetRegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging'
  Add-Result -Id 'EX-008' -Priority 'Medium' -Area 'Logging' -Check 'PowerShell Module Logging' -Expected '1' -Actual $v -Compliant ($v -eq 1)

  # EX-009 Transcription
  $v = _GetRegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting'
  Add-Result -Id 'EX-009' -Priority 'Medium' -Area 'Logging' -Check 'PowerShell Transcription' -Expected '1' -Actual $v -Compliant ($v -eq 1)

  # EX-010 AppLocker/WDAC present
  $appLocker = $false; $wdac = $false
  try { $pol = Get-AppLockerPolicy -Effective -ErrorAction Stop; $appLocker = $pol.RuleCollections.Count -gt 0 } catch {}
  $wdac = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
  Add-Result -Id 'EX-010' -Priority 'High' -Area 'Application Control' -Check 'Allow-listing in place (AppLocker/WDAC)' -Expected 'Present' -Actual ("AppLocker={0};WDAC={1}" -f $appLocker,$wdac) -Compliant ($appLocker -or $wdac)

  # EX-011 ASR rules enabled (heuristic)
  $asrKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
  $enabled = 0
  if (Test-Path $asrKey) {
    (Get-Item $asrKey).Property | ForEach-Object {
      $vv = _GetRegVal $asrKey $_
      if ($vv -in 1,2) { $enabled++ }
    }
  }
  Add-Result -Id 'EX-011' -Priority 'High' -Area 'Defender ASR' -Check 'Attack Surface Reduction rules' -Expected 'Several ASR rules enabled' -Actual ("EnabledRules={0}" -f $enabled) -Compliant ($enabled -ge 5)

  # EX-012 Exploit Protection (DEP/ASLR)
  $dep='Unknown'; $aslr='Unknown'; $ok=$false
  try {
    $mit = Get-ProcessMitigation -System
    $dep = $mit.Dep.Enable; $aslr = $mit.ASLR.ForceRelocateImages
    $ok = ($dep -eq 'ON') -and ($aslr -in 'ON','OPT_OUT')
  } catch {}
  Add-Result -Id 'EX-012' -Priority 'High' -Area 'Exploit Protection' -Check 'DEP and ASLR (system)' -Expected 'DEP=ON; ASLR=ON/OPT_OUT' -Actual ("DEP={0};ASLR={1}" -f $dep,$aslr) -Compliant $ok

  # EX-013 RDP NLA
  $v = _GetRegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
  Add-Result -Id 'EX-013' -Priority 'High' -Area 'RDP' -Check 'Require Network Level Authentication' -Expected '1' -Actual $v -Compliant ($v -eq 1)

  # EX-014 NTLM hardening
  $v = _GetRegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
  Add-Result -Id 'EX-014' -Priority 'High' -Area 'Auth' -Check 'NTLM hardening (LmCompatibilityLevel)' -Expected '>= 5' -Actual $v -Compliant (($null -ne $v) -and ([int]$v -ge 5))

  # EX-015 Secure Boot
  $actual='Unknown'; $ok=$false
  try {
    if ($env:firmware_type -eq 'UEFI' -and (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)) {
      if (Confirm-SecureBootUEFI) { $actual='On'; $ok=$true } else { $actual='Off' }
    } else { $actual='Legacy BIOS or cmdlet unavailable' }
  } catch {}
  Add-Result -Id 'EX-015' -Priority 'High' -Area 'Firmware' -Check 'UEFI Secure Boot enabled' -Expected 'On' -Actual $actual -Compliant $ok

  # EX-016 BitLocker OS
  $actual='Unknown'; $ok=$false
  try {
    $bv = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction Stop
    if ($bv.ProtectionStatus -eq 'On') { $actual='On'; $ok=$true } else { $actual=$bv.ProtectionStatus }
  } catch {}
  Add-Result -Id 'EX-016' -Priority 'High' -Area 'Disk Encryption' -Check 'BitLocker enabled on OS drive (C:)' -Expected 'On' -Actual $actual -Compliant $ok

  # EX-017 Defender Tamper Protection
  $actual='Unknown'; $ok=$false
  try { $mp = Get-MpComputerStatus; if ($null -ne $mp.TamperProtectionEnabled) { $ok=[bool]$mp.TamperProtectionEnabled; $actual = [string]$mp.TamperProtectionEnabled } } catch {}
  Add-Result -Id 'EX-017' -Priority 'Medium' -Area 'Defender' -Check 'Tamper Protection enabled' -Expected 'True' -Actual $actual -Compliant $ok

  # EX-018 SmartScreen
  $ss = _GetRegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen'
  $lvl = _GetRegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'ShellSmartScreenLevel'
  $ok = ($ss -eq 1) -and ($lvl -in 'Block','Warn')
  Add-Result -Id 'EX-018' -Priority 'Medium' -Area 'Browser/OS' -Check 'Windows SmartScreen' -Expected 'Enabled; Level=Block/Warn' -Actual ("Enable={0};Level={1}" -f $ss,$lvl) -Compliant $ok

  # EX-019 AutoRun disabled
  $ndr = _GetRegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
  $ok = ($null -ne $ndr) -and (([int]$ndr -band 255) -eq 255)
  Add-Result -Id 'EX-019' -Priority 'Medium' -Area 'Removable Media' -Check 'Disable AutoRun/AutoPlay' -Expected 'NoDriveTypeAutoRun=255' -Actual $ndr -Compliant $ok

  # EX-020 Remote Registry
  $svc = Get-Service -Name 'RemoteRegistry' -ErrorAction SilentlyContinue
  $actual='NotInstalled'; $ok=$false
  if ($svc) { $actual = "$($svc.Status)/$($svc.StartType)"; $ok = ($svc.Status -eq 'Stopped' -and $svc.StartType -in 'Disabled','Manual') }
  Add-Result -Id 'EX-020' -Priority 'Medium' -Area 'Services' -Check 'Remote Registry service' -Expected 'Stopped/Disabled' -Actual $actual -Compliant $ok

  # EX-021 Print Spooler (workstations)
  $svc = Get-Service -Name 'Spooler' -ErrorAction SilentlyContinue
  $actual='NotInstalled'; $ok=$false
  if ($svc) { $actual = "$($svc.Status)/$($svc.StartType)"; $ok = ($svc.Status -eq 'Stopped' -and $svc.StartType -eq 'Disabled') }
  Add-Result -Id 'EX-021' -Priority 'Medium' -Area 'Services' -Check 'Print Spooler disabled (non-print servers)' -Expected 'Stopped/Disabled' -Actual $actual -Compliant $ok

  # EX-022 Guest account disabled
  $actual='NotFound'; $ok=$false
  try { $guest = Get-LocalUser -Name 'Guest' -ErrorAction Stop; $ok = -not $guest.Enabled; $actual = "Enabled=$($guest.Enabled)" } catch {}
  Add-Result -Id 'EX-022' -Priority 'High' -Area 'Accounts' -Check 'Guest account disabled' -Expected 'Disabled' -Actual $actual -Compliant $ok

  # EX-023 LAPS (on-prem)
  $adm = _GetRegVal 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' 'AdmPwdEnabled'
  Add-Result -Id 'EX-023' -Priority 'High' -Area 'Accounts' -Check 'LAPS (on-prem) enabled' -Expected '1' -Actual $adm -Compliant ($adm -eq 1)
}
# =====================[  END: Extra Hardening Checks (merged) ]=====================

try { Invoke-ExtraChecks } catch { Write-Host "[!] Extra checks failed: $_" }
# =======================================================================
$Results | Export-Csv -NoTypeInformation -Encoding UTF8 $CsvPath
  Write-Host "`nSaved:" -ForegroundColor Cyan
  Write-Host "  JSON: $JsonPath"
  Write-Host "  CSV : $CsvPath`n"
} catch {
  Write-Warning "Failed to write JSON/CSV: $_"
}

# Summary footer
$total = $Results.Count
$byPriority = $Results | Group-Object Priority
Write-Host "Summary ($total checks):"
foreach ($g in $byPriority) {
  $pass = ($g.Group | Where-Object { $_.Compliant -eq 'PASS' }).Count
  $fail = ($g.Group | Where-Object { $_.Compliant -eq 'FAIL' }).Count
  Write-Host ("  {0}: {1} PASS / {2} FAIL" -f $g.Name, $pass, $fail)
}

# Fail on High findings if requested
if ($FailOnHighFindings) {
  $highFails = $Results | Where-Object { $_.Priority -eq 'High' -and $_.Compliant -eq 'FAIL' }
  if ($highFails.Count -gt 0) {
    Write-Error ("High-priority findings: {0}" -f $highFails.Count)
    exit 2
  }
}

exit 0
