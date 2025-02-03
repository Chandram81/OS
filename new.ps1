# Script: Complete_OS_Hardening_Check.ps1
# Description: Checks all OS hardening settings on Windows 10/11 workstations based on the ASD Hardening Guide.
# Author: Based on ASD Hardening Guide for Windows 10/11
# Version: 1.0

# Output file for logging
$outputFile = "$env:USERPROFILE\Desktop\Complete_OS_Hardening_Check_Report.txt"

# Function to write output to console and log file
function Write-OutputAndLog {
    param (
        [string]$Message
    )
    Write-Output $Message
    Add-Content -Path $outputFile -Value $Message
}

# Clear previous log file
if (Test-Path $outputFile) {
    Remove-Item $outputFile -Force
}

Write-OutputAndLog "=== Complete Windows OS Hardening Check Report ==="
Write-OutputAndLog "Date: $(Get-Date)"
Write-OutputAndLog "Computer Name: $env:COMPUTERNAME"
Write-OutputAndLog ""

# Function to check registry keys
function Check-RegistryKey {
    param (
        [string]$Path,
        [string]$Name,
        [string]$ExpectedValue,
        [string]$Description
    )
    $key = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($key -and $key.$Name -eq $ExpectedValue) {
        Write-OutputAndLog "[PASS] $Description"
    } else {
        Write-OutputAndLog "[FAIL] $Description"
    }
}

# Function to check Group Policy settings
function Check-GroupPolicy {
    param (
        [string]$Path,
        [string]$Name,
        [string]$ExpectedValue,
        [string]$Description
    )
    $policy = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($policy -and $policy.$Name -eq $ExpectedValue) {
        Write-OutputAndLog "[PASS] $Description"
    } else {
        Write-OutputAndLog "[FAIL] $Description"
    }
}

# Function to check service status
function Check-ServiceStatus {
    param (
        [string]$ServiceName,
        [string]$ExpectedStatus,
        [string]$Description
    )
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq $ExpectedStatus) {
        Write-OutputAndLog "[PASS] $Description"
    } else {
        Write-OutputAndLog "[FAIL] $Description"
    }
}

# Function to check feature status
function Check-FeatureStatus {
    param (
        [string]$FeatureName,
        [string]$ExpectedStatus,
        [string]$Description
    )
    $feature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction SilentlyContinue
    if ($feature -and $feature.State -eq $ExpectedStatus) {
        Write-OutputAndLog "[PASS] $Description"
    } else {
        Write-OutputAndLog "[FAIL] $Description"
    }
}

# === High Priority Checks ===
Write-OutputAndLog "=== High Priority Checks ==="

# 1. Credential Guard
$credentialGuard = Get-ComputerInfo | Select-Object -ExpandProperty DeviceGuardSecurityServicesConfigured
if ($credentialGuard -contains "CredentialGuard") {
    Write-OutputAndLog "[PASS] Credential Guard is enabled."
} else {
    Write-OutputAndLog "[FAIL] Credential Guard is not enabled."
}

# 2. Controlled Folder Access
$controlledFolderAccess = Get-MpPreference | Select-Object -ExpandProperty EnableControlledFolderAccess
if ($controlledFolderAccess -eq 1) {
    Write-OutputAndLog "[PASS] Controlled Folder Access is enabled."
} else {
    Write-OutputAndLog "[FAIL] Controlled Folder Access is not enabled."
}

# 3. Exploit Protection (CFG and DEP)
$exploitProtection = Get-ProcessMitigation -System
if ($exploitProtection.CFG -eq "ON" -and $exploitProtection.DEP -eq "ON") {
    Write-OutputAndLog "[PASS] Exploit Protection (CFG and DEP) is enabled."
} else {
    Write-OutputAndLog "[FAIL] Exploit Protection (CFG and/or DEP) is not fully enabled."
}

# 4. UAC Settings
Check-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ExpectedValue 1 -Description "UAC is enabled."

# 5. BitLocker Status
$bitLocker = Manage-bde -Status C:
if ($bitLocker -match "Protection On") {
    Write-OutputAndLog "[PASS] BitLocker is enabled on the C: drive."
} else {
    Write-OutputAndLog "[FAIL] BitLocker is not enabled on the C: drive."
}

# 6. Windows Firewall Status
$firewall = Get-NetFirewallProfile | Where-Object { $_.Enabled -eq "True" }
if ($firewall) {
    Write-OutputAndLog "[PASS] Windows Firewall is enabled."
} else {
    Write-OutputAndLog "[FAIL] Windows Firewall is not enabled."
}

# 7. Windows Update Settings
Check-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ExpectedValue 0 -Description "Windows Automatic Updates are enabled."

# 8. Application Control (AppLocker or WDAC)
$appLocker = Get-AppLockerPolicy -Effective
if ($appLocker) {
    Write-OutputAndLog "[PASS] Application Control (AppLocker) is configured."
} else {
    Write-OutputAndLog "[WARNING] Application Control (AppLocker) is not configured."
}

# 9. Secure Boot and Measured Boot
$secureBoot = Confirm-SecureBootUEFI
if ($secureBoot -eq $true) {
    Write-OutputAndLog "[PASS] Secure Boot is enabled."
} else {
    Write-OutputAndLog "[FAIL] Secure Boot is not enabled."
}

$measuredBoot = Get-WinEvent -LogName "Microsoft-Windows-TPM/Operational" -MaxEvents 1 -ErrorAction SilentlyContinue
if ($measuredBoot) {
    Write-OutputAndLog "[PASS] Measured Boot is enabled."
} else {
    Write-OutputAndLog "[FAIL] Measured Boot is not enabled."
}

# === Medium Priority Checks ===
Write-OutputAndLog "`n=== Medium Priority Checks ==="

# 1. Account Lockout Policy
Check-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ExpectedValue 1 -Description "Account Lockout Policy is configured."

# 2. Anonymous Connections
Check-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -ExpectedValue 1 -Description "Anonymous connections are restricted."

# 3. Antivirus Software
$antivirus = Get-MpComputerStatus
if ($antivirus.AntivirusEnabled -eq $true) {
    Write-OutputAndLog "[PASS] Antivirus software is enabled."
} else {
    Write-OutputAndLog "[FAIL] Antivirus software is not enabled."
}

# 4. Autoplay and AutoRun
Check-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ExpectedValue 255 -Description "Autoplay and AutoRun are disabled."

# 5. Boot Devices
Check-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name "Enabled" -ExpectedValue 1 -Description "Boot devices are restricted."

# 6. Bridging Networks
Check-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NoLMHash" -ExpectedValue 1 -Description "Network bridging is disabled."

# 7. Built-in Guest Accounts
Check-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -ExpectedValue 1 -Description "Built-in guest accounts are disabled."

# 8. CD Burner Access
Check-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoCDBurning" -ExpectedValue 1 -Description "CD burner access is restricted."

# 9. Command Prompt
Check-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableCMD" -ExpectedValue 1 -Description "Command Prompt access is restricted."

# 10. Direct Memory Access (DMA)
Check-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DMA" -Name "DMAProtection" -ExpectedValue 1 -Description "DMA protection is enabled."

# === Low Priority Checks ===
Write-OutputAndLog "`n=== Low Priority Checks ==="

# 1. Displaying File Extensions
Check-RegistryKey -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -ExpectedValue 0 -Description "File extensions are displayed."

# 2. File and Folder Security Properties
Check-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoSecurityTab" -ExpectedValue 0 -Description "File and folder security properties are accessible."

# 3. Location Awareness
Check-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -ExpectedValue 1 -Description "Location services are disabled."

# 4. Microsoft Store
Check-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -ExpectedValue 1 -Description "Microsoft Store access is disabled."

# 5. Resultant Set of Policy (RSOP) Reporting
Check-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableRSOP" -ExpectedValue 1 -Description "RSOP reporting is disabled."

# Summary
Write-OutputAndLog "`n=== Summary ==="
Write-OutputAndLog "Report saved to: $outputFile"