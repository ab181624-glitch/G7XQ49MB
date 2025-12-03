#############################################
# CyberPatriot Security Hardening Script
# For Windows Server 2019/2022
#############################################

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    pause
    exit
}

# Set execution policy for this session
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Color-coded output functions
function Print-Header {
    param([string]$Message)
    Write-Host "`n============================================================" -ForegroundColor Cyan
    Write-Host " $Message" -ForegroundColor Cyan
    Write-Host "============================================================`n" -ForegroundColor Cyan
}

function Print-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor Green
    Add-Content -Path $LogFile -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] SUCCESS: $Message"
}

function Print-Error {
    param([string]$Message)
    Write-Host "[✗] $Message" -ForegroundColor Red
    Add-Content -Path $LogFile -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] ERROR: $Message"
}

function Print-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
    Add-Content -Path $LogFile -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] WARNING: $Message"
}

function Print-Info {
    param([string]$Message)
    Write-Host "[i] $Message" -ForegroundColor Blue
    Add-Content -Path $LogFile -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] INFO: $Message"
}

function Confirm-Action {
    param([string]$Message)
    $response = Read-Host "$Message (y/n)"
    return $response -match '^[Yy]$'
}

function Press-Enter {
    Write-Host "`nPress Enter to continue..." -ForegroundColor Cyan
    Read-Host
}

# Log file setup
$LogFile = "C:\CyberPatriot\audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
New-Item -ItemType Directory -Path "C:\CyberPatriot" -Force -ErrorAction SilentlyContinue | Out-Null

#############################################
# ASCII Art / Splash Screen
#############################################

function Show-Splash {
    Clear-Host
    Write-Host @"
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║    ██████╗██████╗     ██╗    ██╗██╗███╗   ██╗            ║
    ║   ██╔════╝██╔══██╗    ██║    ██║██║████╗  ██║            ║
    ║   ██║     ██████╔╝    ██║ █╗ ██║██║██╔██╗ ██║            ║
    ║   ██║     ██╔═══╝     ██║███╗██║██║██║╚██╗██║            ║
    ║   ╚██████╗██║         ╚███╔███╔╝██║██║ ╚████║            ║
    ║    ╚═════╝╚═╝          ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝            ║
    ║                                                           ║
    ║      ███████╗███████╗██████╗ ██╗   ██╗███████╗██████╗    ║
    ║      ██╔════╝██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗   ║
    ║      ███████╗█████╗  ██████╔╝██║   ██║█████╗  ██████╔╝   ║
    ║      ╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝  ██╔══██╗   ║
    ║      ███████║███████╗██║  ██║ ╚████╔╝ ███████╗██║  ██║   ║
    ║      ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝   ║
    ║                                                           ║
    ║           Security Hardening & Audit Tool                ║
    ║              CyberPatriot Competition                    ║
    ║             Windows Server 2019/2022                     ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
    Write-Host "                    System: $env:COMPUTERNAME" -ForegroundColor Yellow
    Write-Host "                    Date: $(Get-Date)" -ForegroundColor Yellow
    Write-Host ""
    Start-Sleep -Seconds 1
}

#############################################
# Module 1: User Account Auditing
#############################################

function Invoke-UserAuditing {
    Print-Header "USER ACCOUNT AUDITING MODULE"
    Print-Info "Auditing local users and groups..."
    
    # TODO: Implement user auditing
    # - Get authorized users list
    # - Check for unauthorized users
    # - Verify admin group membership
    # - Check for guest accounts
    # - Audit password policies per user
    
    Print-Info "User auditing module - TO BE IMPLEMENTED"
    Press-Enter
}

#############################################
# Module 2: Disable Guest Account
#############################################

function Disable-GuestAccount {
    Print-Header "DISABLE GUEST ACCOUNT"
    Print-Info "Disabling built-in Guest account..."
    
    # TODO: Implement guest account disabling
    # - Disable Guest account
    # - Verify Guest account is disabled
    # - Remove Guest from any groups
    
    Print-Info "Guest account module - TO BE IMPLEMENTED"
    Press-Enter
}

#############################################
# Module 3: Configure Windows Firewall
#############################################

function Configure-Firewall {
    Print-Header "WINDOWS FIREWALL CONFIGURATION"
    Print-Info "Configuring Windows Defender Firewall..."
    
    # TODO: Implement firewall configuration
    # - Enable firewall for all profiles (Domain, Private, Public)
    # - Configure default deny inbound
    # - Configure allow outbound
    # - Review firewall rules
    # - Remove unnecessary rules
    
    Print-Info "Firewall configuration module - TO BE IMPLEMENTED"
    Press-Enter
}

#############################################
# Module 4: Configure Password Policies
#############################################

function Configure-PasswordPolicy {
    Print-Header "PASSWORD POLICY CONFIGURATION"
    Print-Info "Configuring Local Security Policy password requirements..."
    
    # TODO: Implement password policy configuration
    # - Set minimum password length (10-14 characters)
    # - Set password complexity requirements
    # - Set maximum password age (90 days)
    # - Set minimum password age (7 days)
    # - Set password history (5-24 passwords)
    # - Configure account lockout policy
    
    Print-Info "Password policy module - TO BE IMPLEMENTED"
    Press-Enter
}

#############################################
# Module 5: Audit Services
#############################################

function Invoke-ServiceAudit {
    Print-Header "SERVICE AUDIT"
    Print-Info "Auditing Windows services..."
    
    # TODO: Implement service auditing
    # - List all running services
    # - Identify prohibited services (Telnet, FTP, etc.)
    # - Disable unnecessary services
    # - Check service startup types
    # - Review service account permissions
    
    Print-Info "Service audit module - TO BE IMPLEMENTED"
    Press-Enter
}

#############################################
# Module 6: Audit File Permissions
#############################################

function Invoke-FilePermissionsAudit {
    Print-Header "FILE PERMISSIONS AUDIT"
    Print-Info "Auditing critical file and folder permissions..."
    
    # TODO: Implement file permissions audit
    # - Check C:\Windows permissions
    # - Check C:\Program Files permissions
    # - Check user home directories
    # - Review system32 permissions
    # - Check for world-writable files
    
    Print-Info "File permissions module - TO BE IMPLEMENTED"
    Press-Enter
}

#############################################
# Module 7: Windows Update
#############################################

function Invoke-WindowsUpdate {
    Print-Header "WINDOWS UPDATE"
    Print-Info "Checking for and installing Windows updates..."
    
    # TODO: Implement Windows Update
    # - Check for available updates
    # - Install critical and security updates
    # - Configure automatic updates
    # - Reboot if required
    
    Print-Info "Windows Update module - TO BE IMPLEMENTED"
    Press-Enter
}

#############################################
# Module 8: Remove Prohibited Software
#############################################

function Remove-ProhibitedSoftware {
    Print-Header "REMOVE PROHIBITED SOFTWARE"
    Print-Info "Scanning for and removing prohibited applications..."
    
    # TODO: Implement prohibited software removal
    # - Scan installed programs
    # - Check against prohibited list (games, P2P, hacking tools)
    # - Uninstall prohibited software
    # - Check for portable apps
    
    Print-Info "Prohibited software removal module - TO BE IMPLEMENTED"
    Press-Enter
}

#############################################
# Module 9: Configure Remote Desktop (RDP)
#############################################

function Configure-RemoteDesktop {
    Print-Header "REMOTE DESKTOP CONFIGURATION"
    Print-Info "Hardening Remote Desktop Protocol (RDP)..."
    
    # TODO: Implement RDP hardening
    # - Set Network Level Authentication (NLA)
    # - Configure encryption level
    # - Limit RDP users
    # - Set idle timeout
    # - Configure firewall for RDP
    
    Print-Info "RDP configuration module - TO BE IMPLEMENTED"
    Press-Enter
}

#############################################
# Module 10: Audit Registry Security Settings
#############################################

function Invoke-RegistrySecurityAudit {
    Print-Header "REGISTRY SECURITY AUDIT"
    Print-Info "Auditing and hardening registry security settings..."
    
    # TODO: Implement registry security audit
    # - Disable anonymous SID enumeration
    # - Configure UAC settings
    # - Disable AutoRun/AutoPlay
    # - Configure SMB settings
    # - Harden NTLM authentication
    
    Print-Info "Registry security audit module - TO BE IMPLEMENTED"
    Press-Enter
}

#############################################
# Module 11: Enable Security Features
#############################################

function Enable-SecurityFeatures {
    Print-Header "ENABLE SECURITY FEATURES"
    Print-Info "Enabling Windows security features..."
    
    # TODO: Implement security features
    # - Enable Windows Defender
    # - Configure Windows Defender Firewall
    # - Enable DEP (Data Execution Prevention)
    # - Enable ASLR (Address Space Layout Randomization)
    # - Configure audit policies
    # - Enable BitLocker (if applicable)
    
    Print-Info "Security features module - TO BE IMPLEMENTED"
    Press-Enter
}

#############################################
# Module 12: Configure Audit Policies
#############################################

function Configure-AuditPolicies {
    Print-Header "CONFIGURE AUDIT POLICIES"
    Print-Info "Configuring Advanced Audit Policies..."
    
    # TODO: Implement audit policy configuration
    # - Enable audit for account logon events
    # - Enable audit for account management
    # - Enable audit for logon events
    # - Enable audit for object access
    # - Enable audit for policy change
    # - Enable audit for privilege use
    # - Enable audit for system events
    
    Print-Info "Audit policies module - TO BE IMPLEMENTED"
    Press-Enter
}

#############################################
# Module 13: Local Security Policy Hardening
#############################################

function Invoke-LocalSecurityPolicyHardening {
    Print-Header "LOCAL SECURITY POLICY HARDENING"
    Print-Info "Hardening Local Security Policy settings..."
    
    # TODO: Implement local security policy hardening
    # - Configure User Rights Assignment
    # - Configure Security Options
    # - Set anonymous access restrictions
    # - Configure LAN Manager authentication
    # - Set minimum session security
    
    Print-Info "Local Security Policy hardening module - TO BE IMPLEMENTED"
    Press-Enter
}

#############################################
# Main Menu
#############################################

function Show-Menu {
    Clear-Host
    Write-Host " 1) User Account Auditing" -ForegroundColor Green
    Write-Host " 2) Disable Guest Account" -ForegroundColor Green
    Write-Host " 3) Configure Windows Firewall" -ForegroundColor Green
    Write-Host " 4) Configure Password Policies" -ForegroundColor Green
    Write-Host " 5) Audit Services" -ForegroundColor Green
    Write-Host " 6) Audit File Permissions" -ForegroundColor Green
    Write-Host " 7) Windows Update" -ForegroundColor Green
    Write-Host " 8) Remove Prohibited Software" -ForegroundColor Green
    Write-Host " 9) Configure Remote Desktop (RDP)" -ForegroundColor Green
    Write-Host "10) Audit Registry Security Settings" -ForegroundColor Green
    Write-Host "11) Enable Security Features" -ForegroundColor Green
    Write-Host "12) Configure Audit Policies" -ForegroundColor Green
    Write-Host "13) Local Security Policy Hardening" -ForegroundColor Yellow
    Write-Host ""
    Write-Host " 0) Exit" -ForegroundColor Red
    Write-Host ""
    Write-Host "Select an option: " -NoNewline -ForegroundColor Cyan
}

#############################################
# Main Program Loop
#############################################

function Main {
    Show-Splash
    
    while ($true) {
        Show-Menu
        $choice = Read-Host
        
        switch ($choice) {
            "1"  { Invoke-UserAuditing }
            "2"  { Disable-GuestAccount }
            "3"  { Configure-Firewall }
            "4"  { Configure-PasswordPolicy }
            "5"  { Invoke-ServiceAudit }
            "6"  { Invoke-FilePermissionsAudit }
            "7"  { Invoke-WindowsUpdate }
            "8"  { Remove-ProhibitedSoftware }
            "9"  { Configure-RemoteDesktop }
            "10" { Invoke-RegistrySecurityAudit }
            "11" { Enable-SecurityFeatures }
            "12" { Configure-AuditPolicies }
            "13" { Invoke-LocalSecurityPolicyHardening }
            "0"  {
                Print-Header "EXITING"
                Print-Info "Security audit log saved to: $LogFile"
                Write-Host "Thank you for using CyberPatriot Security Tool!" -ForegroundColor Green
                exit
            }
            default {
                Print-Error "Invalid option. Please try again."
                Start-Sleep -Seconds 2
            }
        }
    }
}

# Run the main program
Main
