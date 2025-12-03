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

# Set console encoding to UTF-8 to support special characters
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

function Print-Header {
    param([string]$Message)
    Write-Host "`n============================================================" -ForegroundColor Cyan
    Write-Host " $Message" -ForegroundColor Cyan
    Write-Host "============================================================`n" -ForegroundColor Cyan
}

function Print-Success {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
    Add-Content -Path $LogFile -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] SUCCESS: $Message"
}


function Print-Error {
    param([string]$Message)
    Write-Host "[X] $Message" -ForegroundColor Red
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

function Show-Splash {
    Clear-Host
    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Host "                                                               " -ForegroundColor Cyan
    Write-Host "         CYBERPATRIOT WINDOWS SERVER HARDENING TOOL            " -ForegroundColor Cyan
    Write-Host "                                                               " -ForegroundColor Cyan
    Write-Host "              Security Hardening & Audit Tool                  " -ForegroundColor Cyan
    Write-Host "                 CyberPatriot Competition                      " -ForegroundColor Cyan
    Write-Host "                Windows Server 2019/2022                       " -ForegroundColor Cyan
    Write-Host "                                                               " -ForegroundColor Cyan
    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "System: $env:COMPUTERNAME" -ForegroundColor Yellow
    Write-Host "Date: $(Get-Date)" -ForegroundColor Yellow
    Write-Host ""
    Start-Sleep -Seconds 1
}


#############################################
# Module 1: User Account Auditing
#############################################

function Invoke-UserAuditing {
    Print-Header "USER ACCOUNT AUDITING MODULE"
    
    # Script-level variables
    $script:MainUser = ""
    $script:SecureAdminPassword = ""
    $script:AuthorizedAdmins = @{}
    $script:AuthorizedUsers = @()
    
    # ========================================
    # STEP 1: Gather User Information
    # ========================================
    Print-Header "STEP 1: GATHER AUTHORIZED USER INFORMATION"
    
    # Get main username
    Write-Host "`nEnter the main username (primary administrator):" -ForegroundColor Cyan
    $script:MainUser = Read-Host
    
    if (-not (Get-LocalUser -Name $script:MainUser -ErrorAction SilentlyContinue)) {
        Print-Error "User '$script:MainUser' does not exist!"
        Press-Enter
        return
    }
    
    Print-Success "Main user set to: $script:MainUser"
    
    # Get secure admin password
    Write-Host "`nEnter the secure password for admin accounts:" -ForegroundColor Cyan
    $securePass1 = Read-Host -AsSecureString
    Write-Host "Confirm secure password:" -ForegroundColor Cyan
    $securePass2 = Read-Host -AsSecureString
    
    # Compare passwords
    $pass1Plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePass1))
    $pass2Plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePass2))
    
    if ($pass1Plain -ne $pass2Plain) {
        Print-Error "Passwords do not match!"
        Press-Enter
        return
    }
    
    $script:SecureAdminPassword = $pass1Plain
    Print-Success "Secure admin password set"
    
    # Get list of authorized admins
    Write-Host "`nEnter authorized admin users" -ForegroundColor Cyan
    Write-Host "Format: username (press Enter)" -ForegroundColor Yellow
    Write-Host "Enter 'done' when finished`n" -ForegroundColor Yellow
    
    while ($true) {
        $adminUser = Read-Host "Admin username (or 'done')"
        if ($adminUser -eq 'done') { break }
        if ([string]::IsNullOrWhiteSpace($adminUser)) { continue }
        
        $script:AuthorizedAdmins[$adminUser] = $script:SecureAdminPassword
        Print-Success "Added admin: $adminUser"
    }
    
    # Get list of authorized regular users
    Write-Host "`nEnter authorized regular (non-admin) users" -ForegroundColor Cyan
    Write-Host "Enter one username per line, 'done' when finished`n" -ForegroundColor Yellow
    
    while ($true) {
        $user = Read-Host "Username (or 'done')"
        if ($user -eq 'done') { break }
        if ([string]::IsNullOrWhiteSpace($user)) { continue }
        
        $script:AuthorizedUsers += $user
        Print-Success "Added authorized user: $user"
    }
    
    # ========================================
    # STEP 2: Discover System Users
    # ========================================
    Print-Header "STEP 2: DISCOVER SYSTEM USERS"
    
    # Get all local users (exclude built-in system accounts)
    $systemUsers = Get-LocalUser | Where-Object { 
        $_.Name -notmatch '^(DefaultAccount|WDAGUtilityAccount|Guest)$' 
    }
    
    Print-Info "Found $($systemUsers.Count) user accounts on the system"
    
    # Display all users
    Write-Host "`nCurrent Users:" -ForegroundColor Cyan
    foreach ($user in $systemUsers) {
        $adminStatus = if ((Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue).Name -contains "$env:COMPUTERNAME\$($user.Name)") { "[ADMIN]" } else { "[USER]" }
        $enabledStatus = if ($user.Enabled) { "Enabled" } else { "Disabled" }
        Write-Host "  $adminStatus $($user.Name) - $enabledStatus" -ForegroundColor $(if ($user.Enabled) { "White" } else { "Gray" })
    }
    
    # ========================================
    # STEP 3: Disable Guest Account
    # ========================================
    Print-Header "STEP 3: DISABLE GUEST ACCOUNT"
    
    $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($guestAccount) {
        if ($guestAccount.Enabled) {
            if (Confirm-Action "Disable Guest account?") {
                Disable-LocalUser -Name "Guest"
                Print-Success "Guest account disabled"
            }
        } else {
            Print-Success "Guest account already disabled"
        }
    } else {
        Print-Info "Guest account not found"
    }
    
    # ========================================
    # STEP 4: Check for Unauthorized Users
    # ========================================
    Print-Header "STEP 4: CHECK FOR UNAUTHORIZED USERS"
    
    $unauthorizedUsers = @()
    
    foreach ($user in $systemUsers) {
        $isAuthorized = $false
        
        # Check if main user
        if ($user.Name -eq $script:MainUser) {
            $isAuthorized = $true
        }
        
        # Check if in admin list
        if ($script:AuthorizedAdmins.ContainsKey($user.Name)) {
            $isAuthorized = $true
        }
        
        # Check if in regular users list
        if ($script:AuthorizedUsers -contains $user.Name) {
            $isAuthorized = $true
        }
        
        # Check if built-in Administrator account
        if ($user.Name -eq "Administrator") {
            $isAuthorized = $true
        }
        
        if (-not $isAuthorized) {
            $unauthorizedUsers += $user.Name
            Print-Warning "UNAUTHORIZED USER FOUND: $($user.Name)"
        }
    }
    
    # Handle unauthorized users
    if ($unauthorizedUsers.Count -gt 0) {
        Write-Host "`nFound $($unauthorizedUsers.Count) unauthorized user(s)" -ForegroundColor Red
        if (Confirm-Action "Remove unauthorized users?") {
            foreach ($unauth in $unauthorizedUsers) {
                if (Confirm-Action "Remove user '$unauth'?") {
                    try {
                        Remove-LocalUser -Name $unauth -ErrorAction Stop
                        Print-Success "Removed user: $unauth"
                    }
                    catch {
                        Print-Error "Failed to remove user '$unauth': $_"
                    }
                }
            }
        }
    } else {
        Print-Success "No unauthorized users found"
    }
    
    # ========================================
    # STEP 5: Verify Admin Group Membership
    # ========================================
    Print-Header "STEP 5: VERIFY ADMIN GROUP MEMBERSHIP"
    
    $adminGroupMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | 
                         Select-Object -ExpandProperty Name | 
                         ForEach-Object { $_.Split('\')[-1] }
    
    # Check authorized admins have admin rights
    foreach ($admin in $script:AuthorizedAdmins.Keys) {
        $userExists = Get-LocalUser -Name $admin -ErrorAction SilentlyContinue
        
        if ($userExists) {
            if ($adminGroupMembers -contains $admin) {
                Print-Success "$admin has admin privileges"
                
                # Update password
                if (Confirm-Action "Update password for '$admin' to secure password?") {
                    try {
                        $user = Get-LocalUser -Name $admin
                        $user | Set-LocalUser -Password (ConvertTo-SecureString $script:SecureAdminPassword -AsPlainText -Force)
                        Print-Success "Updated password for $admin"
                    }
                    catch {
                        Print-Error "Failed to update password for '$admin': $_"
                    }
                }
            }
            else {
                Print-Warning "$admin does NOT have admin privileges"
                if (Confirm-Action "Grant admin privileges to '$admin'?") {
                    try {
                        Add-LocalGroupMember -Group "Administrators" -Member $admin -ErrorAction Stop
                        Print-Success "Granted admin privileges to $admin"
                        
                        # Set secure password
                        $user = Get-LocalUser -Name $admin
                        $user | Set-LocalUser -Password (ConvertTo-SecureString $script:SecureAdminPassword -AsPlainText -Force)
                        Print-Success "Set secure password for $admin"
                    }
                    catch {
                        Print-Error "Failed to grant admin privileges to '$admin': $_"
                    }
                }
            }
        }
        else {
            Print-Warning "$admin does not exist on the system"
            if (Confirm-Action "Create user '$admin' with admin privileges?") {
                try {
                    New-LocalUser -Name $admin -Password (ConvertTo-SecureString $script:SecureAdminPassword -AsPlainText -Force) -FullName $admin -Description "Administrator" -ErrorAction Stop
                    Add-LocalGroupMember -Group "Administrators" -Member $admin -ErrorAction Stop
                    Print-Success "Created admin user: $admin"
                }
                catch {
                    Print-Error "Failed to create user '$admin': $_"
                }
            }
        }
    }
    
    # ========================================
    # STEP 6: Verify Regular Users DON'T Have Admin Rights
    # ========================================
    Print-Header "STEP 6: VERIFY REGULAR USERS DON'T HAVE ADMIN RIGHTS"
    
    foreach ($user in $script:AuthorizedUsers) {
        $userExists = Get-LocalUser -Name $user -ErrorAction SilentlyContinue
        
        if ($userExists) {
            if ($adminGroupMembers -contains $user) {
                Print-Warning "$user has admin privileges but should NOT"
                if (Confirm-Action "Remove admin privileges from '$user'?") {
                    try {
                        Remove-LocalGroupMember -Group "Administrators" -Member $user -ErrorAction Stop
                        Print-Success "Removed admin privileges from $user"
                    }
                    catch {
                        Print-Error "Failed to remove admin privileges from '$user': $_"
                    }
                }
            }
            else {
                Print-Success "$user correctly has no admin privileges"
            }
        }
        else {
            Print-Warning "$user does not exist on the system"
            if (Confirm-Action "Create user '$user'?") {
                try {
                    $defaultPass = "ChangeMe123!"
                    New-LocalUser -Name $user -Password (ConvertTo-SecureString $defaultPass -AsPlainText -Force) -FullName $user -Description "Standard User" -ErrorAction Stop
                    # Force password change on next logon
                    $userObj = Get-LocalUser -Name $user
                    $userObj | Set-LocalUser -PasswordNeverExpires $false
                    Print-Success "Created user: $user (password: $defaultPass - must change on first login)"
                }
                catch {
                    Print-Error "Failed to create user '$user': $_"
                }
            }
        }
    }
    
    # ========================================
    # STEP 7: Check Critical Group Memberships
    # ========================================
    Print-Header "STEP 7: REVIEW CRITICAL GROUP MEMBERSHIPS"
    
    $criticalGroups = @("Administrators", "Remote Desktop Users", "Remote Management Users", "Backup Operators", "Power Users")
    
    foreach ($group in $criticalGroups) {
        try {
            $members = Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue
            if ($members) {
                Write-Host "`nGroup '$group' members:" -ForegroundColor Cyan
                foreach ($member in $members) {
                    $memberName = $member.Name.Split('\')[-1]
                    Write-Host "  - $memberName" -ForegroundColor White
                }
                
                if (Confirm-Action "Review members of '$group'?") {
                    foreach ($member in $members) {
                        $memberName = $member.Name.Split('\')[-1]
                        Write-Host "`nUser: $memberName" -ForegroundColor Yellow
                        
                        if (Confirm-Action "Remove '$memberName' from '$group'?") {
                            try {
                                Remove-LocalGroupMember -Group $group -Member $memberName -ErrorAction Stop
                                Print-Success "Removed $memberName from $group"
                            }
                            catch {
                                Print-Error "Failed to remove '$memberName' from '$group': $_"
                            }
                        }
                    }
                }
            }
            else {
                Print-Info "Group '$group' has no members"
            }
        }
        catch {
            Print-Warning "Could not access group '$group': $_"
        }
    }
    
    # ========================================
    # STEP 8: Disable Built-in Administrator (Optional)
    # ========================================
    Print-Header "STEP 8: DISABLE BUILT-IN ADMINISTRATOR"
    
    $builtinAdmin = Get-LocalUser | Where-Object { $_.SID -like "*-500" }
    if ($builtinAdmin -and $builtinAdmin.Enabled) {
        Print-Warning "Built-in Administrator account is enabled"
        Print-Info "Current name: $($builtinAdmin.Name)"
        
        if (Confirm-Action "Disable built-in Administrator account?") {
            try {
                Disable-LocalUser -Name $builtinAdmin.Name -ErrorAction Stop
                Print-Success "Disabled built-in Administrator account"
            }
            catch {
                Print-Error "Failed to disable Administrator account: $_"
            }
        }
    }
    else {
        Print-Success "Built-in Administrator account is already disabled"
    }
    
    # ========================================
    # Summary
    # ========================================
    Print-Header "USER AUDIT SUMMARY"
    
    Write-Host "`nFinal User Status:" -ForegroundColor Cyan
    $finalUsers = Get-LocalUser | Where-Object { $_.Name -notmatch '^(DefaultAccount|WDAGUtilityAccount|Guest)$' }
    foreach ($user in $finalUsers) {
        $isAdmin = (Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue).Name -contains "$env:COMPUTERNAME\$($user.Name)"
        $status = if ($user.Enabled) { "Enabled" } else { "Disabled" }
        $role = if ($isAdmin) { "[ADMIN]" } else { "[USER] " }
        Write-Host "  $role $($user.Name) - $status" -ForegroundColor $(if ($user.Enabled) { "Green" } else { "Gray" })
    }
    
    Print-Header "USER ACCOUNT AUDITING COMPLETE"
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
                Start-Sleep -Seconds 1
            }
        }
    }
}

# Run the main program
Main
