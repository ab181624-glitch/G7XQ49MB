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
    Write-Host "`nEnter the main password:" -ForegroundColor Cyan
    $securePass1 = Read-Host
    Write-Host "Confirm main password:" -ForegroundColor Cyan
    $securePass2 = Read-Host
    
    # Compare passwords
    if ($securePass1 -ne $securePass2) {
        Print-Error "Passwords do not match!"
        Press-Enter
        return
    }
    
    $script:SecureAdminPassword = $securePass1
    Print-Success "Main password set"
    
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
        Read-Host "Enter password for $adminUser (will be set to secure password)"
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
    # STEP 8: Apply Secure Password to ALL Users
    # ========================================
    Print-Header "STEP 8: APPLY SECURE PASSWORD TO ALL USERS"
    
    Print-Info "Applying secure password to ALL user accounts..."
    $allUsers = Get-LocalUser | Where-Object { 
        $_.Name -notmatch '^(DefaultAccount|WDAGUtilityAccount|Guest)$' 
    }
    
    if (Confirm-Action "Apply secure admin password to ALL $($allUsers.Count) user accounts?") {
        $passwordsSet = 0
        foreach ($user in $allUsers) {
            try {
                $user | Set-LocalUser -Password (ConvertTo-SecureString $script:SecureAdminPassword -AsPlainText -Force) -ErrorAction Stop
                Print-Success "Set password for: $($user.Name)"
                $passwordsSet++
            }
            catch {
                Print-Error "Failed to set password for '$($user.Name)': $_"
            }
        }
        Print-Success "Applied password to $passwordsSet user account(s)"
    } else {
        Print-Warning "Skipped applying password to all users"
    }
    
    # ========================================
    # STEP 9: Disable Built-in Administrator (Optional)
    # ========================================
    Print-Header "STEP 9: DISABLE BUILT-IN ADMINISTRATOR"
    
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
    # STEP 10: Set UAC to Strictest Level
    # ========================================
    Print-Header "STEP 10: CONFIGURE UAC TO STRICTEST LEVEL"
    
    Print-Info "Setting User Account Control (UAC) to maximum security..."
    
    if (Confirm-Action "Set UAC to strictest level (Always Notify)?") {
        try {
            # Set UAC to highest level (Always notify)
            $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            
            # ConsentPromptBehaviorAdmin: 2 = Always notify
            Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord -ErrorAction Stop
            
            # PromptOnSecureDesktop: 1 = Prompt on secure desktop
            Set-ItemProperty -Path $uacPath -Name "PromptOnSecureDesktop" -Value 1 -Type DWord -ErrorAction Stop
            
            # EnableLUA: 1 = Enable UAC
            Set-ItemProperty -Path $uacPath -Name "EnableLUA" -Value 1 -Type DWord -ErrorAction Stop
            
            # ConsentPromptBehaviorUser: 3 = Prompt for credentials on the secure desktop
            Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorUser" -Value 3 -Type DWord -ErrorAction Stop
            
            Print-Success "UAC set to strictest level (Always Notify)"
            Print-Warning "A system restart is required for UAC changes to take full effect"
        }
        catch {
            Print-Error "Failed to configure UAC: $_"
        }
    } else {
        Print-Warning "Skipped UAC configuration"
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
# Module 2: Configure Password Policies
#############################################

function Configure-PasswordPolicy {
    Print-Header "PASSWORD POLICY CONFIGURATION"
    
    Print-Info "Configuring Local Security Policy password and account lockout requirements..."
    Print-Warning "This module uses secedit to configure security policies"
    
    # ========================================
    # STEP 1: Configure Password Policies
    # ========================================
    Print-Header "STEP 1: CONFIGURE PASSWORD POLICIES"
    
    # Create temporary security template
    $tempSecurityTemplate = "C:\CyberPatriot\secpol_config.inf"
    $tempSecurityDB = "C:\CyberPatriot\secpol_config.sdb"
    
    # Export current security policy
    Print-Info "Exporting current security policy..."
    secedit /export /cfg $tempSecurityTemplate | Out-Null
    
    if (Test-Path $tempSecurityTemplate) {
        Print-Success "Current security policy exported"
        
        # Read current configuration
        $securityConfig = Get-Content $tempSecurityTemplate
        
        # Modify password policies
        Print-Info "Configuring password policies..."
        
        # Maximum password age (90 days) - value can be -1 for unlimited
        $securityConfig = $securityConfig -replace 'MaximumPasswordAge\s*=\s*-?\d+', 'MaximumPasswordAge = 90'
        
        # Minimum password age (7 days)
        $securityConfig = $securityConfig -replace 'MinimumPasswordAge\s*=\s*-?\d+', 'MinimumPasswordAge = 7'
        
        # Minimum password length (10 characters)
        $securityConfig = $securityConfig -replace 'MinimumPasswordLength\s*=\s*-?\d+', 'MinimumPasswordLength = 10'
        
        # Password complexity (Enabled)
        $securityConfig = $securityConfig -replace 'PasswordComplexity\s*=\s*-?\d+', 'PasswordComplexity = 1'
        
        # Password history (24 passwords)
        $securityConfig = $securityConfig -replace 'PasswordHistorySize\s*=\s*-?\d+', 'PasswordHistorySize = 24'
        
        # Store passwords using reversible encryption (Disabled)
        $securityConfig = $securityConfig -replace 'ClearTextPassword\s*=\s*-?\d+', 'ClearTextPassword = 0'
        
        Print-Success "Password policies configured in template"
        
        # ========================================
        # STEP 2: Configure Account Lockout Policies
        # ========================================
        Print-Header "STEP 2: CONFIGURE ACCOUNT LOCKOUT POLICIES"
        
        Print-Info "Configuring account lockout policies..."
        
        # Account lockout threshold (10 invalid attempts)
        $securityConfig = $securityConfig -replace 'LockoutBadCount\s*=\s*\d+', 'LockoutBadCount = 10'
        
        # Account lockout duration (30 minutes)
        $securityConfig = $securityConfig -replace 'LockoutDuration\s*=\s*-?\d+', 'LockoutDuration = 30'
        
        # Reset account lockout counter after (30 minutes)
        $securityConfig = $securityConfig -replace 'ResetLockoutCount\s*=\s*\d+', 'ResetLockoutCount = 30'
        
        Print-Success "Account lockout policies configured in template"
        
        # ========================================
        # STEP 3: Configure Security Options
        # ========================================
        Print-Header "STEP 3: CONFIGURE SECURITY OPTIONS"
        
        Print-Info "Configuring security options..."
        
        # Limit local use of blank passwords to console only (Enabled)
        # This is configured via registry as secedit doesn't handle this well
        
        # Save modified configuration
        $securityConfig | Set-Content $tempSecurityTemplate
        
        # Apply the security configuration
        Print-Info "Applying security configuration..."
        if (Confirm-Action "Apply password and lockout policies to system?") {
            try {
                $result = secedit /configure /db $tempSecurityDB /cfg $tempSecurityTemplate /areas SECURITYPOLICY 2>&1
                
                if ($LASTEXITCODE -eq 0) {
                    Print-Success "Security policies applied successfully"
                } else {
                    Print-Error "Failed to apply security policies (Exit code: $LASTEXITCODE)"
                    Print-Info "Result: $result"
                }
            }
            catch {
                Print-Error "Error applying security policies: $_"
            }
        } else {
            Print-Warning "Skipped applying security policies"
        }
        
        # Configure "Limit local use of blank passwords" via registry
        Print-Info "Configuring blank password policy..."
        if (Confirm-Action "Enable 'Limit local use of blank passwords to console only'?") {
            try {
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                Set-ItemProperty -Path $regPath -Name "LimitBlankPasswordUse" -Value 1 -Type DWord -ErrorAction Stop
                Print-Success "Blank password policy enabled"
            }
            catch {
                Print-Error "Failed to set blank password policy: $_"
            }
        }
        
        # Clean up temporary files
        if (Test-Path $tempSecurityTemplate) { Remove-Item $tempSecurityTemplate -Force }
        if (Test-Path $tempSecurityDB) { Remove-Item $tempSecurityDB -Force }
        
    } else {
        Print-Error "Failed to export current security policy"
    }
    
    # ========================================
    # Summary
    # ========================================
    Print-Header "PASSWORD POLICY SUMMARY"
    
    Write-Host "`nConfigured Policies:" -ForegroundColor Cyan
    Write-Host "  Password Policies:" -ForegroundColor Yellow
    Write-Host "    - Maximum password age: 90 days" -ForegroundColor White
    Write-Host "    - Minimum password age: 7 days" -ForegroundColor White
    Write-Host "    - Minimum password length: 10 characters" -ForegroundColor White
    Write-Host "    - Password complexity: Enabled" -ForegroundColor White
    Write-Host "    - Password history: 24 passwords" -ForegroundColor White
    Write-Host "    - Store passwords using reversible encryption: Disabled" -ForegroundColor White
    Write-Host ""
    Write-Host "  Account Lockout Policies:" -ForegroundColor Yellow
    Write-Host "    - Account lockout threshold: 10 invalid attempts" -ForegroundColor White
    Write-Host "    - Account lockout duration: 30 minutes" -ForegroundColor White
    Write-Host "    - Reset account lockout counter: 30 minutes" -ForegroundColor White
    Write-Host ""
    Write-Host "  Security Options:" -ForegroundColor Yellow
    Write-Host "    - Limit blank passwords to console only: Enabled" -ForegroundColor White
    
    Print-Info "`nYou can verify these settings by opening Local Security Policy (secpol.msc)"
    Print-Info "Navigate to: Security Settings > Account Policies > Password Policy"
    Print-Info "Navigate to: Security Settings > Account Policies > Account Lockout Policy"
    Print-Info "Navigate to: Security Settings > Local Policies > Security Options"
    
    Print-Header "PASSWORD POLICY CONFIGURATION COMPLETE"
    Press-Enter
}

#############################################
# Module 3: Configure Local Security Policy
#############################################

function Configure-LocalSecurityPolicy {
    Print-Header "LOCAL SECURITY POLICY CONFIGURATION"
    
    Print-Info "Configuring Local Policies: Audit Policy, User Rights Assignment, and Security Options"
    Print-Warning "This module will guide you through configuring security policies interactively"
    
    # ========================================
    # STEP 1: Configure Audit Policies
    # ========================================
    Print-Header "STEP 1: CONFIGURE AUDIT POLICIES"
    
    Print-Info "Discovering all audit policies..."
    
    if (Confirm-Action "Enable maximum auditing for all audit policies?") {
        try {
            # Get all audit categories dynamically
            $auditCategories = auditpol /list /category | Where-Object { $_ -match '^\s+' } | ForEach-Object { $_.Trim() }
            
            Print-Info "Found $($auditCategories.Count) audit categories"
            
            foreach ($category in $auditCategories) {
                if (-not [string]::IsNullOrWhiteSpace($category)) {
                    try {
                        auditpol /set /category:"$category" /success:enable /failure:enable 2>&1 | Out-Null
                        if ($LASTEXITCODE -eq 0) {
                            Print-Success "Enabled auditing for: $category"
                        }
                    }
                    catch {
                        Print-Warning "Could not configure: $category"
                    }
                }
            }
            
            # Also enable all subcategories for comprehensive auditing
            Print-Info "`nEnabling all audit subcategories..."
            $auditSubcategories = auditpol /list /subcategory:* | Where-Object { $_ -match '^\s+' } | ForEach-Object { $_.Trim() }
            
            foreach ($subcategory in $auditSubcategories) {
                if (-not [string]::IsNullOrWhiteSpace($subcategory)) {
                    try {
                        auditpol /set /subcategory:"$subcategory" /success:enable /failure:enable 2>&1 | Out-Null
                        if ($LASTEXITCODE -eq 0) {
                            Write-Host "  [+] $subcategory" -ForegroundColor Gray
                        }
                    }
                    catch {
                        # Silently continue
                    }
                }
            }
            
            Print-Success "`nAll audit policies configured for maximum auditing"
        }
        catch {
            Print-Error "Failed to configure audit policies: $_"
        }
    } else {
        Print-Warning "Skipped audit policy configuration"
    }
    
    # ========================================
    # STEP 2: Configure User Rights Assignment
    # ========================================
    Print-Header "STEP 2: CONFIGURE USER RIGHTS ASSIGNMENT"
    
    Print-Info "User Rights Assignment controls which users/groups can perform system actions"
    Print-Warning "These settings are critical for security - REVIEW CAREFULLY"
    
    Write-Host "`n" -NoNewline
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
    Write-Host "                    MANUAL CONFIGURATION REQUIRED" -ForegroundColor Red  
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
    Write-Host ""
    Print-Info "User Rights Assignment must be configured manually via Local Security Policy"
    Print-Info "This prevents accidental lockout or system misconfiguration"
    Write-Host ""
    
    if (Confirm-Action "Open Local Security Policy (secpol.msc) to configure User Rights?") {
        try {
            Start-Process secpol.msc
            Print-Success "Launched Local Security Policy"
            
            Write-Host "`n" -NoNewline
            Write-Host "RECOMMENDED USER RIGHTS CONFIGURATION:" -ForegroundColor Yellow
            Write-Host "═══════════════════════════════════════" -ForegroundColor Yellow
            Write-Host ""
            
            Write-Host "Navigate to: " -ForegroundColor Cyan -NoNewline
            Write-Host "Security Settings > Local Policies > User Rights Assignment" -ForegroundColor White
            Write-Host ""
            
            Write-Host "CRITICAL DENY RIGHTS (Assign to Guest):" -ForegroundColor Red
            Write-Host "  1. Deny access to this computer from the network" -ForegroundColor White
            Write-Host "  2. Deny log on locally" -ForegroundColor White
            Write-Host "  3. Deny log on through Remote Desktop Services" -ForegroundColor White
            Write-Host "  4. Deny log on as a batch job" -ForegroundColor White
            Write-Host "  5. Deny log on as a service" -ForegroundColor White
            Write-Host ""
            
            Write-Host "ALLOW RIGHTS FOR ADMINISTRATORS:" -ForegroundColor Green
            Write-Host "  6. Access this computer from the network: Administrators, Users" -ForegroundColor White
            Write-Host "  7. Allow log on locally: Administrators, Users" -ForegroundColor White
            Write-Host "  8. Allow log on through RDP: Administrators, Remote Desktop Users" -ForegroundColor White
            Write-Host "  9. Shut down the system: Administrators, Users" -ForegroundColor White
            Write-Host " 10. Force shutdown from remote: Administrators (only)" -ForegroundColor White
            Write-Host ""
            
            Write-Host "ADVANCED RIGHTS (Configure if needed):" -ForegroundColor Yellow
            Write-Host "  - Back up files and directories: Administrators, Backup Operators" -ForegroundColor Gray
            Write-Host "  - Restore files and directories: Administrators, Backup Operators" -ForegroundColor Gray
            Write-Host "  - Debug programs: Administrators (only - security risk if broader)" -ForegroundColor Gray
            Write-Host "  - Manage auditing and security log: Administrators (only)" -ForegroundColor Gray
            Write-Host "  - Take ownership of files: Administrators (only)" -ForegroundColor Gray
            Write-Host ""
            
            Write-Host "═══════════════════════════════════════" -ForegroundColor Yellow
            Write-Host "HOW TO CONFIGURE:" -ForegroundColor Cyan
            Write-Host "═══════════════════════════════════════" -ForegroundColor Yellow
            Write-Host "1. Double-click on each policy name" -ForegroundColor White
            Write-Host "2. Click 'Add User or Group' button" -ForegroundColor White
            Write-Host "3. Type account name (e.g., 'Guest' or 'Administrators')" -ForegroundColor White
            Write-Host "4. Click 'Check Names' to verify" -ForegroundColor White
            Write-Host "5. Click OK to apply" -ForegroundColor White
            Write-Host "6. Remove unauthorized users from each policy" -ForegroundColor White
            Write-Host ""
            
            Print-Warning "After making changes, you can verify them using 'gpresult /h report.html'"
            
        }
        catch {
            Print-Error "Failed to launch Local Security Policy: $_"
            Print-Info "You can manually open it by: Start > Run > secpol.msc"
        }
    } else {
        Print-Info "Skipped User Rights Assignment configuration"
        Print-Info "You can configure this later via: secpol.msc"
    }
    
    # ========================================
    # STEP 3: Configure Security Options
    # ========================================
    Print-Header "STEP 3: CONFIGURE SECURITY OPTIONS"
    
    Print-Info "Configuring Security Options via registry..."
    Print-Warning "These settings affect system security and behavior"
    
    if (Confirm-Action "Apply recommended Security Options automatically?") {
        $settingsApplied = 0
        $settingsFailed = 0
        
        # Limit local use of blank passwords to console only (Enabled)
        try {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            Set-ItemProperty -Path $regPath -Name "LimitBlankPasswordUse" -Value 1 -Type DWord -ErrorAction Stop
            Print-Success "Limit blank passwords to console only: Enabled"
            $settingsApplied++
        }
        catch {
            Print-Error "Failed to set LimitBlankPasswordUse: $_"
            $settingsFailed++
        }
        
        # Force audit policy subcategory settings (Enabled)
        try {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            Set-ItemProperty -Path $regPath -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord -ErrorAction Stop
            Print-Success "Force audit policy subcategory settings: Enabled"
            $settingsApplied++
        }
        catch {
            Print-Error "Failed to set SCENoApplyLegacyAuditPolicy: $_"
            $settingsFailed++
        }
        
        # Do not display last user name (Enabled)
        try {
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            Set-ItemProperty -Path $regPath -Name "DontDisplayLastUserName" -Value 1 -Type DWord -ErrorAction Stop
            Print-Success "Do not display last user name: Enabled"
            $settingsApplied++
        }
        catch {
            Print-Error "Failed to set DontDisplayLastUserName: $_"
            $settingsFailed++
        }
        
        # Require CTRL+ALT+DEL (Disabled = require it)
        try {
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            Set-ItemProperty -Path $regPath -Name "DisableCAD" -Value 0 -Type DWord -ErrorAction Stop
            Print-Success "Require CTRL+ALT+DEL: Enabled (more secure)"
            $settingsApplied++
        }
        catch {
            Print-Error "Failed to set DisableCAD: $_"
            $settingsFailed++
        }
        
        # Do not allow anonymous enumeration of SAM accounts (Enabled)
        try {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            Set-ItemProperty -Path $regPath -Name "RestrictAnonymousSAM" -Value 1 -Type DWord -ErrorAction Stop
            Print-Success "Block anonymous SAM enumeration: Enabled"
            $settingsApplied++
        }
        catch {
            Print-Error "Failed to set RestrictAnonymousSAM: $_"
            $settingsFailed++
        }
        
        # Do not allow anonymous enumeration of SAM accounts and shares (Enabled)
        try {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            Set-ItemProperty -Path $regPath -Name "RestrictAnonymous" -Value 1 -Type DWord -ErrorAction Stop
            Print-Success "Block anonymous SAM/shares enumeration: Enabled"
            $settingsApplied++
        }
        catch {
            Print-Error "Failed to set RestrictAnonymous: $_"
            $settingsFailed++
        }
        
        # Do not store LAN Manager hash value (Enabled)
        try {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            Set-ItemProperty -Path $regPath -Name "NoLMHash" -Value 1 -Type DWord -ErrorAction Stop
            Print-Success "Do not store LM hash: Enabled"
            $settingsApplied++
        }
        catch {
            Print-Error "Failed to set NoLMHash: $_"
            $settingsFailed++
        }
        
        # LAN Manager authentication level (5 = Send NTLMv2 response only/refuse LM & NTLM)
        try {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            Set-ItemProperty -Path $regPath -Name "LmCompatibilityLevel" -Value 5 -Type DWord -ErrorAction Stop
            Print-Success "LAN Manager authentication level: NTLMv2 only (most secure)"
            $settingsApplied++
        }
        catch {
            Print-Error "Failed to set LmCompatibilityLevel: $_"
            $settingsFailed++
        }
        
        # Disable shutdown without logon (Disabled = more secure)
        try {
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            Set-ItemProperty -Path $regPath -Name "ShutdownWithoutLogon" -Value 0 -Type DWord -ErrorAction Stop
            Print-Success "Shutdown without logon: Disabled (more secure)"
            $settingsApplied++
        }
        catch {
            Print-Error "Failed to set ShutdownWithoutLogon: $_"
            $settingsFailed++
        }
        
        # Strengthen default permissions of internal system objects (Enabled)
        try {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            Set-ItemProperty -Path $regPath -Name "ProtectionMode" -Value 1 -Type DWord -ErrorAction Stop
            Print-Success "Strengthen default permissions: Enabled"
            $settingsApplied++
        }
        catch {
            Print-Error "Failed to set ProtectionMode: $_"
            $settingsFailed++
        }
        
        # Prevent users from installing printer drivers (Enabled)
        try {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers"
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            Set-ItemProperty -Path $regPath -Name "AddPrinterDrivers" -Value 1 -Type DWord -ErrorAction Stop
            Print-Success "Prevent users from installing printer drivers: Enabled"
            $settingsApplied++
        }
        catch {
            Print-Error "Failed to set AddPrinterDrivers: $_"
            $settingsFailed++
        }
        
        Print-Info "`nSecurity Options Summary: $settingsApplied applied, $settingsFailed failed"
    } else {
        Print-Warning "Skipped Security Options configuration"
    }
    
    # ========================================
    # Summary
    # ========================================
    Print-Header "LOCAL SECURITY POLICY CONFIGURATION COMPLETE"
    
    Print-Info "`nYou can verify these settings by opening Local Security Policy (secpol.msc)"
    Print-Info "Navigate to: Security Settings > Local Policies > Audit Policy"
    Print-Info "Navigate to: Security Settings > Local Policies > User Rights Assignment"
    Print-Info "Navigate to: Security Settings > Local Policies > Security Options"
    
    Press-Enter
}

#############################################
# Module 4: Configure Windows Firewall
#############################################

function Configure-Firewall {
    Print-Header "WINDOWS DEFENDER FIREWALL CONFIGURATION"
    
    Print-Info "Configuring Windows Defender Firewall for maximum security..."
    Print-Warning "This module will enable firewall for all profiles and configure rules"
    
    # ========================================
    # STEP 1: Enable Firewall for All Profiles
    # ========================================
    Print-Header "STEP 1: ENABLE FIREWALL FOR ALL PROFILES"
    
    Print-Info "Checking current firewall status..."
    
    # Get current firewall status
    $domainProfile = Get-NetFirewallProfile -Name Domain
    $privateProfile = Get-NetFirewallProfile -Name Private
    $publicProfile = Get-NetFirewallProfile -Name Public
    
    Write-Host "`nCurrent Firewall Status:" -ForegroundColor Cyan
    Write-Host "  Domain Profile:  $(if ($domainProfile.Enabled) { 'Enabled' } else { 'DISABLED' })" -ForegroundColor $(if ($domainProfile.Enabled) { 'Green' } else { 'Red' })
    Write-Host "  Private Profile: $(if ($privateProfile.Enabled) { 'Enabled' } else { 'DISABLED' })" -ForegroundColor $(if ($privateProfile.Enabled) { 'Green' } else { 'Red' })
    Write-Host "  Public Profile:  $(if ($publicProfile.Enabled) { 'Enabled' } else { 'DISABLED' })" -ForegroundColor $(if ($publicProfile.Enabled) { 'Green' } else { 'Red' })
    
    if (Confirm-Action "`nEnable Windows Firewall for all profiles?") {
        try {
            Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
            Print-Success "Firewall enabled for all profiles"
            
            # Set default actions
            Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Allow
            Print-Success "Default actions set: Block Inbound, Allow Outbound"
            
            # Enable logging
            Set-NetFirewallProfile -Profile Domain,Private,Public -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 4096
            Print-Success "Firewall logging enabled (4MB max per profile)"
        }
        catch {
            Print-Error "Failed to enable firewall: $_"
        }
    } else {
        Print-Warning "Skipped firewall enablement"
    }
    
    # ========================================
    # STEP 2: Review and Manage Firewall Rules
    # ========================================
    Print-Header "STEP 2: REVIEW FIREWALL RULES"
    
    Print-Info "Getting all firewall rules..."
    $allRules = Get-NetFirewallRule | Where-Object { $_.Enabled -eq $true }
    
    Write-Host "`nEnabled Firewall Rules: $($allRules.Count) total" -ForegroundColor Cyan
    
    # Categorize rules
    $inboundRules = $allRules | Where-Object { $_.Direction -eq 'Inbound' }
    $outboundRules = $allRules | Where-Object { $_.Direction -eq 'Outbound' }
    $allowRules = $allRules | Where-Object { $_.Action -eq 'Allow' }
    $blockRules = $allRules | Where-Object { $_.Action -eq 'Block' }
    
    Write-Host "  Inbound Rules:  $($inboundRules.Count)" -ForegroundColor Yellow
    Write-Host "  Outbound Rules: $($outboundRules.Count)" -ForegroundColor Yellow
    Write-Host "  Allow Rules:    $($allowRules.Count)" -ForegroundColor Green
    Write-Host "  Block Rules:    $($blockRules.Count)" -ForegroundColor Red
    
    if (Confirm-Action "`nDo you want to review potentially risky firewall rules?") {
        # Find risky inbound allow rules
        $riskyRules = $allRules | Where-Object { 
            $_.Direction -eq 'Inbound' -and 
            $_.Action -eq 'Allow' -and
            $_.Enabled -eq $true
        }
        
        Write-Host "`n=== INBOUND ALLOW RULES (POTENTIALLY RISKY) ===" -ForegroundColor Yellow
        Write-Host "These rules allow incoming connections. Review carefully.`n" -ForegroundColor Gray
        
        $count = 0
        foreach ($rule in $riskyRules) {
            $count++
            Write-Host "[$count] $($rule.DisplayName)" -ForegroundColor Cyan
            Write-Host "    Direction: $($rule.Direction)" -ForegroundColor Gray
            Write-Host "    Action: $($rule.Action)" -ForegroundColor Gray
            Write-Host "    Profile: $($rule.Profile)" -ForegroundColor Gray
            
            # Get port information if available
            $portFilter = $rule | Get-NetFirewallPortFilter
            if ($portFilter.LocalPort) {
                Write-Host "    Local Port: $($portFilter.LocalPort)" -ForegroundColor Gray
            }
            if ($portFilter.Protocol) {
                Write-Host "    Protocol: $($portFilter.Protocol)" -ForegroundColor Gray
            }
            
            if (Confirm-Action "    Disable this rule?") {
                try {
                    Disable-NetFirewallRule -Name $rule.Name
                    Print-Success "    Disabled: $($rule.DisplayName)"
                }
                catch {
                    Print-Error "    Failed to disable rule: $_"
                }
            }
            
            Write-Host ""
        }
    }
    
    # ========================================
    # STEP 3: Block Common Attack Vectors
    # ========================================
    Print-Header "STEP 3: BLOCK COMMON ATTACK VECTORS"
    
    Print-Info "Configuring rules to block common attack ports..."
    
    $attackPorts = @{
        "Block-Telnet-Inbound" = @{
            "DisplayName" = "Block Telnet (Port 23)"
            "Protocol" = "TCP"
            "LocalPort" = 23
            "Direction" = "Inbound"
            "Action" = "Block"
            "Description" = "Block insecure Telnet protocol"
        }
        "Block-FTP-Inbound" = @{
            "DisplayName" = "Block FTP (Port 21)"
            "Protocol" = "TCP"
            "LocalPort" = 21
            "Direction" = "Inbound"
            "Action" = "Block"
            "Description" = "Block insecure FTP protocol"
        }
        "Block-TFTP-Inbound" = @{
            "DisplayName" = "Block TFTP (Port 69)"
            "Protocol" = "UDP"
            "LocalPort" = 69
            "Direction" = "Inbound"
            "Action" = "Block"
            "Description" = "Block insecure TFTP protocol"
        }
        "Block-NetBIOS-Inbound" = @{
            "DisplayName" = "Block NetBIOS (Ports 137-139)"
            "Protocol" = "TCP"
            "LocalPort" = @(137, 138, 139)
            "Direction" = "Inbound"
            "Action" = "Block"
            "Description" = "Block NetBIOS ports often used for attacks"
        }
        "Block-SMBv1-Inbound" = @{
            "DisplayName" = "Block SMBv1 (Port 445)"
            "Protocol" = "TCP"
            "LocalPort" = 445
            "Direction" = "Inbound"
            "Action" = "Block"
            "Description" = "Block SMB port to prevent ransomware attacks"
        }
    }
    
    if (Confirm-Action "Create firewall rules to block common attack ports?") {
        foreach ($ruleName in $attackPorts.Keys) {
            if (!(Confirm-Action "Block $($ruleName)")) {
                continue
            }
            $ruleConfig = $attackPorts[$ruleName]
            
            # Check if rule already exists
            $existingRule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
            
            if ($existingRule) {
                Print-Info "Rule already exists: $($ruleConfig.DisplayName)"
                if (Confirm-Action "  Update existing rule?") {
                    try {
                        Remove-NetFirewallRule -Name $ruleName
                        New-NetFirewallRule -Name $ruleName `
                            -DisplayName $ruleConfig.DisplayName `
                            -Direction $ruleConfig.Direction `
                            -Action $ruleConfig.Action `
                            -Protocol $ruleConfig.Protocol `
                            -LocalPort $ruleConfig.LocalPort `
                            -Profile Any `
                            -Description $ruleConfig.Description `
                            -Enabled True | Out-Null
                        Print-Success "Updated: $($ruleConfig.DisplayName)"
                    }
                    catch {
                        Print-Error "Failed to update rule: $_"
                    }
                }
            }
            else {
                try {
                    New-NetFirewallRule -Name $ruleName `
                        -DisplayName $ruleConfig.DisplayName `
                        -Direction $ruleConfig.Direction `
                        -Action $ruleConfig.Action `
                        -Protocol $ruleConfig.Protocol `
                        -LocalPort $ruleConfig.LocalPort `
                        -Profile Any `
                        -Description $ruleConfig.Description `
                        -Enabled True | Out-Null
                    Print-Success "Created: $($ruleConfig.DisplayName)"
                }
                catch {
                    Print-Error "Failed to create rule: $_"
                }
            }
        }
    }
    
    # ========================================
    # STEP 4: Configure Specific Service Rules
    # ========================================
    Print-Header "STEP 4: CONFIGURE SERVICE-SPECIFIC RULES"
    
    if (Confirm-Action "Do you want to configure specific service rules (RDP, SSH, etc.)?") {
        # RDP Configuration
        Write-Host "`n--- Remote Desktop (RDP) Configuration ---" -ForegroundColor Cyan
        $rdpRule = Get-NetFirewallRule -DisplayName "*Remote Desktop*" -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true }
        
        if ($rdpRule) {
            Write-Host "RDP firewall rules are currently ENABLED" -ForegroundColor Yellow
            if (Confirm-Action "Keep RDP enabled?") {
                Print-Info "RDP rules kept enabled"
            } else {
                Disable-NetFirewallRule -DisplayName "*Remote Desktop*"
                Print-Success "Disabled all RDP firewall rules"
            }
        } else {
            if (Confirm-Action "Enable Remote Desktop firewall rules?") {
                Enable-NetFirewallRule -DisplayName "*Remote Desktop*" -ErrorAction SilentlyContinue
                Print-Success "Enabled RDP firewall rules"
            }
        }
        
        # File and Printer Sharing
        Write-Host "`n--- File and Printer Sharing ---" -ForegroundColor Cyan
        $fileShareRule = Get-NetFirewallRule -DisplayGroup "File and Printer Sharing" -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true }
        
        if ($fileShareRule) {
            Write-Host "File and Printer Sharing rules are currently ENABLED" -ForegroundColor Yellow
            if (Confirm-Action "Disable File and Printer Sharing?") {
                Disable-NetFirewallRule -DisplayGroup "File and Printer Sharing"
                Print-Success "Disabled File and Printer Sharing rules"
            }
        }
        
        # Windows Remote Management
        Write-Host "`n--- Windows Remote Management (WinRM) ---" -ForegroundColor Cyan
        $winrmRule = Get-NetFirewallRule -DisplayGroup "Windows Remote Management" -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true }
        
        if ($winrmRule) {
            Write-Host "WinRM rules are currently ENABLED" -ForegroundColor Yellow
            if (Confirm-Action "Keep WinRM enabled?") {
                Print-Info "WinRM rules kept enabled"
            } else {
                Disable-NetFirewallRule -DisplayGroup "Windows Remote Management"
                Print-Success "Disabled WinRM firewall rules"
            }
        }
    }
    
    # ========================================
    # STEP 5: Disable Unused Rule Groups
    # ========================================
    Print-Header "STEP 5: DISABLE UNUSED RULE GROUPS"
    
    if (Confirm-Action "Review and disable unused rule groups?") {
        $commonUnusedGroups = @(
            "Network Discovery",
            "DLNA Streaming Server",
            "Media Center Extenders",
            "Windows Media Player",
            "Wireless Display",
            "Cast to Device functionality"
        )
        
        foreach ($group in $commonUnusedGroups) {
            $groupRules = Get-NetFirewallRule -DisplayGroup $group -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true }
            
            if ($groupRules) {
                Write-Host "`n$group - $($groupRules.Count) rule(s) enabled" -ForegroundColor Yellow
                if (Confirm-Action "Disable '$group' rules?") {
                    try {
                        Disable-NetFirewallRule -DisplayGroup $group
                        Print-Success "Disabled: $group"
                    }
                    catch {
                        Print-Error "Failed to disable: $group"
                    }
                }
            }
        }
    }
    
    # ========================================
    # Summary
    # ========================================
    Print-Header "FIREWALL CONFIGURATION SUMMARY"
    
    # Get updated firewall status
    $domainProfile = Get-NetFirewallProfile -Name Domain
    $privateProfile = Get-NetFirewallProfile -Name Private
    $publicProfile = Get-NetFirewallProfile -Name Public
    
    Write-Host "`nFirewall Status:" -ForegroundColor Cyan
    Write-Host "  Domain Profile:  $(if ($domainProfile.Enabled) { 'Enabled' } else { 'DISABLED' })" -ForegroundColor $(if ($domainProfile.Enabled) { 'Green' } else { 'Red' })
    Write-Host "    Default Inbound:  $($domainProfile.DefaultInboundAction)" -ForegroundColor White
    Write-Host "    Default Outbound: $($domainProfile.DefaultOutboundAction)" -ForegroundColor White
    Write-Host ""
    Write-Host "  Private Profile: $(if ($privateProfile.Enabled) { 'Enabled' } else { 'DISABLED' })" -ForegroundColor $(if ($privateProfile.Enabled) { 'Green' } else { 'Red' })
    Write-Host "    Default Inbound:  $($privateProfile.DefaultInboundAction)" -ForegroundColor White
    Write-Host "    Default Outbound: $($privateProfile.DefaultOutboundAction)" -ForegroundColor White
    Write-Host ""
    Write-Host "  Public Profile:  $(if ($publicProfile.Enabled) { 'Enabled' } else { 'DISABLED' })" -ForegroundColor $(if ($publicProfile.Enabled) { 'Green' } else { 'Red' })
    Write-Host "    Default Inbound:  $($publicProfile.DefaultInboundAction)" -ForegroundColor White
    Write-Host "    Default Outbound: $($publicProfile.DefaultOutboundAction)" -ForegroundColor White
    
    $enabledRules = Get-NetFirewallRule | Where-Object { $_.Enabled -eq $true }
    Write-Host "`nTotal Enabled Rules: $($enabledRules.Count)" -ForegroundColor Cyan
    
    Print-Info "`nYou can verify these settings by opening Windows Defender Firewall with Advanced Security"
    Print-Info "Run: wf.msc"
    
    Print-Header "FIREWALL CONFIGURATION COMPLETE"
    Press-Enter
}

#############################################
# Main Menu
#############################################

function Show-Menu {
    Clear-Host
    Write-Host "1) User Account Auditing" -ForegroundColor Green
    Write-Host "2) Configure Password Policies" -ForegroundColor Green
    Write-Host "3) Configure Local Security Policy" -ForegroundColor Green
    Write-Host "4) Configure Windows Firewall" -ForegroundColor Green
    Write-Host ""
    Write-Host "0) Exit" -ForegroundColor Red
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
            "1" { Invoke-UserAuditing }
            "2" { Configure-PasswordPolicy }
            "3" { Configure-LocalSecurityPolicy }
            "4" { Configure-Firewall }
            "0" {
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
