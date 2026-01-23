#!/bin/bash

#############################################
# CIS Benchmark Security Hardening Script
# For Ubuntu 24 / Linux Mint 21
#############################################

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Log file
LOG_FILE="/var/log/cis_benchmark_$(date +%Y%m%d_%H%M%S).log"

#############################################
# Utility Functions
#############################################

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

print_header() {
    echo -e "${CYAN}${BOLD}"
    echo "════════════════════════════════════════════════════════════"
    echo "$1"
    echo "════════════════════════════════════════════════════════════"
    echo -e "${NC}"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
    log_message "SUCCESS: $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
    log_message "ERROR: $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
    log_message "WARNING: $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
    log_message "INFO: $1"
}

confirm_action() {
    echo -e -n "${YELLOW}$1 (y/n): ${NC}"
    read -r response
    [[ "$response" =~ ^[Yy]$ ]]
}

press_enter() {
    echo -e "\n${CYAN}Press Enter to continue...${NC}"
    read -r
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

#############################################
# ASCII Art / Splash Screen
#############################################

show_splash() {
    clear
    echo -e "${CYAN}${BOLD}"
    cat << "EOF"
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║     ██████╗██╗███████╗                                   ║
    ║    ██╔════╝██║██╔════╝                                   ║
    ║    ██║     ██║███████╗                                   ║
    ║    ██║     ██║╚════██║                                   ║
    ║    ╚██████╗██║███████║                                   ║
    ║     ╚═════╝╚═╝╚══════╝                                   ║
    ║                                                           ║
    ║    ██████╗ ███████╗███╗   ██╗ ██████╗██╗  ██╗           ║
    ║    ██╔══██╗██╔════╝████╗  ██║██╔════╝██║  ██║           ║
    ║    ██████╔╝█████╗  ██╔██╗ ██║██║     ███████║           ║
    ║    ██╔══██╗██╔══╝  ██║╚██╗██║██║     ██╔══██║           ║
    ║    ██████╔╝███████╗██║ ╚████║╚██████╗██║  ██║           ║
    ║    ╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝           ║
    ║                                                           ║
    ║           Security Hardening & Audit Tool                ║
    ║              CIS Benchmark Compliance                    ║
    ║                   Ubuntu 24 / Mint 21                    ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "${YELLOW}                    System: $(hostname)${NC}"
    echo -e "${YELLOW}                    Date: $(date)${NC}"
    echo ""
    sleep 1
}

#############################################
# Module Template
#############################################

module_template() {
    print_header "MODULE NAME"
    print_info "Module description goes here"
    echo ""
    
    local changes_made=false
    
    if ! confirm_action "Run this module?"; then
        print_info "Skipping module"
        press_enter
        return
    fi
    
    echo -e "\n${BOLD}Module implementation goes here${NC}"
    
    # Your code here
    print_info "Placeholder for actual implementation"
    
    # Summary
    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════${NC}"
    if [[ "$changes_made" == true ]]; then
        print_success "Module completed with changes"
    else
        print_info "No changes were made"
    fi
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    
    press_enter
}

#############################################
# Task 1: CIS 1.1.1 - Filesystem Kernel Modules
#############################################

task_1() {
    print_header "CIS 1.1.1 - CONFIGURE FILESYSTEM KERNEL MODULES"
    print_info "Disabling unused filesystem kernel modules"
    echo ""
    
    local changes_made=false
    local modprobe_conf="/etc/modprobe.d/cis-filesystems.conf"
    
    if ! confirm_action "Disable unused filesystem kernel modules per CIS 1.1.1?"; then
        print_info "Skipping filesystem kernel module configuration"
        press_enter
        return
    fi
    
    # Create modprobe config file
    cat > "$modprobe_conf" << 'EOF'
# CIS Benchmark 1.1.1 - Disable unused filesystem kernel modules

# 1.1.1.1 Ensure cramfs kernel module is not available
install cramfs /bin/false
blacklist cramfs

# 1.1.1.2 Ensure freevxfs kernel module is not available
install freevxfs /bin/false
blacklist freevxfs

# 1.1.1.3 Ensure hfs kernel module is not available
install hfs /bin/false
blacklist hfs

# 1.1.1.4 Ensure hfsplus kernel module is not available
install hfsplus /bin/false
blacklist hfsplus

# 1.1.1.5 Ensure jffs2 kernel module is not available
install jffs2 /bin/false
blacklist jffs2

# 1.1.1.6 Ensure overlay kernel module is not available (if not using containers)
# install overlay /bin/false
# blacklist overlay

# 1.1.1.7 Ensure squashfs kernel module is not available (if not using snaps)
# install squashfs /bin/false
# blacklist squashfs

# 1.1.1.8 Ensure udf kernel module is not available
install udf /bin/false
blacklist udf

# 1.1.1.9 Ensure usb-storage kernel module is not available (if not needed)
# install usb-storage /bin/false
# blacklist usb-storage
EOF
    
    print_success "Created $modprobe_conf"
    changes_made=true
    
    # Unload modules if currently loaded
    echo -e "\n${BOLD}Unloading modules if currently loaded...${NC}"
    local modules=("cramfs" "freevxfs" "hfs" "hfsplus" "jffs2" "udf")
    
    for mod in "${modules[@]}"; do
        if lsmod | grep -q "^$mod"; then
            print_warning "$mod is currently loaded"
            if rmmod "$mod" 2>/dev/null; then
                print_success "Unloaded $mod"
            else
                print_warning "Could not unload $mod (may be in use)"
            fi
        else
            print_info "$mod not currently loaded"
        fi
    done
    
    # Update initramfs
    echo -e "\n${BOLD}Updating initramfs...${NC}"
    if confirm_action "Update initramfs to apply changes?"; then
        update-initramfs -u 2>/dev/null && print_success "initramfs updated"
    fi
    
    # Summary
    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════${NC}"
    print_success "Filesystem kernel modules disabled per CIS 1.1.1"
    print_info "Disabled: cramfs, freevxfs, hfs, hfsplus, jffs2, udf"
    print_warning "Note: overlay and squashfs commented out (may be needed for containers/snaps)"
    print_warning "Note: usb-storage commented out (may be needed for USB drives)"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    
    press_enter
}

#############################################
# Task 2: CIS 1.1.2 - Filesystem Partitions
#############################################

task_2() {
    print_header "CIS 1.1.2 - CONFIGURE FILESYSTEM PARTITIONS"
    print_info "Auditing and configuring partition mount options"
    echo ""
    
    local changes_made=false
    local fstab="/etc/fstab"
    
    if ! confirm_action "Audit and configure partition mount options per CIS 1.1.2?"; then
        print_info "Skipping partition configuration"
        press_enter
        return
    fi
    
    # Backup fstab
    cp "$fstab" "${fstab}.bak.$(date +%Y%m%d_%H%M%S)"
    print_success "Backed up $fstab"
    
    echo -e "\n${BOLD}Current Partition Configuration:${NC}"
    df -h | grep -E "^/dev|^tmpfs" | grep -E "/(tmp|home|var)" || echo "No relevant partitions found"
    echo ""
    findmnt --fstab -t tmpfs,ext4,xfs,btrfs | grep -E "/(tmp|home|var)" || echo "No entries in fstab"
    echo ""
    
    # CIS 1.1.2.1 - /tmp configuration
    echo -e "${BOLD}═══ CIS 1.1.2.1 - /tmp Configuration ═══${NC}"
    
    if ! grep -q "^tmpfs /tmp" "$fstab" && ! findmnt -n /tmp | grep -q tmpfs; then
        print_warning "/tmp is not tmpfs or separate partition"
        if confirm_action "Configure /tmp as tmpfs with nodev,nosuid,noexec?"; then
            echo "tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec,mode=1777 0 0" >> "$fstab"
            print_success "Added /tmp tmpfs to fstab"
            changes_made=true
        fi
    else
        print_success "/tmp already configured"
        
        # Check options
        if ! findmnt -n /tmp | grep -q "nodev"; then
            print_warning "/tmp missing nodev option"
        fi
        if ! findmnt -n /tmp | grep -q "nosuid"; then
            print_warning "/tmp missing nosuid option"
        fi
        if ! findmnt -n /tmp | grep -q "noexec"; then
            print_warning "/tmp missing noexec option"
        fi
    fi
    
    # CIS 1.1.2.2 - /dev/shm configuration
    echo -e "\n${BOLD}═══ CIS 1.1.2.2 - /dev/shm Configuration ═══${NC}"
    
    if ! grep -q "/dev/shm" "$fstab" || ! findmnt -n /dev/shm | grep -q "noexec"; then
        if grep -q "^tmpfs /dev/shm" "$fstab"; then
            sed -i 's|^tmpfs /dev/shm tmpfs.*|tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0|' "$fstab"
            print_success "Updated /dev/shm options in fstab"
        else
            echo "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0" >> "$fstab"
            print_success "Added /dev/shm to fstab"
        fi
        changes_made=true
    else
        print_success "/dev/shm already configured properly"
    fi
    
    # CIS 1.1.2.5 - /var/tmp configuration
    echo -e "\n${BOLD}═══ CIS 1.1.2.5 - /var/tmp Configuration ═══${NC}"
    
    if ! grep -q "/var/tmp" "$fstab"; then
        print_warning "/var/tmp not configured with restrictive options"
        if confirm_action "Configure /var/tmp with nodev,nosuid,noexec?"; then
            echo "tmpfs /var/tmp tmpfs defaults,nodev,nosuid,noexec,mode=1777 0 0" >> "$fstab"
            print_success "Added /var/tmp to fstab"
            changes_made=true
        fi
    fi
    
    # Information about other partitions
    echo -e "\n${BOLD}═══ Additional Partition Checks ═══${NC}"
    print_info "CIS 1.1.2.3: Separate /home partition (Manual check)"
    print_info "CIS 1.1.2.4: Separate /var partition (Manual check)"
    print_info "CIS 1.1.2.6: Separate /var/log partition (Manual check)"
    print_info "CIS 1.1.2.7: Separate /var/log/audit partition (Manual check)"
    echo ""
    print_warning "These require manual review - check if separate partitions exist:"
    df -h | grep -E "/(home|var)$" || echo "No separate partitions found"
    
    # Summary
    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════${NC}"
    if [[ "$changes_made" == true ]]; then
        print_success "Partition configuration updated per CIS 1.1.2"
        print_warning "Remount or reboot to apply changes:"
        echo -e "  ${CYAN}mount -o remount /tmp${NC}"
        echo -e "  ${CYAN}mount -o remount /dev/shm${NC}"
        echo -e "  ${CYAN}mount -o remount /var/tmp${NC}"
    else
        print_info "No changes made - review manually"
    fi
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    
    press_enter
}

#############################################
# Task 3: CIS 1.2 - Package Management
#############################################

task_3() {
    print_header "CIS 1.2 - PACKAGE MANAGEMENT"
    print_info "Configuring package repositories and automatic updates"
    echo ""
    
    local changes_made=false
    
    if ! confirm_action "Configure package management per CIS 1.2?"; then
        print_info "Skipping package management configuration"
        press_enter
        return
    fi
    
    # CIS 1.2.1.1 - GPG keys check
    echo -e "${BOLD}═══ CIS 1.2.1.1 - GPG Keys ═══${NC}"
    print_info "Checking GPG keys for package repositories"
    apt-key list 2>/dev/null | head -20
    echo ""
    print_warning "Manual: Verify all keys are authorized"
    
    # CIS 1.2.1.2 - Repository check
    echo -e "\n${BOLD}═══ CIS 1.2.1.2 - Package Repositories ═══${NC}"
    print_info "Current repository configuration:"
    grep -h "^deb" /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null | grep -v "^#" | head -10
    echo ""
    print_warning "Manual: Verify all repositories are authorized"
    
    # CIS 1.2.2.1 - Updates check
    echo -e "\n${BOLD}═══ CIS 1.2.2.1 - System Updates ═══${NC}"
    if confirm_action "Check for available updates?"; then
        apt update
        local updates=$(apt list --upgradable 2>/dev/null | grep -c "upgradable")
        if [[ $updates -gt 0 ]]; then
            print_warning "$updates package(s) can be updated"
            if confirm_action "Install updates now?"; then
                apt upgrade -y
                print_success "System updated"
                changes_made=true
            fi
        else
            print_success "System is up to date"
        fi
    fi
    
    # CIS 1.2.2.2 - Automatic updates
    echo -e "\n${BOLD}═══ CIS 1.2.2.2 - Automatic Updates ═══${NC}"
    
    if ! dpkg -l | grep -q "unattended-upgrades"; then
        print_warning "unattended-upgrades not installed"
        if confirm_action "Install unattended-upgrades?"; then
            apt install -y unattended-upgrades apt-listchanges
            print_success "Installed unattended-upgrades"
            changes_made=true
        fi
    else
        print_success "unattended-upgrades already installed"
    fi
    
    if dpkg -l | grep -q "unattended-upgrades"; then
        if confirm_action "Configure automatic security updates?"; then
            cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
            
            cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
            
            print_success "Configured automatic security updates"
            changes_made=true
        fi
    fi
    
    # Summary
    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════${NC}"
    if [[ "$changes_made" == true ]]; then
        print_success "Package management configured per CIS 1.2"
    else
        print_info "No changes made"
    fi
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    
    press_enter
}

#############################################
# Task 4: CIS 1.3 - Mandatory Access Control (AppArmor)
#############################################

task_4() {
    print_header "CIS 1.3 - MANDATORY ACCESS CONTROL (APPARMOR)"
    print_info "Configuring AppArmor per CIS benchmark"
    echo ""
    
    local changes_made=false
    
    if ! confirm_action "Configure AppArmor per CIS 1.3?"; then
        print_info "Skipping AppArmor configuration"
        press_enter
        return
    fi
    
    # CIS 1.3.1.1 - Ensure AppArmor packages are installed
    echo -e "${BOLD}═══ CIS 1.3.1.1 - AppArmor Packages ═══${NC}"
    
    local apparmor_pkgs=("apparmor" "apparmor-utils")
    for pkg in "${apparmor_pkgs[@]}"; do
        if ! dpkg -l | grep -q "^ii.*$pkg"; then
            print_warning "$pkg not installed"
            if confirm_action "Install $pkg?"; then
                apt install -y "$pkg"
                print_success "Installed $pkg"
                changes_made=true
            fi
        else
            print_success "$pkg already installed"
        fi
    done
    
    # CIS 1.3.1.2 - Ensure AppArmor is enabled in bootloader
    echo -e "\n${BOLD}═══ CIS 1.3.1.2 - AppArmor Boot Configuration ═══${NC}"
    
    local grub_cfg="/etc/default/grub"
    if [[ -f "$grub_cfg" ]]; then
        if grep -q "^GRUB_CMDLINE_LINUX_DEFAULT=" "$grub_cfg"; then
            local current=$(grep "^GRUB_CMDLINE_LINUX_DEFAULT=" "$grub_cfg")
            
            if ! echo "$current" | grep -q "apparmor=1"; then
                print_warning "apparmor=1 not in GRUB config"
                if confirm_action "Add apparmor=1 to GRUB?"; then
                    cp "$grub_cfg" "${grub_cfg}.bak.$(date +%Y%m%d_%H%M%S)"
                    sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 apparmor=1 security=apparmor"/' "$grub_cfg"
                    update-grub
                    print_success "Added AppArmor to GRUB config"
                    print_warning "Reboot required for changes to take effect"
                    changes_made=true
                fi
            else
                print_success "AppArmor already enabled in GRUB"
            fi
        fi
    fi
    
    # CIS 1.3.1.3 & 1.3.1.4 - AppArmor profiles
    echo -e "\n${BOLD}═══ CIS 1.3.1.3/4 - AppArmor Profiles ═══${NC}"
    
    if command -v aa-status &>/dev/null; then
        print_info "Current AppArmor status:"
        aa-status --verbose 2>/dev/null | head -30
        echo ""
        
        # Check for disabled profiles
        local disabled=$(aa-status 2>/dev/null | grep "profiles are loaded" | grep -oP '\d+' | head -1)
        local complain=$(aa-status 2>/dev/null | grep "profiles are in complain mode" | grep -oP '\d+' | head -1)
        
        if [[ -n "$complain" && "$complain" -gt 0 ]]; then
            print_warning "$complain profile(s) in complain mode (should be enforcing)"
            if confirm_action "Set all profiles to enforce mode?"; then
                for profile in /etc/apparmor.d/*; do
                    if [[ -f "$profile" ]] && [[ ! "$profile" =~ (abstractions|cache|disable|force-complain|local|tunables) ]]; then
                        aa-enforce "$profile" 2>/dev/null
                    fi
                done
                print_success "Set profiles to enforce mode"
                changes_made=true
            fi
        else
            print_success "All profiles in enforce mode"
        fi
        
        # Enable AppArmor service
        if ! systemctl is-active apparmor &>/dev/null; then
            if confirm_action "Enable and start AppArmor service?"; then
                systemctl enable apparmor
                systemctl start apparmor
                print_success "AppArmor service enabled and started"
                changes_made=true
            fi
        else
            print_success "AppArmor service is active"
        fi
    else
        print_error "aa-status command not available"
    fi
    
    # Summary
    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════${NC}"
    if [[ "$changes_made" == true ]]; then
        print_success "AppArmor configured per CIS 1.3"
        print_warning "Reboot may be required for boot configuration changes"
    else
        print_info "No changes made"
    fi
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    
    press_enter
}

#############################################
# Task 5: CIS 1.4 - Bootloader Configuration
#############################################

task_5() {
    print_header "CIS 1.4 - BOOTLOADER CONFIGURATION"
    print_info "Securing GRUB bootloader"
    echo ""
    
    local changes_made=false
    
    print_danger "WARNING: This configures bootloader security"
    print_danger "Incorrect configuration may prevent system boot!"
    echo ""
    
    if ! confirm_action "Configure bootloader per CIS 1.4?"; then
        print_info "Skipping bootloader configuration"
        press_enter
        return
    fi
    
    # CIS 1.4.1 - Bootloader password
    echo -e "${BOLD}═══ CIS 1.4.1 - Bootloader Password ═══${NC}"
    
    local grub_cfg="/boot/grub/grub.cfg"
    local grub_user_cfg="/etc/grub.d/40_custom"
    
    if [[ ! -f "$grub_cfg" ]]; then
        print_error "GRUB config not found at $grub_cfg"
    else
        if grep -q "^password" "$grub_cfg"; then
            print_success "Bootloader password already configured"
        else
            print_warning "No bootloader password configured"
            print_info "To set bootloader password:"
            echo -e "  1. Run: ${CYAN}grub-mkpasswd-pbkdf2${NC}"
            echo -e "  2. Add to /etc/grub.d/40_custom:"
            echo -e "     ${CYAN}set superusers=\"root\"${NC}"
            echo -e "     ${CYAN}password_pbkdf2 root <hash>${NC}"
            echo -e "  3. Run: ${CYAN}update-grub${NC}"
            print_danger "Manual step required - not automated for safety"
        fi
    fi
    
    # CIS 1.4.2 - Bootloader permissions
    echo -e "\n${BOLD}═══ CIS 1.4.2 - Bootloader Permissions ═══${NC}"
    
    if [[ -f "$grub_cfg" ]]; then
        local current_perms=$(stat -c "%a" "$grub_cfg")
        if [[ "$current_perms" != "400" && "$current_perms" != "600" ]]; then
            print_warning "$grub_cfg has permissions $current_perms (should be 400/600)"
            if confirm_action "Set $grub_cfg permissions to 400?"; then
                chmod 400 "$grub_cfg"
                chown root:root "$grub_cfg"
                print_success "Set $grub_cfg to 400 root:root"
                changes_made=true
            fi
        else
            print_success "$grub_cfg permissions correct ($current_perms)"
        fi
    fi
    
    # Additional GRUB security
    echo -e "\n${BOLD}═══ Additional Bootloader Security ═══${NC}"
    
    local grub_default="/etc/default/grub"
    if [[ -f "$grub_default" ]]; then
        # Disable recovery mode
        if ! grep -q "^GRUB_DISABLE_RECOVERY=" "$grub_default"; then
            if confirm_action "Disable GRUB recovery mode?"; then
                echo "GRUB_DISABLE_RECOVERY=true" >> "$grub_default"
                update-grub
                print_success "Disabled recovery mode"
                changes_made=true
            fi
        fi
    fi
    
    # Summary
    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════${NC}"
    if [[ "$changes_made" == true ]]; then
        print_success "Bootloader configured per CIS 1.4"
        print_info "Bootloader password requires manual setup"
    else
        print_info "No changes made"
    fi
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    
    press_enter
}

#############################################
# Task 6: CIS 1.5 - Additional Process Hardening
#############################################

task_6() {
    print_header "CIS 1.5 - ADDITIONAL PROCESS HARDENING"
    print_info "Configuring kernel security parameters"
    echo ""
    
    local changes_made=false
    local sysctl_cis="/etc/sysctl.d/99-cis.conf"
    
    if ! confirm_action "Configure process hardening per CIS 1.5?"; then
        print_info "Skipping process hardening"
        press_enter
        return
    fi
    
    # Backup existing sysctl config
    if [[ -f "$sysctl_cis" ]]; then
        cp "$sysctl_cis" "${sysctl_cis}.bak.$(date +%Y%m%d_%H%M%S)"
    fi
    
    echo -e "${BOLD}═══ CIS 1.5.1-6 - Kernel Parameters ═══${NC}"
    
    # Create/update sysctl configuration
    cat > "$sysctl_cis" << 'EOF'
# CIS 1.5 - Additional Process Hardening

# CIS 1.5.1 - Core dumps
fs.suid_dumpable = 0
kernel.core_uses_pid = 1

# CIS 1.5.2 - Address space layout randomization (ASLR)
kernel.randomize_va_space = 2

# CIS 1.5.3 - Prelink (disable if installed)
# prelink should be removed

# CIS 1.5.4 - Automatic Error Reporting
# apport should be disabled

# Additional hardening
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 2
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# Process restrictions
kernel.perf_event_paranoid = 3
kernel.kexec_load_disabled = 1

# CIS requirement - disable SysRq
kernel.sysrq = 0
EOF
    
    print_success "Created $sysctl_cis"
    changes_made=true
    
    # Apply sysctl settings
    if confirm_action "Apply sysctl settings now?"; then
        sysctl -p "$sysctl_cis"
        print_success "Applied sysctl settings"
    fi
    
    # CIS 1.5.3 - Check for prelink
    echo -e "\n${BOLD}═══ CIS 1.5.3 - Prelink Check ═══${NC}"
    
    if dpkg -l | grep -q "^ii.*prelink"; then
        print_warning "prelink is installed (CIS recommends removal)"
        if confirm_action "Remove prelink package?"; then
            apt purge -y prelink
            print_success "Removed prelink"
            changes_made=true
        fi
    else
        print_success "prelink not installed"
    fi
    
    # CIS 1.5.4 - Automatic error reporting
    echo -e "\n${BOLD}═══ CIS 1.5.4 - Automatic Error Reporting ═══${NC}"
    
    if dpkg -l | grep -q "^ii.*apport"; then
        if systemctl is-active apport &>/dev/null; then
            print_warning "apport service is active"
            if confirm_action "Disable apport service?"; then
                systemctl stop apport
                systemctl disable apport
                systemctl mask apport
                print_success "Disabled apport"
                changes_made=true
            fi
        else
            print_success "apport is not active"
        fi
    else
        print_success "apport not installed"
    fi
    
    # Core dump configuration
    echo -e "\n${BOLD}═══ Core Dump Configuration ═══${NC}"
    
    local coredump_conf="/etc/systemd/coredump.conf"
    if [[ -f "$coredump_conf" ]]; then
        if ! grep -q "^Storage=none" "$coredump_conf"; then
            if confirm_action "Disable core dumps in systemd?"; then
                mkdir -p /etc/systemd/coredump.conf.d/
                cat > /etc/systemd/coredump.conf.d/99-disable.conf << 'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
                print_success "Disabled systemd core dumps"
                changes_made=true
            fi
        else
            print_success "Core dumps already disabled"
        fi
    fi
    
    # limits.conf for core dumps
    if ! grep -q "^* hard core 0" /etc/security/limits.conf; then
        echo "* hard core 0" >> /etc/security/limits.conf
        print_success "Added hard core limit to limits.conf"
        changes_made=true
    fi
    
    # Summary
    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════${NC}"
    if [[ "$changes_made" == true ]]; then
        print_success "Process hardening configured per CIS 1.5"
        print_info "Current sysctl hardening:"
        sysctl kernel.randomize_va_space kernel.dmesg_restrict kernel.sysrq 2>/dev/null
    else
        print_info "No changes made"
    fi
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    
    press_enter
}

#############################################
# Task 7: CIS 1.6 - Command Line Warning Banners
#############################################

task_7() {
    print_header "CIS 1.6 - COMMAND LINE WARNING BANNERS"
    print_info "Configuring warning banners for system access"
    echo ""
    
    local changes_made=false
    
    if ! confirm_action "Configure warning banners per CIS 1.6?"; then
        print_info "Skipping banner configuration"
        press_enter
        return
    fi
    
    # CIS 1.6.1 - /etc/motd
    echo -e "${BOLD}═══ CIS 1.6.1 - Message of the Day (MOTD) ═══${NC}"
    
    local motd="/etc/motd"
    local banner_text="Authorized users only. All activity may be monitored and reported."
    
    if [[ ! -f "$motd" ]] || ! grep -q "Authorized users only" "$motd"; then
        cat > "$motd" << EOF
################################################################################
#                              WARNING NOTICE                                  #
################################################################################
#                                                                              #
#  This system is for authorized use only. Users have no expectation of       #
#  privacy. Unauthorized access or use may subject violators to criminal,     #
#  civil, and/or administrative action. All activities are logged and         #
#  monitored. By accessing this system, you consent to these terms.           #
#                                                                              #
################################################################################
EOF
        print_success "Created $motd"
        changes_made=true
    else
        print_success "$motd already configured"
    fi
    
    # CIS 1.6.2 - /etc/issue
    echo -e "\n${BOLD}═══ CIS 1.6.2 - Local Login Banner (issue) ═══${NC}"
    
    local issue="/etc/issue"
    if [[ ! -f "$issue" ]] || ! grep -q "Authorized users only" "$issue"; then
        cat > "$issue" << 'EOF'
Authorized users only. All activity may be monitored and reported.
EOF
        print_success "Created $issue"
        changes_made=true
    else
        print_success "$issue already configured"
    fi
    
    # CIS 1.6.3 - /etc/issue.net
    echo -e "\n${BOLD}═══ CIS 1.6.3 - Remote Login Banner (issue.net) ═══${NC}"
    
    local issue_net="/etc/issue.net"
    if [[ ! -f "$issue_net" ]] || ! grep -q "Authorized users only" "$issue_net"; then
        cat > "$issue_net" << 'EOF'
Authorized users only. All activity may be monitored and reported.
EOF
        print_success "Created $issue_net"
        changes_made=true
    else
        print_success "$issue_net already configured"
    fi
    
    # Set proper permissions
    echo -e "\n${BOLD}═══ Setting Banner Permissions ═══${NC}"
    
    for banner_file in "$motd" "$issue" "$issue_net"; do
        if [[ -f "$banner_file" ]]; then
            chmod 644 "$banner_file"
            chown root:root "$banner_file"
            print_success "Set permissions on $banner_file"
        fi
    done
    
    # Configure SSH banner
    echo -e "\n${BOLD}═══ SSH Banner Configuration ═══${NC}"
    
    local sshd_config="/etc/ssh/sshd_config"
    if [[ -f "$sshd_config" ]]; then
        if grep -q "^#Banner" "$sshd_config" || ! grep -q "^Banner" "$sshd_config"; then
            if confirm_action "Enable SSH banner?"; then
                sed -i 's/^#Banner.*/Banner \/etc\/issue.net/' "$sshd_config"
                if ! grep -q "^Banner" "$sshd_config"; then
                    echo "Banner /etc/issue.net" >> "$sshd_config"
                fi
                print_success "Enabled SSH banner"
                print_warning "SSH service restart required: systemctl restart sshd"
                changes_made=true
            fi
        else
            print_success "SSH banner already configured"
        fi
    fi
    
    # Display banners for review
    echo -e "\n${BOLD}═══ Current Banner Content ═══${NC}"
    print_info "$issue content:"
    cat "$issue"
    echo ""
    
    # Summary
    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════${NC}"
    if [[ "$changes_made" == true ]]; then
        print_success "Warning banners configured per CIS 1.6"
        print_info "Banners set: $motd, $issue, $issue.net"
    else
        print_info "No changes made"
    fi
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    
    press_enter
}

#############################################
# Task 8: CIS 1.7 - Cinnamon Desktop Environment
#############################################

task_8() {
    print_header "CIS 1.7 - CINNAMON DESKTOP ENVIRONMENT"
    print_info "Configuring Cinnamon desktop security settings"
    echo ""
    
    local changes_made=false
    
    if ! confirm_action "Configure Cinnamon desktop per CIS 1.7?"; then
        print_info "Skipping desktop configuration"
        press_enter
        return
    fi
    
    # CIS 1.7.1 - Screensaver lock
    echo -e "${BOLD}═══ CIS 1.7.1 - Screensaver Configuration ═══${NC}"
    
    if command -v gsettings &>/dev/null; then
        # Enable screensaver lock
        print_info "Configuring screensaver lock settings"
        
        # These settings should be configured per-user or via dconf profiles
        print_warning "Screensaver settings require per-user or dconf profile configuration"
        print_info "Recommended settings:"
        echo -e "  ${CYAN}gsettings set org.cinnamon.desktop.screensaver lock-enabled true${NC}"
        echo -e "  ${CYAN}gsettings set org.cinnamon.desktop.screensaver idle-activation-enabled true${NC}"
        echo -e "  ${CYAN}gsettings set org.cinnamon.desktop.screensaver lock-delay 0${NC}"
        echo -e "  ${CYAN}gsettings set org.cinnamon.desktop.session idle-delay 900${NC}"
        echo ""
        
        # Create dconf profile for system-wide settings
        if confirm_action "Create system-wide dconf profile for screensaver?"; then
            mkdir -p /etc/dconf/profile
            cat > /etc/dconf/profile/user << 'EOF'
user-db:user
system-db:local
EOF
            
            mkdir -p /etc/dconf/db/local.d
            cat > /etc/dconf/db/local.d/00-screensaver << 'EOF'
[org/cinnamon/desktop/screensaver]
lock-enabled=true
idle-activation-enabled=true
lock-delay=uint32 0

[org/cinnamon/desktop/session]
idle-delay=uint32 900
EOF
            
            dconf update
            print_success "Created dconf profile for screensaver lock"
            changes_made=true
        fi
    else
        print_error "gsettings command not available"
    fi
    
    # CIS 1.7.2 - Disable user list
    echo -e "\n${BOLD}═══ CIS 1.7.2 - Login Screen User List ═══${NC}"
    
    local lightdm_conf="/etc/lightdm/lightdm.conf"
    local lightdm_conf_d="/etc/lightdm/lightdm.conf.d"
    
    if [[ -d "$lightdm_conf_d" ]]; then
        cat > "${lightdm_conf_d}/50-no-user-list.conf" << 'EOF'
[Seat:*]
greeter-hide-users=true
greeter-show-manual-login=true
allow-guest=false
EOF
        print_success "Disabled user list in LightDM"
        changes_made=true
    elif [[ -f "$lightdm_conf" ]]; then
        if ! grep -q "greeter-hide-users=true" "$lightdm_conf"; then
            if confirm_action "Disable user list in LightDM?"; then
                cp "$lightdm_conf" "${lightdm_conf}.bak.$(date +%Y%m%d_%H%M%S)"
                
                # Add settings to [Seat:*] section
                if grep -q "^\[Seat:\*\]" "$lightdm_conf"; then
                    sed -i '/^\[Seat:\*\]/a greeter-hide-users=true' "$lightdm_conf"
                    sed -i '/^\[Seat:\*\]/a greeter-show-manual-login=true' "$lightdm_conf"
                    sed -i '/^\[Seat:\*\]/a allow-guest=false' "$lightdm_conf"
                else
                    cat >> "$lightdm_conf" << 'EOF'

[Seat:*]
greeter-hide-users=true
greeter-show-manual-login=true
allow-guest=false
EOF
                fi
                print_success "Configured LightDM to hide user list"
                changes_made=true
            fi
        else
            print_success "LightDM user list already hidden"
        fi
    else
        print_warning "LightDM configuration not found"
    fi
    
    # CIS 1.7.3 - Screen lock on suspend
    echo -e "\n${BOLD}═══ CIS 1.7.3 - Lock on Suspend/Sleep ═══${NC}"
    
    if [[ -d "/etc/dconf/db/local.d" ]]; then
        cat > /etc/dconf/db/local.d/00-power-management << 'EOF'
[org/cinnamon/settings-daemon/plugins/power]
sleep-inactive-ac-timeout=900
sleep-inactive-battery-timeout=900
lock-on-suspend=true

[org/cinnamon/desktop/screensaver]
lock-on-suspend=true
EOF
        dconf update
        print_success "Configured lock on suspend"
        changes_made=true
    else
        print_warning "dconf not available for power management settings"
    fi
    
    # Additional desktop security
    echo -e "\n${BOLD}═══ Additional Desktop Security ═══${NC}"
    
    if [[ -d "/etc/dconf/db/local.d" ]]; then
        # Disable automount
        cat > /etc/dconf/db/local.d/00-media-handling << 'EOF'
[org/cinnamon/desktop/media-handling]
automount=false
automount-open=false
autorun-never=true
EOF
        
        # Privacy settings
        cat > /etc/dconf/db/local.d/00-privacy << 'EOF'
[org/cinnamon/desktop/privacy]
remember-recent-files=false
recent-files-max-age=0
remember-app-usage=false
EOF
        
        dconf update
        print_success "Configured additional desktop security settings"
        changes_made=true
    fi
    
    # Summary
    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════${NC}"
    if [[ "$changes_made" == true ]]; then
        print_success "Cinnamon desktop configured per CIS 1.7"
        print_warning "Logout/login required for dconf changes to take effect"
        print_info "Users should verify screensaver lock with: gsettings list-recursively org.cinnamon.desktop.screensaver"
    else
        print_info "No changes made"
    fi
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    
    press_enter
}

#############################################
# Task 9: CIS 2.1 - Disable Unnecessary Server Services
#############################################

task_9() {
    print_header "CIS 2.1 - DISABLE UNNECESSARY SERVER SERVICES"
    print_info "Removing or disabling server services per CIS benchmark"
    echo ""
    
    local changes_made=false
    
    # Services that should NOT be running on most systems
    local unwanted_services=(
        "autofs:autofs:CIS 2.1.1"
        "avahi-daemon:avahi-daemon:CIS 2.1.2"
        "isc-dhcp-server:isc-dhcp-server isc-dhcp-server6:CIS 2.1.3"
        "bind9:bind9:CIS 2.1.4"
        "dnsmasq:dnsmasq:CIS 2.1.5"
        "vsftpd:vsftpd:CIS 2.1.6"
        "slapd:slapd:CIS 2.1.7"
        "dovecot-imapd:dovecot-imapd dovecot-pop3d:CIS 2.1.8"
        "nfs-server:nfs-kernel-server:CIS 2.1.9"
        "nis:nis:CIS 2.1.10"
        "cups:cups cups-daemon:CIS 2.1.12"
        "rpcbind:rpcbind:CIS 2.1.13"
        "rsync:rsync:CIS 2.1.14"
        "smbd:samba samba-common:CIS 2.1.15"
        "snmpd:snmpd:CIS 2.1.16"
        "tftpd-hpa:tftpd-hpa:CIS 2.1.17"
        "squid:squid:CIS 2.1.18"
        "xinet:xinetd:CIS 2.1.20"
    )
    
    # Protected services (LAMP requirement from README)
    local protected_services=("apache2" "mysql" "mariadb" "httpd" "nginx")
    
    if ! confirm_action "Remove/disable unnecessary server services per CIS 2.1?"; then
        print_info "Skipping server service removal"
        press_enter
        return
    fi
    
    echo -e "${BOLD}═══ Checking and Removing Unnecessary Services ═══${NC}"
    echo ""
    
    for service_entry in "${unwanted_services[@]}"; do
        IFS=':' read -r service_name packages cis_ref <<< "$service_entry"
        
        echo -e "${CYAN}[$cis_ref]${NC} Checking $service_name..."
        
        # Check if service is active
        if systemctl is-active "$service_name" &>/dev/null; then
            print_warning "Service $service_name is active"
            systemctl stop "$service_name" 2>/dev/null
            systemctl disable "$service_name" 2>/dev/null
            systemctl mask "$service_name" 2>/dev/null
            print_success "Stopped and disabled $service_name"
            changes_made=true
        fi
        
        # Check if packages are installed and remove
        for pkg in $packages; do
            if dpkg -l | grep -q "^ii.*$pkg"; then
                print_warning "Package $pkg is installed"
                apt purge -y "$pkg" 2>/dev/null
                print_success "Removed $pkg"
                changes_made=true
            fi
        done
    done
    
    # Special handling for SSH (CIS 2.1.11) - configure, don't remove
    echo -e "\n${BOLD}═══ CIS 2.1.11 - SSH Server ═══${NC}"
    if systemctl is-active sshd &>/dev/null || systemctl is-active ssh &>/dev/null; then
        print_info "SSH server is installed and active"
        print_warning "CIS recommends removing SSH if not needed for remote access"
        print_info "Keeping SSH for remote management (consider hardening in Section 5)"
    else
        print_success "SSH server not active"
    fi
    
    # Special handling for web server (CIS 2.1.19) - LAMP protection
    echo -e "\n${BOLD}═══ CIS 2.1.19 - Web Server (LAMP Protected) ═══${NC}"
    if systemctl is-active apache2 &>/dev/null || systemctl is-active httpd &>/dev/null; then
        print_info "Web server (Apache) is active"
        print_warning "CIS recommends removing web servers if not needed"
        print_success "Web server PROTECTED - Required for LAMP/OrangeHRM"
        print_info "Ensure web server is hardened (see MintUbu.sh task 16)"
    else
        print_info "No web server detected"
    fi
    
    # X Window Server (CIS 2.1.21)
    echo -e "\n${BOLD}═══ CIS 2.1.21 - X Window Server ═══${NC}"
    if dpkg -l | grep -q "^ii.*xserver-xorg"; then
        print_warning "X Window Server installed (required for GUI desktop)"
        print_info "This is a desktop system - X Window Server is needed"
        print_success "Keeping X Window Server for Cinnamon desktop"
    else
        print_success "X Window Server check complete"
    fi
    
    # Summary
    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════${NC}"
    if [[ "$changes_made" == true ]]; then
        print_success "Unnecessary server services removed per CIS 2.1"
        print_info "Protected services: SSH (for remote access), Apache (LAMP requirement)"
    else
        print_success "No unnecessary services found"
    fi
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    
    press_enter
}

#############################################
# Task 10: CIS 2.1.22-23 - Mail & Network Service Audit
#############################################

task_10() {
    print_header "CIS 2.1.22-23 - MAIL TRANSFER AGENT & SERVICE AUDIT"
    print_info "Configuring MTA for local-only and auditing listening services"
    echo ""
    
    local changes_made=false
    
    if ! confirm_action "Configure mail transfer agent and audit services per CIS 2.1.22-23?"; then
        print_info "Skipping mail and service audit"
        press_enter
        return
    fi
    
    # CIS 2.1.22 - Mail Transfer Agent local-only mode
    echo -e "${BOLD}═══ CIS 2.1.22 - Mail Transfer Agent Configuration ═══${NC}"
    
    if command -v postfix &>/dev/null && systemctl is-active postfix &>/dev/null; then
        print_info "Postfix detected and active"
        
        local main_cf="/etc/postfix/main.cf"
        if [[ -f "$main_cf" ]]; then
            # Check if configured for local-only
            if grep -q "^inet_interfaces = localhost" "$main_cf"; then
                print_success "Postfix already configured for local-only mode"
            else
                if confirm_action "Configure Postfix for local-only mode?"; then
                    cp "$main_cf" "${main_cf}.bak.$(date +%Y%m%d_%H%M%S)"
                    
                    # Set inet_interfaces to localhost
                    if grep -q "^inet_interfaces" "$main_cf"; then
                        sed -i 's/^inet_interfaces.*/inet_interfaces = localhost/' "$main_cf"
                    else
                        echo "inet_interfaces = localhost" >> "$main_cf"
                    fi
                    
                    systemctl restart postfix
                    print_success "Configured Postfix for local-only mode"
                    changes_made=true
                fi
            fi
        fi
    elif command -v sendmail &>/dev/null; then
        print_warning "Sendmail detected - consider using Postfix instead"
        print_info "Sendmail configuration requires manual review"
    else
        print_success "No mail transfer agent detected"
    fi
    
    # CIS 2.1.23 - Network listening services audit
    echo -e "\n${BOLD}═══ CIS 2.1.23 - Listening Network Services Audit ═══${NC}"
    
    print_info "Current listening network services:"
    echo ""
    
    # Show listening services
    if command -v ss &>/dev/null; then
        echo -e "${CYAN}TCP Listening:${NC}"
        ss -tlnp | grep LISTEN | head -20
        echo ""
        echo -e "${CYAN}UDP Listening:${NC}"
        ss -ulnp | head -20
    elif command -v netstat &>/dev/null; then
        echo -e "${CYAN}TCP Listening:${NC}"
        netstat -tlnp | grep LISTEN | head -20
        echo ""
        echo -e "${CYAN}UDP Listening:${NC}"
        netstat -ulnp | head -20
    else
        print_error "Neither ss nor netstat available for service audit"
    fi
    
    echo ""
    print_warning "Manual Review Required:"
    print_info "1. Verify all listening services are authorized"
    print_info "2. Common authorized services: SSH (22), Apache (80/443), MySQL (3306)"
    print_info "3. Investigate any unexpected listening services"
    print_info "4. Use 'systemctl list-units --type=service --state=running' for service list"
    
    # Show some key services
    echo -e "\n${BOLD}Key Service Status:${NC}"
    for service in sshd ssh apache2 httpd mysql mariadb ufw; do
        if systemctl is-active "$service" &>/dev/null; then
            echo -e "  ${GREEN}✓${NC} $service is active"
        fi
    done
    
    # Summary
    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════${NC}"
    if [[ "$changes_made" == true ]]; then
        print_success "Mail transfer agent configured per CIS 2.1.22"
    fi
    print_info "CIS 2.1.23: Manual review of listening services required"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    
    press_enter
}

#############################################
# Task 11: CIS 2.2 - Remove Insecure Client Services
#############################################

task_11() {
    print_header "CIS 2.2 - REMOVE INSECURE CLIENT SERVICES"
    print_info "Removing insecure client packages per CIS benchmark"
    echo ""
    
    local changes_made=false
    
    # Insecure client packages that should be removed
    local insecure_clients=(
        "nis:CIS 2.2.1:NIS Client"
        "rsh-client:CIS 2.2.2:RSH Client"
        "talk:CIS 2.2.3:Talk Client"
        "telnet:CIS 2.2.4:Telnet Client"
        "ldap-utils:CIS 2.2.5:LDAP Client"
        "ftp:CIS 2.2.6:FTP Client"
    )
    
    if ! confirm_action "Remove insecure client packages per CIS 2.2?"; then
        print_info "Skipping client package removal"
        press_enter
        return
    fi
    
    echo -e "${BOLD}═══ Removing Insecure Client Packages ═══${NC}"
    echo ""
    
    for client_entry in "${insecure_clients[@]}"; do
        IFS=':' read -r package cis_ref description <<< "$client_entry"
        
        echo -e "${CYAN}[$cis_ref]${NC} Checking $description ($package)..."
        
        if dpkg -l | grep -q "^ii.*$package"; then
            print_warning "$package is installed"
            apt purge -y "$package" 2>/dev/null
            print_success "Removed $package"
            changes_made=true
        else
            print_success "$package not installed"
        fi
    done
    
    # Additional insecure packages
    echo -e "\n${BOLD}═══ Additional Insecure Packages ═══${NC}"
    
    local additional_packages=("rsh-redone-client" "telnetd" "tftp" "talk-server")
    
    for pkg in "${additional_packages[@]}"; do
        if dpkg -l | grep -q "^ii.*$pkg"; then
            print_warning "$pkg is installed"
            apt purge -y "$pkg" 2>/dev/null
            print_success "Removed $pkg"
            changes_made=true
        fi
    done
    
    # Summary
    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════${NC}"
    if [[ "$changes_made" == true ]]; then
        print_success "Insecure client packages removed per CIS 2.2"
        print_info "Use secure alternatives: ssh instead of telnet/rsh, sftp instead of ftp"
    else
        print_success "No insecure client packages found"
    fi
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    
    press_enter
}

#############################################
# Task 12: CIS 2.3 - Configure Time Synchronization
#############################################

task_12() {
    print_header "CIS 2.3 - CONFIGURE TIME SYNCHRONIZATION"
    print_info "Ensuring time synchronization is properly configured"
    echo ""
    
    local changes_made=false
    
    if ! confirm_action "Configure time synchronization per CIS 2.3?"; then
        print_info "Skipping time synchronization configuration"
        press_enter
        return
    fi
    
    # CIS 2.3.1.1 - Ensure single time sync daemon
    echo -e "${BOLD}═══ CIS 2.3.1.1 - Time Synchronization Daemon ═══${NC}"
    
    local time_daemons=("ntp" "chrony" "systemd-timesyncd")
    local active_daemons=()
    
    # Check which time daemons are active
    for daemon in "${time_daemons[@]}"; do
        if systemctl is-active "$daemon" &>/dev/null; then
            active_daemons+=("$daemon")
        fi
    done
    
    if [[ ${#active_daemons[@]} -eq 0 ]]; then
        print_warning "No time synchronization daemon is active"
        print_info "Installing and configuring systemd-timesyncd (CIS recommended)"
        
        # Enable systemd-timesyncd
        systemctl enable systemd-timesyncd
        systemctl start systemd-timesyncd
        print_success "Enabled systemd-timesyncd"
        changes_made=true
        
    elif [[ ${#active_daemons[@]} -gt 1 ]]; then
        print_warning "Multiple time sync daemons active: ${active_daemons[*]}"
        print_info "CIS requires only ONE time sync daemon"
        
        # Keep systemd-timesyncd, disable others
        if confirm_action "Disable all except systemd-timesyncd?"; then
            for daemon in "${active_daemons[@]}"; do
                if [[ "$daemon" != "systemd-timesyncd" ]]; then
                    systemctl stop "$daemon"
                    systemctl disable "$daemon"
                    systemctl mask "$daemon"
                    print_success "Disabled $daemon"
                    changes_made=true
                fi
            done
            
            systemctl enable systemd-timesyncd
            systemctl start systemd-timesyncd
            print_success "Enabled systemd-timesyncd"
        fi
    else
        print_success "Single time sync daemon active: ${active_daemons[0]}"
    fi
    
    # CIS 2.3.2.1 - Configure systemd-timesyncd with authorized timeserver
    echo -e "\n${BOLD}═══ CIS 2.3.2.1 - Configure Timeserver ═══${NC}"
    
    local timesyncd_conf="/etc/systemd/timesyncd.conf"
    if systemctl is-active systemd-timesyncd &>/dev/null; then
        if [[ -f "$timesyncd_conf" ]]; then
            # Check if NTP servers are configured
            if grep -q "^NTP=" "$timesyncd_conf"; then
                print_success "NTP servers already configured"
                grep "^NTP=" "$timesyncd_conf"
            else
                print_warning "NTP servers not explicitly configured"
                if confirm_action "Configure NTP servers (ubuntu.pool.ntp.org)?"; then
                    cp "$timesyncd_conf" "${timesyncd_conf}.bak.$(date +%Y%m%d_%H%M%S)"
                    
                    # Add NTP configuration
                    cat >> "$timesyncd_conf" << 'EOF'

[Time]
NTP=0.ubuntu.pool.ntp.org 1.ubuntu.pool.ntp.org 2.ubuntu.pool.ntp.org 3.ubuntu.pool.ntp.org
FallbackNTP=ntp.ubuntu.com
EOF
                    systemctl restart systemd-timesyncd
                    print_success "Configured NTP servers"
                    changes_made=true
                fi
            fi
        fi
        
        # CIS 2.3.2.2 - Verify systemd-timesyncd is enabled and running
        echo -e "\n${BOLD}═══ CIS 2.3.2.2 - Verify Time Sync Status ═══${NC}"
        
        if systemctl is-enabled systemd-timesyncd &>/dev/null; then
            print_success "systemd-timesyncd is enabled"
        else
            systemctl enable systemd-timesyncd
            print_success "Enabled systemd-timesyncd"
            changes_made=true
        fi
        
        if systemctl is-active systemd-timesyncd &>/dev/null; then
            print_success "systemd-timesyncd is active"
        else
            systemctl start systemd-timesyncd
            print_success "Started systemd-timesyncd"
            changes_made=true
        fi
        
        # Show status
        echo -e "\n${CYAN}Time Synchronization Status:${NC}"
        timedatectl status 2>/dev/null | grep -E "(synchronized|NTP service|Time zone)"
    fi
    
    # Summary
    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════${NC}"
    if [[ "$changes_made" == true ]]; then
        print_success "Time synchronization configured per CIS 2.3"
        print_info "Verify with: timedatectl status"
    else
        print_success "Time synchronization already configured properly"
    fi
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    
    press_enter
}

#############################################
# Task 13: CIS 2.4.1 - Configure Cron
#############################################

task_13() {
    print_header "CIS 2.4.1 - CONFIGURE CRON"
    print_info "Securing cron daemon and directories per CIS benchmark"
    echo ""
    
    local changes_made=false
    
    if ! confirm_action "Configure cron security per CIS 2.4.1?"; then
        print_info "Skipping cron configuration"
        press_enter
        return
    fi
    
    # CIS 2.4.1.1 - Ensure cron daemon is enabled and active
    echo -e "${BOLD}═══ CIS 2.4.1.1 - Cron Daemon Status ═══${NC}"
    
    if ! systemctl is-enabled cron &>/dev/null; then
        print_warning "Cron daemon not enabled"
        systemctl enable cron
        print_success "Enabled cron daemon"
        changes_made=true
    else
        print_success "Cron daemon is enabled"
    fi
    
    if ! systemctl is-active cron &>/dev/null; then
        print_warning "Cron daemon not active"
        systemctl start cron
        print_success "Started cron daemon"
        changes_made=true
    else
        print_success "Cron daemon is active"
    fi
    
    # CIS 2.4.1.2-8 - Set permissions on cron files and directories
    echo -e "\n${BOLD}═══ CIS 2.4.1.2-8 - Cron File Permissions ═══${NC}"
    
    local cron_paths=(
        "/etc/crontab:600:root:root:CIS 2.4.1.2"
        "/etc/cron.hourly:700:root:root:CIS 2.4.1.3"
        "/etc/cron.daily:700:root:root:CIS 2.4.1.4"
        "/etc/cron.weekly:700:root:root:CIS 2.4.1.5"
        "/etc/cron.monthly:700:root:root:CIS 2.4.1.6"
        "/etc/cron.yearly:700:root:root:CIS 2.4.1.7"
        "/etc/cron.d:700:root:root:CIS 2.4.1.8"
    )
    
    for path_entry in "${cron_paths[@]}"; do
        IFS=':' read -r path perms owner group cis_ref <<< "$path_entry"
        
        if [[ -e "$path" ]]; then
            echo -e "\n${CYAN}[$cis_ref]${NC} $path"
            
            local current_perms=$(stat -c "%a" "$path")
            local current_owner=$(stat -c "%U" "$path")
            local current_group=$(stat -c "%G" "$path")
            
            local needs_fix=false
            
            if [[ "$current_perms" != "$perms" ]]; then
                print_warning "Permissions: $current_perms (should be $perms)"
                needs_fix=true
            fi
            
            if [[ "$current_owner" != "$owner" ]] || [[ "$current_group" != "$group" ]]; then
                print_warning "Ownership: $current_owner:$current_group (should be $owner:$group)"
                needs_fix=true
            fi
            
            if [[ "$needs_fix" == true ]]; then
                chmod "$perms" "$path"
                chown "$owner:$group" "$path"
                print_success "Fixed: $path ($perms $owner:$group)"
                changes_made=true
            else
                print_success "Correct: $perms $owner:$group"
            fi
        else
            echo -e "${CYAN}[$cis_ref]${NC} $path - Not found"
        fi
    done
    
    # CIS 2.4.1.9 - Restrict crontab access
    echo -e "\n${BOLD}═══ CIS 2.4.1.9 - Restrict Crontab Access ═══${NC}"
    
    # Create /etc/cron.allow if it doesn't exist
    if [[ ! -f "/etc/cron.allow" ]]; then
        touch /etc/cron.allow
        chmod 600 /etc/cron.allow
        chown root:root /etc/cron.allow
        print_success "Created /etc/cron.allow"
        changes_made=true
    else
        chmod 600 /etc/cron.allow
        chown root:root /etc/cron.allow
        print_success "Set permissions on /etc/cron.allow (600 root:root)"
    fi
    
    # Remove /etc/cron.deny if it exists
    if [[ -f "/etc/cron.deny" ]]; then
        print_warning "/etc/cron.deny exists (CIS recommends using cron.allow instead)"
        if confirm_action "Remove /etc/cron.deny?"; then
            rm /etc/cron.deny
            print_success "Removed /etc/cron.deny"
            changes_made=true
        fi
    fi
    
    print_info "Only users listed in /etc/cron.allow can use cron"
    print_info "Add authorized users: echo 'username' >> /etc/cron.allow"
    
    # Summary
    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════${NC}"
    if [[ "$changes_made" == true ]]; then
        print_success "Cron configured per CIS 2.4.1"
        print_info "Cron daemon: $(systemctl is-active cron)"
        print_info "Access control: /etc/cron.allow (restrictive)"
    else
        print_success "Cron already configured properly"
    fi
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    
    press_enter
}

#############################################
# Task 14: CIS 2.4.2 - Configure At
#############################################

task_14() {
    print_header "CIS 2.4.2 - CONFIGURE AT"
    print_info "Securing at daemon access per CIS benchmark"
    echo ""
    
    local changes_made=false
    
    if ! confirm_action "Configure at daemon access per CIS 2.4.2?"; then
        print_info "Skipping at configuration"
        press_enter
        return
    fi
    
    # Check if at is installed
    echo -e "${BOLD}═══ CIS 2.4.2.1 - At Daemon Access Control ═══${NC}"
    
    if ! dpkg -l | grep -q "^ii.*at"; then
        print_success "at package not installed"
        print_info "No configuration needed"
    else
        print_info "at package is installed"
        
        # Create /etc/at.allow if it doesn't exist
        if [[ ! -f "/etc/at.allow" ]]; then
            touch /etc/at.allow
            chmod 600 /etc/at.allow
            chown root:root /etc/at.allow
            print_success "Created /etc/at.allow"
            changes_made=true
        else
            chmod 600 /etc/at.allow
            chown root:root /etc/at.allow
            print_success "Set permissions on /etc/at.allow (600 root:root)"
        fi
        
        # Remove /etc/at.deny if it exists
        if [[ -f "/etc/at.deny" ]]; then
            print_warning "/etc/at.deny exists (CIS recommends using at.allow instead)"
            if confirm_action "Remove /etc/at.deny?"; then
                rm /etc/at.deny
                print_success "Removed /etc/at.deny"
                changes_made=true
            fi
        fi
        
        # Check at service status
        if systemctl is-active atd &>/dev/null; then
            print_info "at daemon is active"
        else
            print_info "at daemon is not active"
        fi
        
        print_info "Only users listed in /etc/at.allow can use at"
        print_info "Add authorized users: echo 'username' >> /etc/at.allow"
    fi
    
    # Summary
    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════${NC}"
    if [[ "$changes_made" == true ]]; then
        print_success "At daemon configured per CIS 2.4.2"
        print_info "Access control: /etc/at.allow (restrictive)"
    else
        print_success "At daemon already configured properly"
    fi
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    
    press_enter
}

#############################################
# Task 15: Placeholder Module 15
#############################################

task_15() {
    print_header "TASK 15 PLACEHOLDER"
    print_info "Implementation pending"
    echo ""
    
    # TODO: Implement task 15
    print_warning "This module is not yet implemented"
    
    press_enter
}

#############################################
# Task 16: Placeholder Module 16
#############################################

task_16() {
    print_header "TASK 16 PLACEHOLDER"
    print_info "Implementation pending"
    echo ""
    
    # TODO: Implement task 16
    print_warning "This module is not yet implemented"
    
    press_enter
}

#############################################
# Task 17: Placeholder Module 17
#############################################

task_17() {
    print_header "TASK 17 PLACEHOLDER"
    print_info "Implementation pending"
    echo ""
    
    # TODO: Implement task 17
    print_warning "This module is not yet implemented"
    
    press_enter
}

#############################################
# Task 18: Placeholder Module 18
#############################################

task_18() {
    print_header "TASK 18 PLACEHOLDER"
    print_info "Implementation pending"
    echo ""
    
    # TODO: Implement task 18
    print_warning "This module is not yet implemented"
    
    press_enter
}

#############################################
# Task 19: Placeholder Module 19
#############################################

task_19() {
    print_header "TASK 19 PLACEHOLDER"
    print_info "Implementation pending"
    echo ""
    
    # TODO: Implement task 19
    print_warning "This module is not yet implemented"
    
    press_enter
}

#############################################
# Task 20: Placeholder Module 20
#############################################

task_20() {
    print_header "TASK 20 PLACEHOLDER"
    print_info "Implementation pending"
    echo ""
    
    # TODO: Implement task 20
    print_warning "This module is not yet implemented"
    
    press_enter
}

#############################################
# Main Menu
#############################################

show_menu() {
    clear
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}       CIS BENCHMARK SECURITY HARDENING TOOL${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${GREEN}=== SECTION 1: CIS INITIAL SETUP ===${NC}"
    echo -e "${GREEN} 1)${NC} CIS 1.1.1 - Disable Unused Filesystems"
    echo -e "${GREEN} 2)${NC} CIS 1.1.2 - Configure Filesystem Partitions"
    echo -e "${GREEN} 3)${NC} CIS 1.2 - Package Management"
    echo -e "${GREEN} 4)${NC} CIS 1.3 - Mandatory Access Control (AppArmor)"
    echo -e "${GREEN} 5)${NC} CIS 1.4 - Bootloader Configuration"
    echo ""
    echo -e "${CYAN}=== SECTION 2: SERVICES CONFIGURATION ===${NC}"
    echo -e "${GREEN} 6)${NC} CIS 1.5 - Additional Process Hardening"
    echo -e "${GREEN} 7)${NC} CIS 1.6 - Command Line Warning Banners"
    echo -e "${GREEN} 8)${NC} CIS 1.7 - Cinnamon Desktop Environment"
    echo -e "${GREEN} 9)${NC} CIS 2.1 - Disable Unnecessary Server Services"
    echo -e "${GREEN}10)${NC} CIS 2.1.22-23 - Mail & Network Service Audit"
    echo ""
    echo -e "${YELLOW}=== SECTION 3: CLIENT & TIME SERVICES ===${NC}"
    echo -e "${GREEN}11)${NC} CIS 2.2 - Remove Insecure Client Services"
    echo -e "${GREEN}12)${NC} CIS 2.3 - Configure Time Synchronization"
    echo -e "${GREEN}13)${NC} CIS 2.4.1 - Configure Cron"
    echo -e "${GREEN}14)${NC} CIS 2.4.2 - Configure At"
    echo -e "${GREEN}15)${NC} Task 15 - Placeholder"
    echo ""
    echo -e "${MAGENTA}=== SECTION 4: PLACEHOLDER TASKS ===${NC}"
    echo -e "${GREEN}16)${NC} Task 16 - Placeholder"
    echo -e "${GREEN}17)${NC} Task 17 - Placeholder"
    echo -e "${GREEN}18)${NC} Task 18 - Placeholder"
    echo -e "${GREEN}19)${NC} Task 19 - Placeholder"
    echo -e "${GREEN}20)${NC} Task 20 - Placeholder"
    echo ""
    echo -e "${RED} 0)${NC} Exit"
    echo ""
    echo -e -n "${CYAN}Select an option: ${NC}"
}

#############################################
# Main Program Loop
#############################################

main() {
    check_root
    show_splash
    
    while true; do
        show_menu
        read -r choice
        
        case $choice in
            1) task_1 ;;
            2) task_2 ;;
            3) task_3 ;;
            4) task_4 ;;
            5) task_5 ;;
            6) task_6 ;;
            7) task_7 ;;
            8) task_8 ;;
            9) task_9 ;;
            10) task_10 ;;
            11) task_11 ;;
            12) task_12 ;;
            13) task_13 ;;
            14) task_14 ;;
            15) task_15 ;;
            16) task_16 ;;
            17) task_17 ;;
            18) task_18 ;;
            19) task_19 ;;
            20) task_20 ;;
            0)
                print_header "EXITING"
                print_info "Security audit log saved to: $LOG_FILE"
                echo -e "${GREEN}Thank you for using CIS Benchmark Tool!${NC}"
                exit 0
                ;;
            *)
                print_error "Invalid option. Please try again."
                sleep 2
                ;;
        esac
    done
}

# Run the main program
main
