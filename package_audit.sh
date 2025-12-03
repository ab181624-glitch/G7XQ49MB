#!/bin/bash

#############################################################################
# Package Audit Script
# Compares installed packages against a whitelist and prompts for actions
#############################################################################

# Configuration
GITHUB_RAW_URL="https://github.com/ab181624-glitch/G7XQ49MB/raw/refs/heads/main/package_whitelist.txt"
WORK_DIR="${HOME}/.package_audit"
WHITELIST_FILE="${WORK_DIR}/package_whitelist.txt"
NEW_PACKAGES_FILE="${WORK_DIR}/new_whitelist_additions.txt"
AUDIT_LOG="${WORK_DIR}/package_audit.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

#############################################################################
# Functions
#############################################################################

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$AUDIT_LOG"
}

print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

# Detect package manager
detect_package_manager() {
    if command -v dpkg &> /dev/null; then
        echo "dpkg"
    elif command -v rpm &> /dev/null; then
        echo "rpm"
    elif command -v pacman &> /dev/null; then
        echo "pacman"
    else
        echo "unknown"
    fi
}

# Get list of installed packages
get_installed_packages() {
    local pm="$1"
    case "$pm" in
        dpkg)
            dpkg-query -W -f='${Package}\n' | sort
            ;;
        rpm)
            rpm -qa --qf '%{NAME}\n' | sort
            ;;
        pacman)
            pacman -Qq | sort
            ;;
        *)
            echo "ERROR: Unsupported package manager" >&2
            exit 1
            ;;
    esac
}

# Get package description
get_package_description() {
    local package="$1"
    local pm="$2"
    
    case "$pm" in
        dpkg)
            apt-cache show "$package" 2>/dev/null | grep -E "^Description:" | head -n 1 | sed 's/Description: //' || echo "No description available"
            ;;
        rpm)
            rpm -qi "$package" 2>/dev/null | grep -E "^Summary" | sed 's/Summary *: //' || echo "No description available"
            ;;
        pacman)
            pacman -Qi "$package" 2>/dev/null | grep -E "^Description" | sed 's/Description *: //' || echo "No description available"
            ;;
        *)
            echo "No description available"
            ;;
    esac
}

# Download whitelist from GitHub
download_whitelist() {
    local temp_file="${WHITELIST_FILE}.tmp"
    echo -e "${YELLOW}Downloading whitelist from GitHub...${NC}"
    
    if wget -q -O "$temp_file" "$GITHUB_RAW_URL" 2>/dev/null; then
        mv "$temp_file" "$WHITELIST_FILE"
        echo -e "${GREEN}✓ Whitelist downloaded successfully${NC}"
        log_message "Whitelist downloaded from $GITHUB_RAW_URL"
        return 0
    else
        rm -f "$temp_file"
        if [ -f "$WHITELIST_FILE" ]; then
            echo -e "${YELLOW}⚠ Download failed, using cached whitelist${NC}"
            log_message "Failed to download whitelist, using cached version"
            return 1
        else
            echo -e "${RED}✗ Failed to download whitelist and no cache available${NC}"
            echo -e "${YELLOW}Creating new whitelist file...${NC}"
            touch "$WHITELIST_FILE"
            log_message "Failed to download whitelist, created empty file"
            return 1
        fi
    fi
}

# Remove package
remove_package() {
    local package="$1"
    local pm="$2"
    
    echo -e "${YELLOW}Removing package: $package${NC}"
    
    case "$pm" in
        dpkg)
            sudo apt-get remove -y "$package" || sudo dpkg --remove "$package"
            ;;
        rpm)
            sudo yum remove -y "$package" || sudo dnf remove -y "$package" || sudo rpm -e "$package"
            ;;
        pacman)
            sudo pacman -R --noconfirm "$package"
            ;;
    esac
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Package removed successfully${NC}"
        log_message "Removed package: $package"
    else
        echo -e "${RED}✗ Failed to remove package${NC}"
        log_message "Failed to remove package: $package"
    fi
}

# Process a single package
process_package() {
    local package="$1"
    local pm="$2"
    
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${RED}Package NOT in whitelist: ${BLUE}$package${NC}"
    
    # Get and display package description
    local description=$(get_package_description "$package" "$pm")
    echo -e "${GREEN}Description:${NC} $description"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Prompt user for action
    while true; do
        echo ""
        echo "What would you like to do?"
        echo "  1) Add to whitelist (permanent)"
        echo "  2) Allow but don't add to whitelist (temporary)"
        echo "  3) Remove this package"
        echo -n "Enter choice [1-3]: "
        read -r choice
        
        case "$choice" in
            1)
                echo "$package" >> "$NEW_PACKAGES_FILE"
                echo -e "${GREEN}✓ Added to whitelist${NC}"
                log_message "Added to whitelist: $package"
                break
                ;;
            2)
                echo -e "${GREEN}✓ Allowed (temporary)${NC}"
                log_message "Allowed temporarily: $package"
                break
                ;;
            3)
                remove_package "$package" "$pm"
                break
                ;;
            *)
                echo -e "${RED}Invalid choice. Please enter 1, 2, or 3.${NC}"
                ;;
        esac
    done
}

# Generate instructions for updating GitHub
generate_sync_instructions() {
    if [ ! -s "$NEW_PACKAGES_FILE" ]; then
        return
    fi
    
    echo ""
    print_header "WHITELIST UPDATE REQUIRED"
    
    echo -e "${YELLOW}New packages were added to the whitelist:${NC}"
    cat "$NEW_PACKAGES_FILE"
    
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}To update the GitHub repository:${NC}"
    echo ""
    echo -e "${BLUE}Option 1: Manual Update${NC}"
    echo "  1. Copy the new packages listed above"
    echo "  2. Add them to your package_whitelist.txt file in the repo"
    echo "  3. Commit and push the changes"
    echo ""
    echo -e "${BLUE}Option 2: Using GitHub API (requires token)${NC}"
    echo "  Run this command on a machine with GitHub access:"
    echo -e "  ${YELLOW}cat $NEW_PACKAGES_FILE | while read pkg; do echo \"\$pkg\" >> package_whitelist.txt; done${NC}"
    echo -e "  ${YELLOW}git add package_whitelist.txt && git commit -m 'Update whitelist' && git push${NC}"
    echo ""
    echo -e "${BLUE}Option 3: Email/Slack the additions${NC}"
    echo -e "  Copy the file: ${YELLOW}$NEW_PACKAGES_FILE${NC}"
    echo "  Send it to your admin to update the repository"
    echo ""
    
    # Create a ready-to-paste file
    local update_file="${WORK_DIR}/whitelist_update_$(date +%s).txt"
    cat "$NEW_PACKAGES_FILE" > "$update_file"
    echo -e "${GREEN}✓ Update file saved to: ${YELLOW}$update_file${NC}"
    
    log_message "Generated whitelist update file: $update_file"
}

#############################################################################
# Main Script
#############################################################################

main() {
    print_header "Package Audit Script"
    
    # Create work directory if it doesn't exist
    mkdir -p "$WORK_DIR"
    
    # Initialize log
    echo "=== Package Audit Started ===" > "$AUDIT_LOG"
    log_message "Script started"
    
    # Detect package manager
    echo -e "${YELLOW}Detecting package manager...${NC}"
    PM=$(detect_package_manager)
    echo -e "${GREEN}✓ Detected: $PM${NC}"
    log_message "Package manager: $PM"
    
    if [ "$PM" = "unknown" ]; then
        echo -e "${RED}ERROR: Could not detect package manager${NC}"
        exit 1
    fi
    
    # Download whitelist
    download_whitelist
    
    # Initialize new packages file
    > "$NEW_PACKAGES_FILE"
    
    # Get installed packages
    echo -e "${YELLOW}Getting installed packages...${NC}"
    mapfile -t INSTALLED < <(get_installed_packages "$PM")
    echo -e "${GREEN}✓ Found ${#INSTALLED[@]} installed packages${NC}"
    log_message "Total installed packages: ${#INSTALLED[@]}"
    
    # Load whitelist into associative array for O(1) lookup
    # Also track wildcard patterns (entries ending with *)
    declare -A WHITELIST_MAP
    declare -a WHITELIST_PATTERNS
    if [ -s "$WHITELIST_FILE" ]; then
        local count=0
        while IFS= read -r package; do
            # Skip empty lines and comments
            [[ -z "$package" || "$package" =~ ^[[:space:]]*# ]] && continue
            
            # Check if it's a wildcard pattern (ends with *)
            if [[ "$package" == *\* ]]; then
                WHITELIST_PATTERNS+=("$package")
            else
                WHITELIST_MAP["$package"]=1
            fi
            ((count++))
        done < "$WHITELIST_FILE"
        echo -e "${GREEN}✓ Loaded $count whitelisted packages/patterns${NC}"
        log_message "Whitelisted packages: $count (${#WHITELIST_PATTERNS[@]} patterns)"
    else
        echo -e "${YELLOW}⚠ Whitelist is empty${NC}"
        log_message "Whitelist is empty"
    fi
    
    # Find packages not in whitelist - O(n) time complexity
    print_header "Scanning for Non-Whitelisted Packages"
    
    NOT_WHITELISTED=()
    for package in "${INSTALLED[@]}"; do
        # First check exact match (O(1))
        if [[ -v WHITELIST_MAP["$package"] ]]; then
            continue
        fi
        
        # Then check wildcard patterns
        local matched=0
        for pattern in "${WHITELIST_PATTERNS[@]}"; do
            # Remove the trailing * and check if package starts with pattern
            local prefix="${pattern%\*}"
            if [[ "$package" == "$prefix"* ]]; then
                matched=1
                break
            fi
        done
        
        if [[ $matched -eq 0 ]]; then
            NOT_WHITELISTED+=("$package")
        fi
    done
    
    if [ ${#NOT_WHITELISTED[@]} -eq 0 ]; then
        echo -e "${GREEN}✓ All packages are whitelisted!${NC}"
        log_message "All packages whitelisted - no action needed"
        exit 0
    fi
    
    echo -e "${YELLOW}Found ${#NOT_WHITELISTED[@]} packages not in whitelist${NC}"
    log_message "Non-whitelisted packages found: ${#NOT_WHITELISTED[@]}"
    
    # Process each non-whitelisted package
    for package in "${NOT_WHITELISTED[@]}"; do
        process_package "$package" "$PM"
    done
    
    # Generate sync instructions
    generate_sync_instructions
    
    print_header "Audit Complete"
    echo -e "${GREEN}✓ Package audit finished${NC}"
    echo -e "${BLUE}Log file: $AUDIT_LOG${NC}"
    log_message "Script completed"
}

# Run main function
main

exit 0
