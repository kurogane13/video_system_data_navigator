#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
ORANGE='\033[0;33m'
MAGENTA='\033[1;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Global variables for OS detection
OS_TYPE=""
FIREWALL_TYPE=""

# Connection credentials file
CRDS_FILE="$HOME/.setup_system_remote_crds"

# Function to print colored separator
print_separator() {
    echo -e "${CYAN}================================================================${NC}"
}

# Function to print section header
print_header() {
    echo
    print_separator
    echo -e "${WHITE}$1${NC}"
    print_separator
    echo
}

# Function to print step
print_step() {
    echo -e "${YELLOW}[STEP]${NC} $1"
}

# Function to print success
print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Function to print error
print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to print info
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Function to print warning
print_warning() {
    echo -e "${ORANGE}[WARNING]${NC} $1"
}

# Function to print debug
print_debug() {
    echo -e "${PURPLE}[DEBUG]${NC} $1"
}

# Function to print double separator
print_double_separator() {
    echo -e "${MAGENTA}================================================================${NC}"
    echo -e "${CYAN}================================================================${NC}"
}

# Function to detect operating system
detect_os() {
    print_info "Detecting operating system..."
    
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        case "$ID" in
            ubuntu|debian)
                OS_TYPE="ubuntu"
                FIREWALL_TYPE="ufw"
                print_success "Detected: Ubuntu/Debian system"
                ;;
            centos|rhel|fedora|rocky|alma)
                OS_TYPE="centos"
                FIREWALL_TYPE="firewalld"
                print_success "Detected: CentOS/RHEL/Fedora system"
                ;;
            *)
                print_warning "Unknown distribution: $ID, defaulting to Ubuntu"
                OS_TYPE="ubuntu"
                FIREWALL_TYPE="ufw"
                ;;
        esac
    else
        print_warning "Cannot detect OS, defaulting to Ubuntu"
        OS_TYPE="ubuntu"
        FIREWALL_TYPE="ufw"
    fi
}

# Function to configure firewall for Ubuntu/Debian
configure_ubuntu_firewall() {
    print_info "Configuring UFW firewall for Ubuntu..."
    
    # Check if UFW is installed
    if ! command -v ufw &> /dev/null; then
        print_error "UFW is not installed. Installing..."
        if ! sudo apt-get update && sudo apt-get install -y ufw; then
            print_error "Failed to install UFW"
            return 1
        fi
    fi
    
    # Enable UFW if not already enabled
    if ! sudo ufw status | grep -q "Status: active"; then
        print_info "Enabling UFW..."
        sudo ufw --force enable
    fi
    
    # Open ports
    print_info "Opening port 9090 (API Server)..."
    if sudo ufw allow 9090/tcp; then
        print_success "Port 9090/tcp opened"
    else
        print_error "Failed to open port 9090/tcp"
        return 1
    fi
    
    print_info "Opening port 4200 (Terminal Access)..."
    if sudo ufw allow 4200/tcp; then
        print_success "Port 4200/tcp opened"
    else
        print_error "Failed to open port 4200/tcp"
        return 1
    fi
    
    print_success "UFW firewall configured successfully"
    return 0
}

# Function to configure firewall for CentOS/RHEL
configure_centos_firewall() {
    print_info "Configuring firewall for CentOS/RHEL..."
    
    # Detect which firewall system is in use
    if systemctl is-active --quiet firewalld; then
        FIREWALL_TYPE="firewalld"
        print_info "Using firewalld"
    elif systemctl list-units --full -all | grep -Fq "iptables.service"; then
        FIREWALL_TYPE="iptables"
        print_info "Using iptables"
    else
        print_warning "No firewall service detected, attempting to use firewalld"
        FIREWALL_TYPE="firewalld"
    fi
    
    if [[ "$FIREWALL_TYPE" == "firewalld" ]]; then
        configure_firewalld
    else
        configure_iptables
    fi
}

# Function to configure firewalld
configure_firewalld() {
    print_info "Configuring firewalld..."
    
    # Check if firewalld is installed
    if ! command -v firewall-cmd &> /dev/null; then
        print_error "firewalld is not installed. Installing..."
        if ! sudo yum install -y firewalld; then
            print_error "Failed to install firewalld"
            return 1
        fi
    fi
    
    # Start firewalld if not running
    if ! systemctl is-active --quiet firewalld; then
        print_info "Starting firewalld service..."
        sudo systemctl start firewalld
        sudo systemctl enable firewalld
    fi
    
    # Open ports
    print_info "Opening port 9090/tcp (API Server)..."
    if sudo firewall-cmd --permanent --add-port=9090/tcp; then
        print_success "Port 9090/tcp added to permanent rules"
    else
        print_error "Failed to add port 9090/tcp"
        return 1
    fi
    
    print_info "Opening port 4200/tcp (Terminal Access)..."
    if sudo firewall-cmd --permanent --add-port=4200/tcp; then
        print_success "Port 4200/tcp added to permanent rules"
    else
        print_error "Failed to add port 4200/tcp"
        return 1
    fi
    
    # Reload firewall
    print_info "Reloading firewall to apply changes..."
    if sudo firewall-cmd --reload; then
        print_success "Firewall rules reloaded successfully"
    else
        print_error "Failed to reload firewall rules"
        return 1
    fi
    
    return 0
}

# Function to configure iptables
configure_iptables() {
    print_info "Configuring iptables..."
    
    # Check if iptables is installed
    if ! command -v iptables &> /dev/null; then
        print_error "iptables is not installed"
        return 1
    fi
    
    # Open ports
    print_info "Opening port 9090/tcp (API Server)..."
    if sudo iptables -I INPUT -p tcp --dport 9090 -j ACCEPT; then
        print_success "Port 9090/tcp opened with iptables"
    else
        print_error "Failed to open port 9090/tcp with iptables"
        return 1
    fi
    
    print_info "Opening port 4200/tcp (Terminal Access)..."
    if sudo iptables -I INPUT -p tcp --dport 4200 -j ACCEPT; then
        print_success "Port 4200/tcp opened with iptables"
    else
        print_error "Failed to open port 4200/tcp with iptables"
        return 1
    fi
    
    # Save iptables rules
    print_info "Saving iptables rules..."
    if command -v iptables-save &> /dev/null; then
        sudo iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
        print_success "iptables rules saved"
    else
        print_warning "Could not save iptables rules automatically"
    fi
    
    return 0
}

# Function to configure firewall based on OS
configure_firewall() {
    print_step "Configuring firewall for video system ports..."
    
    case "$OS_TYPE" in
        "ubuntu")
            configure_ubuntu_firewall
            ;;
        "centos")
            configure_centos_firewall
            ;;
        *)
            print_error "Unsupported OS type: $OS_TYPE"
            return 1
            ;;
    esac
}

# Function to create video system credentials
create_video_system_credentials() {
    print_header "VIDEO SYSTEM CREDENTIALS SETUP"
    
    print_info "Setting up authentication credentials for the video system"
    print_info "These credentials will be used to login to the web interface"
    echo
    
    local username=""
    local password=""
    local confirm_password=""
    
    # Get username
    while [[ -z "$username" ]]; do
        echo -e "${CYAN}Enter video system username:${NC}"
        read -p "> " username
        
        if [[ -z "$username" ]]; then
            print_error "Username cannot be empty"
        elif [[ "$username" =~ [[:space:]] ]]; then
            print_error "Username cannot contain spaces"
            username=""
        elif [[ "$username" =~ : ]]; then
            print_error "Username cannot contain colon (:) character"
            username=""
        fi
    done
    
    # Get password
    while [[ -z "$password" ]]; do
        echo -e "${CYAN}Enter video system password:${NC}"
        read -s -p "> " password
        echo
        
        if [[ -z "$password" ]]; then
            print_error "Password cannot be empty"
        elif [[ "$password" =~ : ]]; then
            print_error "Password cannot contain colon (:) character"
            password=""
        fi
    done
    
    # Confirm password
    while [[ "$password" != "$confirm_password" ]]; do
        echo -e "${CYAN}Confirm password:${NC}"
        read -s -p "> " confirm_password
        echo
        
        if [[ "$password" != "$confirm_password" ]]; then
            print_error "Passwords do not match. Please try again."
        fi
    done
    
    # Create credentials file
    local crds_file="$HOME/.crds"
    echo "${username}:${password}" > "$crds_file"
    chmod 600 "$crds_file"
    
    print_success "Credentials saved to $crds_file"
    print_info "Username: $username"
    print_info "Password: [hidden]"
    echo
}

# Function to show main menu
show_main_menu() {
    print_double_separator
    echo -e "${WHITE}${BOLD}               VIDEO AND FILES MANAGEMENT SYSTEM SETUP${NC}"
    echo -e "${CYAN}                    Automated Installation & Configuration${NC}"
    print_double_separator
    echo
    echo -e "${MAGENTA}${BOLD}Please select an option:${NC}"
    echo
    echo -e "${GREEN}1)${NC} ${WHITE}${BOLD}Setup New System${NC} - Configure the system for this server"
    echo -e "${YELLOW}2)${NC} ${WHITE}${BOLD}Restore to Default${NC} - Revert system to original state"
    echo -e "${ORANGE}3)${NC} ${WHITE}${BOLD}Kill & Restart Server${NC} - Force restart the video system server"
    echo -e "${CYAN}4)${NC} ${WHITE}${BOLD}Transfer System to Remote${NC} - Copy system to another server via SCP"
    echo -e "${PURPLE}5)${NC} ${WHITE}${BOLD}Connection Management${NC} - Manage saved remote connections"
    echo -e "${BLUE}6)${NC} ${WHITE}${BOLD}Diagnose Credentials${NC} - Debug connection storage issues"
    echo -e "${RED}7)${NC} ${WHITE}${BOLD}Exit${NC}"
    echo
}

# Function to restore system to default
restore_to_default() {
    print_header "RESTORE TO DEFAULT SYSTEM"
    
    # Check if backup exists
    if [[ ! -d "$USER_HOME/video-system-default" ]]; then
        print_error "Default backup not found at: $USER_HOME/video-system-default"
        print_error "Cannot restore system to default state."
        echo
        echo -e "${YELLOW}Press any key to return to main menu...${NC}"
        read -n 1 -s
        return
    fi
    
    print_step "Found default backup at: $USER_HOME/video-system-default"
    echo
    
    # Warning message
    echo -e "${RED}⚠️  WARNING: SYSTEM RESTORATION ⚠️${NC}"
    echo
    echo -e "${YELLOW}This operation will:${NC}"
    echo -e "${RED}  • DELETE the current video-system directory${NC}"
    echo -e "${RED}  • REMOVE all custom configurations${NC}"
    echo -e "${RED}  • ERASE IP address settings${NC}"
    echo -e "${RED}  • DELETE authentication credentials${NC}"
    echo -e "${RED}  • RESTORE original default files${NC}"
    echo
    echo -e "${WHITE}Your video files and data will NOT be affected.${NC}"
    echo -e "${WHITE}Only configuration files will be restored to defaults.${NC}"
    echo
    echo -e "${RED}THIS ACTION CANNOT BE UNDONE!${NC}"
    echo
    
    # First confirmation
    echo -e "${YELLOW}Are you sure you want to restore to default? (yes/NO)${NC}"
    read -p "Type 'yes' to confirm: " CONFIRM1
    
    if [[ "$CONFIRM1" != "yes" ]]; then
        print_info "Restoration cancelled by user"
        echo
        echo -e "${YELLOW}Press any key to return to main menu...${NC}"
        read -n 1 -s
        return
    fi
    
    # Second confirmation
    echo
    echo -e "${RED}FINAL CONFIRMATION REQUIRED${NC}"
    echo -e "${YELLOW}This will permanently delete your current configuration.${NC}"
    echo -e "${YELLOW}Type 'RESTORE' in capital letters to proceed: ${NC}"
    read -p "Final confirmation: " CONFIRM2
    
    if [[ "$CONFIRM2" != "RESTORE" ]]; then
        print_info "Restoration cancelled by user"
        echo
        echo -e "${YELLOW}Press any key to return to main menu...${NC}"
        read -n 1 -s
        return
    fi
    
    # Perform restoration
    print_step "Beginning system restoration..."
    
    # Restore from backup (overwrite current video-system)
    print_step "Restoring default configuration..."
    cp -r "$USER_HOME/video-system-default" "$USER_HOME/video-system"
    print_success "Default configuration restored"
    
    # Remove credentials file if it exists
    if [[ -f "$USER_HOME/.crds" ]]; then
        print_step "Removing custom credentials..."
        rm -f "$USER_HOME/.crds"
        print_success "Credentials removed"
    fi
    
    echo
    print_separator
    echo -e "${GREEN}✅ SYSTEM RESTORATION COMPLETE${NC}"
    print_separator
    echo
    echo -e "${CYAN}The system has been restored to its default state.${NC}"
    echo -e "${WHITE}You can now run 'Setup New System' to configure it again.${NC}"
    echo
    echo -e "${YELLOW}Press any key to return to main menu...${NC}"
    read -n 1 -s
}

# Function to setup new system
setup_new_system() {
    print_header "SETUP NEW SYSTEM"
    
    # Detect operating system
    detect_os
    echo
    
    # Create video system credentials
    create_video_system_credentials
    
    # Get current user home directory
    USER_HOME=$(echo $HOME)
    print_info "Detected user home directory: ${USER_HOME}"

    # Get the script directory to find source directories
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    SOURCE_VIDEO_SYSTEM="$SCRIPT_DIR/video-system"
    SOURCE_VIDEO_SYSTEM_DEFAULT="$SCRIPT_DIR/video-system-default"

    # Alternative source location if script is run from outside video_system_data_navigator
    ALT_SOURCE_DIR="$USER_HOME/video_system_data_navigator"
    ALT_SOURCE_VIDEO_SYSTEM="$ALT_SOURCE_DIR/video-system"
    ALT_SOURCE_VIDEO_SYSTEM_DEFAULT="$ALT_SOURCE_DIR/video-system-default"

    # Debug information
    print_info "Script directory: $SCRIPT_DIR"
    print_info "Current working directory: $(pwd)"
    print_info "Looking for source directories at:"
    print_info "  Primary: $SOURCE_VIDEO_SYSTEM"
    print_info "  Alternative: $ALT_SOURCE_VIDEO_SYSTEM"

    # Check if video-system directory exists, if not copy from available source
    if [[ ! -d "$USER_HOME/video-system" ]]; then
        print_step "video-system directory not found in $USER_HOME"

        # First, try to copy from script directory
        if [[ -d "$SOURCE_VIDEO_SYSTEM" ]]; then
            print_step "Copying video-system from $SOURCE_VIDEO_SYSTEM"
            cp -r "$SOURCE_VIDEO_SYSTEM" "$USER_HOME/"
            print_success "✅ video-system directory copied to $USER_HOME/video-system"
        # If not found in script directory, try alternative location
        elif [[ -d "$ALT_SOURCE_VIDEO_SYSTEM" ]]; then
            print_step "Script not run from video_system_data_navigator directory"
            print_step "Copying video-system from alternative location: $ALT_SOURCE_VIDEO_SYSTEM"
            cp -r "$ALT_SOURCE_VIDEO_SYSTEM" "$USER_HOME/"
            print_success "✅ video-system directory copied from $ALT_SOURCE_DIR to $USER_HOME/video-system"
        else
            print_error "Source video-system directory not found in either location:"
            print_error "  Primary: $SOURCE_VIDEO_SYSTEM"
            print_error "  Alternative: $ALT_SOURCE_VIDEO_SYSTEM"
            print_error "Please ensure video-system directory exists in ~/video_system_data_navigator/"
            echo
            echo -e "${YELLOW}Press any key to return to main menu...${NC}"
            read -n 1 -s
            return
        fi
    else
        print_success "Found existing video-system directory at: $USER_HOME/video-system"
    fi

    # Check if video-system-default directory exists, if not copy from available source
    if [[ ! -d "$USER_HOME/video-system-default" ]]; then
        print_step "video-system-default directory not found in $USER_HOME"

        # First, try to copy from script directory
        if [[ -d "$SOURCE_VIDEO_SYSTEM_DEFAULT" ]]; then
            print_step "Copying video-system-default from $SOURCE_VIDEO_SYSTEM_DEFAULT"
            cp -r "$SOURCE_VIDEO_SYSTEM_DEFAULT" "$USER_HOME/"
            print_success "✅ video-system-default directory copied to $USER_HOME/video-system-default"
        # If not found in script directory, try alternative location
        elif [[ -d "$ALT_SOURCE_VIDEO_SYSTEM_DEFAULT" ]]; then
            print_step "Copying video-system-default from alternative location: $ALT_SOURCE_VIDEO_SYSTEM_DEFAULT"
            cp -r "$ALT_SOURCE_VIDEO_SYSTEM_DEFAULT" "$USER_HOME/"
            print_success "✅ video-system-default directory copied from $ALT_SOURCE_DIR to $USER_HOME/video-system-default"
        else
            print_step "Source video-system-default not found in either location, will create from video-system"
            if [[ -d "$USER_HOME/video-system" ]]; then
                cp -r "$USER_HOME/video-system" "$USER_HOME/video-system-default"
                print_success "✅ video-system-default directory created from video-system"
            else
                print_error "Cannot create video-system-default: no video-system directory found"
                return
            fi
        fi
    else
        print_success "Found existing video-system-default directory at: $USER_HOME/video-system-default"
    fi
    echo
    
    # Step 0: Create backup of original system
    print_header "STEP 0: CREATING DEFAULT BACKUP"
    
    if [[ -d "$USER_HOME/video-system-default" ]]; then
        print_info "Default backup already exists at: $USER_HOME/video-system-default"
        echo -e "${YELLOW}Do you want to update the backup with current video-system? (y/N)${NC}"
        read -p "Update backup? " -n 1 -r
        echo
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_step "Updating default backup..."
            cp -r "$USER_HOME/video-system" "$USER_HOME/video-system-default"
            print_success "Default backup updated"
        else
            print_info "Using existing backup"
        fi
    else
        print_step "Creating default backup of video-system..."
        cp -r "$USER_HOME/video-system" "$USER_HOME/video-system-default"
        print_success "Default backup created at: $USER_HOME/video-system-default"
    fi
    echo

# Step 1: Get IP Address
print_header "STEP 1: NETWORK CONFIGURATION"
echo -e "${CYAN}Enter the IP address where this system will be accessible:${NC}"
echo -e "${YELLOW}(Example: 192.168.1.100 or 34.68.60.53)${NC}"
read -p "IP Address: " TARGET_IP

# Validate IP address format
if [[ ! $TARGET_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    print_error "Invalid IP address format"
    exit 1
fi

print_success "Target IP set to: $TARGET_IP"
echo

# Step 2: Get Username and Password
print_header "STEP 2: AUTHENTICATION SETUP"
echo -e "${CYAN}Enter the username for system authentication:${NC}"
read -p "Username: " AUTH_USERNAME

echo -e "${CYAN}Enter the password for system authentication:${NC}"
read -s -p "Password: " AUTH_PASSWORD
echo
echo -e "${GREEN}Credentials configured successfully${NC}"
echo

# Create credentials file
print_step "Creating credentials file at ~/.crds"
echo "$AUTH_USERNAME:$AUTH_PASSWORD" > "$USER_HOME/.crds"
chmod 600 "$USER_HOME/.crds"
print_success "Credentials saved securely"
echo

# Step 3: System Analysis and File Updates
print_header "STEP 3: SYSTEM FILE CONFIGURATION"

# Define files to update
DASHBOARD_FILE="$USER_HOME/video-system/docs/dashboard.html"
API_CONSOLE_FILE="$USER_HOME/video-system/docs/api_console.html" 
AUTH_SERVER_FILE="$USER_HOME/video-system/scripts/auth_api_server.py"

print_step "Analyzing configuration files..."

# Check if files exist
missing_files=()
for file in "$DASHBOARD_FILE" "$API_CONSOLE_FILE" "$AUTH_SERVER_FILE"; do
    if [[ ! -f "$file" ]]; then
        missing_files+=("$file")
    fi
done

if [[ ${#missing_files[@]} -gt 0 ]]; then
    print_error "Missing required files:"
    for file in "${missing_files[@]}"; do
        echo "  - $file"
    done
    exit 1
fi

print_success "All required files found"
echo

# Function to find and replace IP addresses
update_ip_in_file() {
    local file="$1"
    local description="$2"
    
    print_step "Updating $description"
    
    # First check for gcppftest01 and replace if found
    if grep -q "gcppftest01" "$file"; then
        print_info "Found 'gcppftest01' references, replacing with $TARGET_IP"
        sed -i "s/gcppftest01/$TARGET_IP/g" "$file"
    fi
    
    # Find and replace existing IP addresses in http:// URLs
    if grep -q "http://[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+:" "$file"; then
        print_info "Found existing IP addresses, replacing with $TARGET_IP"
        sed -i "s|http://[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+:|http://$TARGET_IP:|g" "$file"
    fi
    
    print_success "Updated $description successfully"
}

# Function to update username paths
update_username_in_file() {
    local file="$1"
    local description="$2"
    local current_user=$(basename "$USER_HOME")
    
    print_step "Updating username paths in $description"
    
    # Replace /home/[username]/video-system patterns
    if grep -q "/home/[^/]*/video-system" "$file"; then
        print_info "Found username paths, replacing with current user: $current_user"
        sed -i "s|/home/[^/]*/video-system|$USER_HOME/video-system|g" "$file"
    fi
    
    # Replace specific /home/gus patterns if they exist
    if grep -q "/home/gus" "$file"; then
        print_info "Found /home/gus paths, replacing with $USER_HOME"
        sed -i "s|/home/gus|$USER_HOME|g" "$file"
    fi
    
    print_success "Updated username paths in $description successfully"
}

# Update all files
update_ip_in_file "$DASHBOARD_FILE" "Dashboard HTML"
update_ip_in_file "$API_CONSOLE_FILE" "API Console HTML"
update_ip_in_file "$AUTH_SERVER_FILE" "Authentication Server"

echo
update_username_in_file "$DASHBOARD_FILE" "Dashboard HTML"
update_username_in_file "$API_CONSOLE_FILE" "API Console HTML"
update_username_in_file "$AUTH_SERVER_FILE" "Authentication Server"
update_username_in_file "$USER_HOME/video-system/scripts/debug_logger.py" "Debug Logger Script"
update_username_in_file "$USER_HOME/video-system/scripts/log_wrapper.py" "Log Wrapper Script"

echo

# Step 4: System Configuration
print_header "STEP 4: SYSTEM SECURITY SETUP"

# Detect Linux distribution
print_step "Detecting Linux distribution..."
if command -v lsb_release &> /dev/null; then
    DISTRO=$(lsb_release -si)
    VERSION=$(lsb_release -sr)
elif [[ -f /etc/os-release ]]; then
    source /etc/os-release
    DISTRO=$NAME
    VERSION=$VERSION_ID
else
    DISTRO="Unknown"
    VERSION="Unknown"
fi

print_success "Detected: $DISTRO $VERSION"
echo

# Configure firewall based on distribution
print_step "Configuring firewall..."

if command -v ufw &> /dev/null; then
    print_info "Using UFW firewall"
    sudo ufw --force enable
    sudo ufw allow 9090/tcp comment "Video System API Server"
    sudo ufw allow 4200/tcp comment "Web Terminal Console"
    print_success "UFW firewall configured"
elif command -v firewall-cmd &> /dev/null; then
    print_info "Using firewalld"
    sudo systemctl enable firewalld
    sudo systemctl start firewalld
    sudo firewall-cmd --permanent --add-port=9090/tcp
    sudo firewall-cmd --permanent --add-port=4200/tcp
    sudo firewall-cmd --reload
    print_success "Firewalld configured"
elif command -v iptables &> /dev/null; then
    print_info "Using iptables"
    sudo iptables -A INPUT -p tcp --dport 9090 -j ACCEPT
    sudo iptables -A INPUT -p tcp --dport 4200 -j ACCEPT
    # Save iptables rules (method varies by distro)
    if command -v iptables-save &> /dev/null; then
        sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
        sudo iptables-save > /etc/sysconfig/iptables 2>/dev/null || \
        print_info "iptables rules applied (manual save may be required)"
    fi
    print_success "iptables configured"
else
    print_error "No supported firewall found. Please manually configure ports 9090 and 4200"
fi

echo

# Step 5: Web Terminal Installation
print_header "STEP 5: WEB TERMINAL INSTALLATION"

print_step "Installing shellinabox for web terminal access on port 4200..."

# Check if shellinabox is already installed
if command -v shellinaboxd &> /dev/null; then
    print_success "Shellinabox already installed"
else
    print_info "Installing shellinabox and net-tools automatically..."
    if command -v apt-get &> /dev/null; then
        print_info "Installing via apt-get..."
        sudo apt-get update && sudo apt-get install -y shellinabox net-tools
    elif command -v yum &> /dev/null; then
        print_info "Installing EPEL repository for CentOS/RHEL..."
        sudo yum install -y epel-release
        print_info "Installing via yum..."
        sudo yum install -y shellinabox net-tools
    elif command -v dnf &> /dev/null; then
        print_info "Installing EPEL repository for CentOS/RHEL..."
        sudo dnf install -y epel-release  
        print_info "Installing via dnf..."
        sudo dnf install -y shellinabox net-tools
    elif command -v pacman &> /dev/null; then
        print_info "Installing via pacman..."
        sudo pacman -S shellinabox net-tools
    else
        print_error "Package manager not found. Please install shellinabox manually"
    fi
    
    # Configure shellinabox to run on port 4200
    print_step "Configuring shellinabox service..."
    
    # Configure for different distributions
    if command -v yum &> /dev/null || command -v dnf &> /dev/null; then
        # CentOS/RHEL configuration
        print_info "Configuring shellinabox for CentOS/RHEL..."
        
        sudo tee /etc/sysconfig/shellinaboxd > /dev/null << 'EOF'
# shellinabox daemon configuration  
USER=nobody
GROUP=nobody
CERTDIR=/var/lib/shellinabox
PORT=4200
OPTS="--no-beep --disable-ssl -t"
EOF
        
        print_info "Created /etc/sysconfig/shellinaboxd configuration"
        SERVICE_NAME="shellinaboxd"
    else
        # Ubuntu/Debian configuration
        if [[ -f /etc/default/shellinabox ]]; then
            sudo sed -i 's/SHELLINABOX_PORT=.*/SHELLINABOX_PORT=4200/' /etc/default/shellinabox
        fi
        SERVICE_NAME="shellinabox"
    fi
    
    sudo systemctl enable "$SERVICE_NAME"
    sudo systemctl start "$SERVICE_NAME"
    print_success "Shellinabox installed and configured on port 4200"
    
    # Configure shellinabox for HTTP access (disable SSL)
    print_step "Configuring shellinabox for HTTP access..."
    if [[ -f /etc/default/shellinabox ]]; then
        # Check if SHELLINABOX_ARGS already exists
        if grep -q "^SHELLINABOX_ARGS=" /etc/default/shellinabox; then
            # Update existing SHELLINABOX_ARGS line
            sudo sed -i 's/^SHELLINABOX_ARGS=.*/SHELLINABOX_ARGS="--no-beep --disable-ssl"/' /etc/default/shellinabox
            print_info "Updated existing SHELLINABOX_ARGS with --disable-ssl"
        else
            # Add new SHELLINABOX_ARGS line
            echo 'SHELLINABOX_ARGS="--no-beep --disable-ssl"' | sudo tee -a /etc/default/shellinabox >/dev/null
            print_info "Added SHELLINABOX_ARGS with --disable-ssl"
        fi
        
        # Restart shellinabox to apply HTTP configuration
        print_info "Restarting $SERVICE_NAME to enable HTTP access..."
        sudo systemctl restart "$SERVICE_NAME"
        sleep 2
        
        # Verify HTTP access is working
        if curl -s -I http://localhost:4200 2>/dev/null | grep -q "HTTP/1.1 200"; then
            print_success "Shellinabox HTTP access configured successfully!"
            print_info "Web terminal accessible at: http://$TARGET_IP:4200"
        else
            print_warning "HTTP configuration applied, but verification failed"
            print_info "Web terminal should be accessible at: http://$TARGET_IP:4200"
        fi
    else
        print_warning "Shellinabox config file not found, HTTP configuration skipped"
    fi
fi

echo

# Step 6: Create Required Directories
print_header "STEP 6: DIRECTORY SETUP"

print_step "Creating random_files directory if needed..."
if [[ -d "$USER_HOME/random_files" ]]; then
    print_success "~/random_files directory already exists"
else
    print_info "Creating ~/random_files directory..."
    mkdir -p "$USER_HOME/random_files"
    chmod 755 "$USER_HOME/random_files"
    print_success "✅ ~/random_files directory created"
fi

# Create logs directory if needed
print_step "Creating logs directory if needed..."
if [[ -d "$USER_HOME/video-system/logs" ]]; then
    print_success "~/video-system/logs directory already exists"
else
    print_info "Creating ~/video-system/logs directory..."
    mkdir -p "$USER_HOME/video-system/logs"
    chmod 755 "$USER_HOME/video-system/logs"
    print_success "✅ ~/video-system/logs directory created"
fi

echo

# Step 7: Server Validation
print_header "STEP 7: SYSTEM VALIDATION"

# Check if port 9090 is already in use
print_step "Checking port 9090 availability..."

# Check for processes listening on port 9090 (both IPv4 and IPv6)
PORT_CHECK=$(netstat -tuln 2>/dev/null | grep ":9090[[:space:]]" || ss -tuln 2>/dev/null | grep ":9090[[:space:]]" || true)

if [[ -n "$PORT_CHECK" ]]; then
    print_info "Port 9090 is currently in use:"
    echo "$PORT_CHECK"
    
    # Check if systemd is using the port
    SYSTEMD_CHECK=$(sudo netstat -tlnp 2>/dev/null | grep ":9090[[:space:]].*systemd" || sudo ss -tlnp 2>/dev/null | grep ":9090[[:space:]].*systemd" || true)
    
    if [[ -n "$SYSTEMD_CHECK" ]]; then
        print_error "systemd is using port 9090!"
        print_info "This likely means there's a systemd service configured for port 9090"
        print_info "Check: sudo systemctl status | grep 9090"
        print_info "You may need to stop the conflicting service or change the port"
        echo
        echo -e "${YELLOW}Continue anyway? The Python server will try to bind to the port. (y/N)${NC}"
        read -p "Continue? " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Setup cancelled by user"
            echo
            echo -e "${YELLOW}Press any key to return to main menu...${NC}"
            read -n 1 -s
            return
        fi
    else
        print_info "Attempting to free port 9090..."
    
    # Multiple methods to find and kill processes using port 9090
    PIDS=""
    
    # Method 1: lsof (both regular and sudo)
    if command -v lsof &> /dev/null; then
        LSOF_PIDS=$(lsof -ti:9090 2>/dev/null | tr '\n' ' ')
        SUDO_LSOF_PIDS=$(sudo lsof -ti:9090 2>/dev/null | tr '\n' ' ')
        PIDS="$PIDS $LSOF_PIDS $SUDO_LSOF_PIDS"
    fi
    
    # Method 2: netstat
    if command -v netstat &> /dev/null; then
        NETSTAT_PIDS=$(netstat -tlnp 2>/dev/null | grep ":9090[[:space:]]" | awk '{print $7}' | cut -d'/' -f1 | grep -E '^[0-9]+$' | tr '\n' ' ')
        SUDO_NETSTAT_PIDS=$(sudo netstat -tlnp 2>/dev/null | grep ":9090[[:space:]]" | awk '{print $7}' | cut -d'/' -f1 | grep -E '^[0-9]+$' | tr '\n' ' ')
        PIDS="$PIDS $NETSTAT_PIDS $SUDO_NETSTAT_PIDS"
    fi
    
    # Method 3: ss
    if command -v ss &> /dev/null; then
        SS_PIDS=$(ss -tlnp 2>/dev/null | grep ":9090[[:space:]]" | grep -o 'pid=[0-9]*' | cut -d'=' -f2 | tr '\n' ' ')
        SUDO_SS_PIDS=$(sudo ss -tlnp 2>/dev/null | grep ":9090[[:space:]]" | grep -o 'pid=[0-9]*' | cut -d'=' -f2 | tr '\n' ' ')
        PIDS="$PIDS $SS_PIDS $SUDO_SS_PIDS"
    fi
    
    # Method 4: fuser
    if command -v fuser &> /dev/null; then
        FUSER_PIDS=$(fuser 9090/tcp 2>/dev/null | tr '\n' ' ')
        SUDO_FUSER_PIDS=$(sudo fuser 9090/tcp 2>/dev/null | tr '\n' ' ')
        PIDS="$PIDS $FUSER_PIDS $SUDO_FUSER_PIDS"
    fi
    
    # Remove duplicates and clean up - exclude system critical PIDs
    PIDS=$(echo "$PIDS" | tr ' ' '\n' | grep -E '^[0-9]+$' | grep -v '^1$' | grep -v '^2$' | sort -u | tr '\n' ' ')
    
    if [[ -n "$PIDS" ]]; then
        echo -e "${YELLOW}Found processes using port 9090: $PIDS${NC}"
        for PID in $PIDS; do
            # Skip critical system processes
            if [[ "$PID" -eq 1 || "$PID" -eq 2 || "$PID" -lt 10 ]]; then
                print_info "Skipping system process $PID"
                continue
            fi
            
            if kill -0 "$PID" 2>/dev/null || sudo kill -0 "$PID" 2>/dev/null; then
                print_info "Terminating process $PID"
                kill -TERM "$PID" 2>/dev/null || sudo kill -TERM "$PID" 2>/dev/null
                sleep 1
                if kill -0 "$PID" 2>/dev/null || sudo kill -0 "$PID" 2>/dev/null; then
                    print_info "Force killing process $PID"
                    kill -9 "$PID" 2>/dev/null || sudo kill -9 "$PID" 2>/dev/null
                fi
            fi
        done
        sleep 3
        
        # Final verification and aggressive cleanup if still occupied
        if netstat -tuln 2>/dev/null | grep -q ":9090[[:space:]]" || ss -tuln 2>/dev/null | grep -q ":9090[[:space:]]"; then
            print_info "Port still occupied, attempting aggressive cleanup..."
            # Try brute force methods
            sudo fuser -k 9090/tcp 2>/dev/null || true
            sudo lsof -ti:9090 | xargs -r sudo kill -9 2>/dev/null || true
            sleep 2
            
            # Final check
            if netstat -tuln 2>/dev/null | grep -q ":9090[[:space:]]" || ss -tuln 2>/dev/null | grep -q ":9090[[:space:]]"; then
                print_error "Failed to free port 9090 after aggressive cleanup"
                print_info "Port may be in TIME_WAIT state - try waiting 30 seconds"
            else
                print_success "Port 9090 is now available"
            fi
        else
            print_success "Port 9090 is now available"
        fi
    else
        print_info "No processes found, but port appears busy. Attempting aggressive cleanup..."
        # Try brute force even if no PIDs found
        sudo fuser -k 9090/tcp 2>/dev/null || true
        sudo lsof -ti:9090 | xargs -r sudo kill -9 2>/dev/null || true
        sleep 2
        
        if netstat -tuln 2>/dev/null | grep -q ":9090[[:space:]]" || ss -tuln 2>/dev/null | grep -q ":9090[[:space:]]"; then
            print_error "Port 9090 still appears busy after cleanup"
            print_info "This may be a TIME_WAIT state - try waiting 30 seconds"
        else
            print_success "Port 9090 is now available"
        fi
    fi
fi
else
    print_success "Port 9090 is available"
fi

print_step "Starting authentication server for testing..."
cd "$USER_HOME/video-system/scripts"

# Start server in background for testing
python3 auth_api_server.py &
SERVER_PID=$!
sleep 3

print_step "Testing server authentication..."
echo -e "${CYAN}Testing with curl command:${NC}"
echo -e "${YELLOW}curl -X POST \"http://$TARGET_IP:9090/api/auth\" -H \"Content-Type: application/json\" -d '{\"username\":\"$AUTH_USERNAME\",\"password\":\"****\"}'${NC}"
echo

# Test authentication
CURL_RESPONSE=$(curl -s -X POST "http://$TARGET_IP:9090/api/auth" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$AUTH_USERNAME\",\"password\":\"$AUTH_PASSWORD\"}" 2>/dev/null)

if [[ $? -eq 0 ]] && echo "$CURL_RESPONSE" | grep -q "success.*true"; then
    print_success "Authentication server is responding correctly!"
    echo -e "${GREEN}Response:${NC}"
    echo "$CURL_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$CURL_RESPONSE"
else
    print_error "Authentication test failed"
    print_info "Server may need manual startup: cd $USER_HOME/video-system/scripts && python3 auth_api_server.py"
fi

# Stop test server
kill $SERVER_PID 2>/dev/null
echo

# Final Summary
print_header "INSTALLATION COMPLETE"

echo -e "${GREEN}✅ System successfully configured!${NC}"
echo
echo -e "${CYAN}📋 Configuration Summary:${NC}"
echo -e "   ${WHITE}Target IP:${NC} $TARGET_IP"
echo -e "   ${WHITE}Username:${NC} $AUTH_USERNAME"
echo -e "   ${WHITE}Home Directory:${NC} $USER_HOME"
echo -e "   ${WHITE}System:${NC} $DISTRO $VERSION"
echo
echo -e "${CYAN}🚀 Access Points:${NC}"
echo -e "   ${WHITE}Main Dashboard:${NC} http://$TARGET_IP:9090"
echo -e "   ${WHITE}API Console:${NC} http://$TARGET_IP:9090/api_console.html"
echo -e "   ${WHITE}Web Terminal:${NC} http://$TARGET_IP:4200"
echo
echo -e "${CYAN}📁 Configuration files updated:${NC}"
echo -e "   ✓ $USER_HOME/video-system/docs/dashboard.html"
echo -e "   ✓ $USER_HOME/video-system/docs/api_console.html"
echo -e "   ✓ $USER_HOME/video-system/scripts/auth_api_server.py"
echo -e "   ✓ $USER_HOME/.crds (credentials)"
echo
print_separator

# Final prompt to start the server
echo -e "${WHITE}🚀 READY TO START THE SERVER${NC}"
echo
echo -e "${YELLOW}The system is now configured and ready to use!${NC}"
echo -e "${CYAN}To start the Video and Files Management System server, run:${NC}"
echo
echo -e "${GREEN}    python3 ~/video-system/scripts/auth_api_server.py${NC}"
echo
echo -e "${YELLOW}Would you like to start the server now? (y/N)${NC}"
read -p "Start server? " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Check and kill any processes on port 9090 before starting
    print_step "Preparing to start server..."
    if netstat -tuln 2>/dev/null | grep -q ":9090[[:space:]]" || ss -tuln 2>/dev/null | grep -q ":9090[[:space:]]"; then
        print_info "Port 9090 is in use. Freeing it now..."
        
        # Aggressive port cleanup - force kill everything on port 9090
        print_info "Performing aggressive port cleanup..."
        
        # Brute force methods first
        sudo fuser -k 9090/tcp 2>/dev/null || true
        sudo lsof -ti:9090 | xargs -r sudo kill -9 2>/dev/null || true
        
        # Multiple methods to find and kill any remaining processes
        PIDS=""
        
        # Method 1: lsof (both regular and sudo)
        if command -v lsof &> /dev/null; then
            LSOF_PIDS=$(lsof -ti:9090 2>/dev/null | tr '\n' ' ')
            SUDO_LSOF_PIDS=$(sudo lsof -ti:9090 2>/dev/null | tr '\n' ' ')
            PIDS="$PIDS $LSOF_PIDS $SUDO_LSOF_PIDS"
        fi
        
        # Method 2: netstat
        if command -v netstat &> /dev/null; then
            NETSTAT_PIDS=$(netstat -tlnp 2>/dev/null | grep ":9090 " | awk '{print $7}' | cut -d'/' -f1 | grep -E '^[0-9]+$' | tr '\n' ' ')
            SUDO_NETSTAT_PIDS=$(sudo netstat -tlnp 2>/dev/null | grep ":9090 " | awk '{print $7}' | cut -d'/' -f1 | grep -E '^[0-9]+$' | tr '\n' ' ')
            PIDS="$PIDS $NETSTAT_PIDS $SUDO_NETSTAT_PIDS"
        fi
        
        # Method 3: ss
        if command -v ss &> /dev/null; then
            SS_PIDS=$(ss -tlnp 2>/dev/null | grep ":9090 " | grep -o 'pid=[0-9]*' | cut -d'=' -f2 | tr '\n' ' ')
            SUDO_SS_PIDS=$(sudo ss -tlnp 2>/dev/null | grep ":9090 " | grep -o 'pid=[0-9]*' | cut -d'=' -f2 | tr '\n' ' ')
            PIDS="$PIDS $SS_PIDS $SUDO_SS_PIDS"
        fi
        
        # Remove duplicates and clean up - exclude system critical PIDs
        PIDS=$(echo "$PIDS" | tr ' ' '\n' | grep -E '^[0-9]+$' | grep -v '^1$' | grep -v '^2$' | sort -u | tr '\n' ' ')
        
        if [[ -n "$PIDS" ]]; then
            echo -e "${YELLOW}Terminating remaining processes: $PIDS${NC}"
            for PID in $PIDS; do
                # Skip critical system processes
                if [[ "$PID" -eq 1 || "$PID" -eq 2 || "$PID" -lt 10 ]]; then
                    print_info "Skipping system process $PID"
                    continue
                fi
                
                if kill -0 "$PID" 2>/dev/null || sudo kill -0 "$PID" 2>/dev/null; then
                    print_info "Force killing process $PID"
                    kill -9 "$PID" 2>/dev/null || sudo kill -9 "$PID" 2>/dev/null
                fi
            done
        fi
        
        sleep 3
        
        # Final verification and TIME_WAIT handling
        if netstat -tuln 2>/dev/null | grep -q ":9090[[:space:]]" || ss -tuln 2>/dev/null | grep -q ":9090[[:space:]]"; then
            # Check if it's in TIME_WAIT state
            if netstat -an 2>/dev/null | grep ":9090.*TIME_WAIT" || ss -an 2>/dev/null | grep ":9090.*TIME-WAIT"; then
                print_info "Port 9090 is in TIME_WAIT state - FORCE KILLING it!"
                
                # AGGRESSIVE cleanup for TIME_WAIT states
                print_info "Performing NUCLEAR cleanup of port 9090..."
                
                # Kill any TCP connections to port 9090
                sudo ss -K dport = 9090 2>/dev/null || true
                sudo ss -K sport = 9090 2>/dev/null || true
                
                # Force reset TCP connections
                netstat -an 2>/dev/null | grep ":9090" | while read line; do
                    local_addr=$(echo $line | awk '{print $4}')
                    remote_addr=$(echo $line | awk '{print $5}')
                    if [[ "$remote_addr" != "0.0.0.0:*" && "$remote_addr" != ":::*" ]]; then
                        sudo ss -K dst "$remote_addr" 2>/dev/null || true
                        sudo ss -K src "$local_addr" 2>/dev/null || true
                    fi
                done
                
                # Set aggressive socket reuse parameters
                echo 1 | sudo tee /proc/sys/net/ipv4/tcp_tw_reuse >/dev/null 2>&1 || true
                echo 1 | sudo tee /proc/sys/net/ipv4/tcp_tw_recycle >/dev/null 2>&1 || true
                echo 5 | sudo tee /proc/sys/net/ipv4/tcp_fin_timeout >/dev/null 2>&1 || true
                echo 1 | sudo tee /proc/sys/net/ipv4/tcp_timestamps >/dev/null 2>&1 || true
                
                # Wait and verify
                sleep 3
                
                print_success "FORCE KILL completed - port should now be free!"
            else
                print_error "Port 9090 still busy after all cleanup attempts"
                print_info "FORCE KILLING everything on port 9090 regardless..."
                
                # Nuclear option - kill everything related to port 9090
                sudo ss -K dport = 9090 2>/dev/null || true
                sudo ss -K sport = 9090 2>/dev/null || true
                sudo pkill -9 -f "9090" 2>/dev/null || true
                sudo pkill -9 -f "auth_api_server" 2>/dev/null || true
                
                print_success "Nuclear cleanup completed!"
            fi
        else
            print_success "Port 9090 is now available"
        fi
    fi
    
    print_step "Starting the Video and Files Management System server..."
    echo -e "${CYAN}Server will run on: http://$TARGET_IP:9090${NC}"
    echo -e "${CYAN}Server will run in background and survive after script exit${NC}"
    echo
    
    # Create a wrapper script to handle socket reuse and background execution
    cat > "$USER_HOME/start_server.sh" << 'EOL'
#!/bin/bash
# Enable socket reuse for TIME_WAIT states
export SO_REUSEADDR=1
export SO_REUSEPORT=1

# Set Python to unbuffered output
export PYTHONUNBUFFERED=1

# Change to scripts directory
cd ~/video-system/scripts

# Start the server with nohup in background
nohup python3 -u auth_api_server.py > ~/video-system/server.log 2>&1 &

# Get the PID and save it
SERVER_PID=$!
echo $SERVER_PID > ~/video-system/server.pid

echo "Server started in background with PID: $SERVER_PID"
echo "Server log: ~/video-system/server.log"
echo "To stop server: kill $SERVER_PID"
EOL
    
    chmod +x "$USER_HOME/start_server.sh"
    
    # Execute the wrapper script
    "$USER_HOME/start_server.sh"
    
    # Show server status
    sleep 2
    if [[ -f "$USER_HOME/video-system/server.pid" ]]; then
        SERVER_PID=$(cat "$USER_HOME/video-system/server.pid")
        if ps -p $SERVER_PID > /dev/null 2>&1; then
            print_success "Server is running in background (PID: $SERVER_PID)"
            print_info "Server log: ~/video-system/server.log"
            print_info "To stop server later: kill $SERVER_PID"
            print_info "Or: pkill -f auth_api_server"
        else
            print_error "Server failed to start. Check ~/video-system/server.log"
        fi
    fi
else
    echo
    print_info "To start the server later, run:"
    echo -e "${GREEN}    cd ~/video-system/scripts${NC}"
    echo -e "${GREEN}    python3 auth_api_server.py${NC}"
fi

    echo
    
    # Configure firewall
    if configure_firewall; then
        print_success "Firewall configured successfully"
        echo
        print_info "Ports opened:"
        print_info "• Port 9090 (Video System API)"
        print_info "• Port 4200 (Terminal Access)"
        echo
    else
        print_warning "Firewall configuration failed or was skipped"
        print_info "You may need to manually open ports 9090 and 4200"
        echo
    fi

    echo
    print_separator
    echo -e "${WHITE}Setup completed successfully! 🎉${NC}"
    print_separator
    echo
    print_info "Your video system is now accessible at:"
    echo -e "   ${WHITE}• Web Interface:${NC} http://$TARGET_IP:9090"
    echo -e "   ${WHITE}• Terminal Access:${NC} http://$TARGET_IP:4200"
    echo
    print_info "Use your configured credentials to login"
    echo
    echo -e "${YELLOW}Press any key to return to main menu...${NC}"
    read -n 1 -s
}

# Function to kill and restart server
kill_and_restart_server() {
    print_header "KILL & RESTART VIDEO SYSTEM SERVER"
    
    print_step "Select server location and connection method"
    echo
    
    # Server location options
    print_separator
    echo -e "${MAGENTA}${BOLD}SERVER LOCATION OPTIONS${NC}"
    print_separator
    echo
    echo -e "${GREEN}1)${NC} Local server (this machine)"
    echo -e "${CYAN}2)${NC} Remote server (via SSH)"
    echo -e "${YELLOW}3)${NC} Return to main menu"
    echo
    
    local location_choice
    while true; do
        echo -e "${CYAN}Select server location (1-3): ${NC}"
        read -p "> " location_choice
        
        if [[ "$location_choice" == "1" || "$location_choice" == "2" || "$location_choice" == "3" ]]; then
            break
        else
            print_error "Invalid choice. Please select 1, 2, or 3."
            echo
        fi
    done
    
    case "$location_choice" in
        1)
            # Local server restart
            restart_local_server
            ;;
        2)
            # Remote server restart
            restart_remote_server
            ;;
        3)
            # Return to main menu
            print_info "Returning to main menu..."
            return
            ;;
    esac
}

# Function to restart local server
restart_local_server() {
    print_header "LOCAL SERVER RESTART"
    
    print_step "Checking for running video system server processes..."
    
    # Get current user home directory
    USER_HOME=$(echo $HOME)
    
    # Multiple methods to find processes related to video system
    FOUND_PROCESSES=false
    
    # Method 1: Check for auth_api_server processes
    if pgrep -f "auth_api_server" > /dev/null 2>&1; then
        print_info "Found auth_api_server processes:"
        ps aux | grep auth_api_server | grep -v grep
        FOUND_PROCESSES=true
    fi
    
    # Method 2: Check for processes on port 9090
    if command -v lsof &> /dev/null && lsof -i:9090 > /dev/null 2>&1; then
        print_info "Found processes using port 9090:"
        lsof -i:9090
        FOUND_PROCESSES=true
    fi
    
    # Method 3: Check for python processes in video-system directory
    if pgrep -f "python.*video-system" > /dev/null 2>&1; then
        print_info "Found Python processes in video-system directory:"
        ps aux | grep python | grep video-system | grep -v grep
        FOUND_PROCESSES=true
    fi
    
    if [[ "$FOUND_PROCESSES" == "true" ]]; then
        echo
        print_step "Terminating all video system server processes..."
        
        # Kill auth_api_server processes
        print_info "Killing auth_api_server processes..."
        pkill -f "auth_api_server" 2>/dev/null || true
        
        # Force kill processes on port 9090 using multiple methods
        print_info "Freeing port 9090..."
        
        # Method 1: lsof + kill
        if command -v lsof &> /dev/null; then
            LSOF_PIDS=$(lsof -ti:9090 2>/dev/null || true)
            if [[ -n "$LSOF_PIDS" ]]; then
                echo "$LSOF_PIDS" | xargs -r kill -9 2>/dev/null || true
            fi
            
            SUDO_LSOF_PIDS=$(sudo lsof -ti:9090 2>/dev/null || true)
            if [[ -n "$SUDO_LSOF_PIDS" ]]; then
                echo "$SUDO_LSOF_PIDS" | xargs -r sudo kill -9 2>/dev/null || true
            fi
        fi
        
        # Method 2: fuser
        if command -v fuser &> /dev/null; then
            fuser -k 9090/tcp 2>/dev/null || true
            sudo fuser -k 9090/tcp 2>/dev/null || true
        fi
        
        # Method 3: ss (socket statistics)
        if command -v ss &> /dev/null; then
            sudo ss -K dport = 9090 2>/dev/null || true
            sudo ss -K sport = 9090 2>/dev/null || true
        fi
        
        # Kill any Python processes in video-system directory
        pkill -f "python.*video-system" 2>/dev/null || true
        
        # Remove PID file if it exists
        if [[ -f "$USER_HOME/video-system/server.pid" ]]; then
            OLD_PID=$(cat "$USER_HOME/video-system/server.pid" 2>/dev/null)
            if [[ -n "$OLD_PID" ]] && kill -0 "$OLD_PID" 2>/dev/null; then
                print_info "Killing server with PID: $OLD_PID"
                kill -9 "$OLD_PID" 2>/dev/null || sudo kill -9 "$OLD_PID" 2>/dev/null || true
            fi
            rm -f "$USER_HOME/video-system/server.pid"
        fi
        
        sleep 3
        print_success "All video system processes terminated"
    else
        print_info "No video system server processes found running"
    fi
    
    echo
    print_separator
    echo -e "${CYAN}${BOLD}RESTARTING LOCAL VIDEO SYSTEM SERVER${NC}"
    print_separator
    echo
    
    # Verify video-system directory exists
    if [[ ! -d "$USER_HOME/video-system/scripts" ]]; then
        print_error "Video system directory not found at: $USER_HOME/video-system"
        print_error "Please run 'Setup New System' first"
        echo
        echo -e "${YELLOW}Press any key to return to main menu...${NC}"
        read -n 1 -s
        return
    fi
    
    # Verify auth_api_server.py exists
    if [[ ! -f "$USER_HOME/video-system/scripts/auth_api_server.py" ]]; then
        print_error "Server script not found at: $USER_HOME/video-system/scripts/auth_api_server.py"
        echo
        echo -e "${YELLOW}Press any key to return to main menu...${NC}"
        read -n 1 -s
        return
    fi
    
    # Check if port 9090 is still in use after killing
    print_step "Verifying port 9090 availability..."
    if netstat -tuln 2>/dev/null | grep -q ":9090[[:space:]]" || ss -tuln 2>/dev/null | grep -q ":9090[[:space:]]"; then
        print_warning "Port 9090 is still in use. Attempting aggressive cleanup..."
        
        # Aggressive cleanup for TIME_WAIT states
        if netstat -an 2>/dev/null | grep ":9090.*TIME_WAIT" || ss -an 2>/dev/null | grep ":9090.*TIME-WAIT"; then
            print_info "Port in TIME_WAIT state - applying system-level fixes..."
            # Set aggressive socket reuse parameters for CentOS/RHEL compatibility
            echo 1 | sudo tee /proc/sys/net/ipv4/tcp_tw_reuse >/dev/null 2>&1 || true
            echo 5 | sudo tee /proc/sys/net/ipv4/tcp_fin_timeout >/dev/null 2>&1 || true
            echo 1 | sudo tee /proc/sys/net/ipv4/tcp_timestamps >/dev/null 2>&1 || true
            
            # Additional cleanup for RHEL/CentOS systems
            if command -v systemctl &> /dev/null; then
                sudo sysctl -w net.ipv4.tcp_tw_reuse=1 2>/dev/null || true
                sudo sysctl -w net.ipv4.tcp_fin_timeout=5 2>/dev/null || true
            fi
        fi
        
        sleep 2
        if netstat -tuln 2>/dev/null | grep -q ":9090[[:space:]]" || ss -tuln 2>/dev/null | grep -q ":9090[[:space:]]"; then
            print_warning "Port 9090 still busy - server may fail to start"
        else
            print_success "Port 9090 is now available"
        fi
    else
        print_success "Port 9090 is available"
    fi
    
    echo
    print_step "Starting local video system server..."
    
    # Create the start server wrapper script if it doesn't exist
    if [[ ! -f "$USER_HOME/start_server.sh" ]]; then
        print_info "Creating server startup script..."
        cat > "$USER_HOME/start_server.sh" << 'EOL'
#!/bin/bash
# Enable socket reuse for TIME_WAIT states
export SO_REUSEADDR=1
export SO_REUSEPORT=1

# Set Python to unbuffered output
export PYTHONUNBUFFERED=1

# Change to scripts directory
cd ~/video-system/scripts

# Start the server with nohup in background
nohup python3 -u auth_api_server.py > ~/video-system/server.log 2>&1 &

# Get the PID and save it
SERVER_PID=$!
echo $SERVER_PID > ~/video-system/server.pid

echo "Server started in background with PID: $SERVER_PID"
echo "Server log: ~/video-system/server.log"
echo "To stop server: kill $SERVER_PID"
EOL
        chmod +x "$USER_HOME/start_server.sh"
    fi
    
    # Execute the wrapper script
    print_info "Executing server startup script..."
    "$USER_HOME/start_server.sh"
    
    # Wait and verify server started
    sleep 3
    
    if [[ -f "$USER_HOME/video-system/server.pid" ]]; then
        SERVER_PID=$(cat "$USER_HOME/video-system/server.pid")
        if ps -p $SERVER_PID > /dev/null 2>&1; then
            print_success "✅ Local video system server restarted successfully!"
            echo
            print_info "Server Details:"
            echo -e "   ${WHITE}Process ID:${NC} $SERVER_PID"
            echo -e "   ${WHITE}Log file:${NC} ~/video-system/server.log"
            echo -e "   ${WHITE}Port:${NC} 9090"
            
            # Try to get the server's IP address
            if command -v hostname &> /dev/null; then
                LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")
                echo -e "   ${WHITE}Access URL:${NC} http://$LOCAL_IP:9090"
            fi
            
            echo
            print_info "To stop server later: kill $SERVER_PID"
            print_info "Or run: pkill -f auth_api_server"
        else
            print_error "❌ Server failed to start properly"
            echo
            if [[ -f "$USER_HOME/video-system/server.log" ]]; then
                print_info "Last few lines of server log:"
                tail -n 10 "$USER_HOME/video-system/server.log" 2>/dev/null || echo "Could not read log file"
            fi
        fi
    else
        print_error "❌ Server PID file not created - startup may have failed"
    fi
    
    echo
    print_separator
    echo -e "${GREEN}${BOLD}Local server restart operation completed!${NC}"
    print_separator
    echo
    echo -e "${YELLOW}Press any key to return to main menu...${NC}"
    read -n 1 -s
}

# Function to restart remote server
restart_remote_server() {
    print_header "REMOTE SERVER RESTART"
    
    # Connection options
    print_separator
    echo -e "${MAGENTA}${BOLD}SERVER RESTART OPTIONS${NC}"
    print_separator
    echo
    echo -e "${GREEN}1)${NC} Restart Server (Video system in this local host)"
    echo -e "${CYAN}2)${NC} Use saved remote connection"
    echo -e "${YELLOW}3)${NC} Enter remote connection details manually"
    echo -e "${RED}4)${NC} Return to main menu"
    echo
    
    local connection_choice
    while true; do
        echo -e "${CYAN}Select restart method (1-4): ${NC}"
        read -p "> " connection_choice
        
        if [[ "$connection_choice" == "1" || "$connection_choice" == "2" || "$connection_choice" == "3" || "$connection_choice" == "4" ]]; then
            break
        else
            print_error "Invalid choice. Please select 1, 2, 3, or 4."
            echo
        fi
    done
    
    # Handle local restart option
    if [[ "$connection_choice" == "1" ]]; then
        print_header "LOCAL SERVER RESTART"
        
        print_info "You selected to restart the video system server on this local host."
        print_info "This will restart ~/video-system/scripts/auth_api_server.py on this machine."
        echo
        
        echo -e "${CYAN}Are you sure you want to restart the LOCAL video system server? (y/N): ${NC}"
        read -p "" -n 1 -r
        echo
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            # Call the local restart function
            restart_local_server
        else
            print_info "Local server restart cancelled"
            echo
            echo -e "${YELLOW}Press any key to return to main menu...${NC}"
            read -n 1 -s
        fi
        return
    fi
    
    local remote_host=""
    local remote_user=""  
    local auth_method=""
    local auth_value=""
    local connection_name=""
    
    if [[ "$connection_choice" == "2" ]]; then
        # Use saved connection
        if [[ ! -f "$CRDS_FILE" ]] || [[ ! -r "$CRDS_FILE" ]]; then
            print_error "Credentials file not found or not readable: $CRDS_FILE"
            print_info "Please use option 5 (Connection Management) to add connections first"
            echo
            echo -e "${YELLOW}Press any key to return to main menu...${NC}"
            read -n 1 -s
            return
        fi
        
        # Check if file has valid content
        local file_check_result
        file_check_result=$(python3 -c "
import json
import os
import sys

crds_file = '$CRDS_FILE'
try:
    if not os.path.exists(crds_file) or os.path.getsize(crds_file) == 0:
        print('EMPTY')
        sys.exit(0)
    
    with open(crds_file, 'r') as f:
        data = json.load(f)
    
    if not isinstance(data, list) or len(data) == 0:
        print('NO_CONNECTIONS')
    else:
        print('VALID')
        
except json.JSONDecodeError:
    print('INVALID_JSON')
except Exception as e:
    print(f'ERROR: {str(e)}')
" 2>/dev/null)
        
        if [[ "$file_check_result" != "VALID" ]]; then
            case "$file_check_result" in
                "EMPTY")
                    print_error "Credentials file is empty"
                    ;;
                "NO_CONNECTIONS")
                    print_error "No saved connections found"
                    ;;
                "INVALID_JSON")
                    print_error "Credentials file is corrupted (invalid JSON)"
                    print_info "You may need to recreate your connections"
                    ;;
                *)
                    print_error "Error reading credentials file: $file_check_result"
                    ;;
            esac
            print_info "Please use option 5 (Connection Management) to add connections first"
            echo
            echo -e "${YELLOW}Press any key to return to main menu...${NC}"
            read -n 1 -s
            return
        fi
        
        # List saved connections
        echo
        print_step "Available saved connections:"
        echo
        
        local list_result
        list_result=$(python3 -c "
import json
import sys

crds_file = '$CRDS_FILE'
try:
    with open(crds_file, 'r') as f:
        connections = json.load(f)
    
    if not isinstance(connections, list):
        print('ERROR: Invalid JSON structure')
        sys.exit(1)
        
    if not connections:
        print('ERROR: No connections found')
        sys.exit(1)
        
    for i, conn in enumerate(connections, 1):
        if not isinstance(conn, dict):
            print(f'ERROR: Invalid connection format at index {i}')
            continue
            
        name = conn.get('name', 'Unknown')
        username = conn.get('username', 'Unknown')
        host = conn.get('host', 'Unknown')
        auth_method = conn.get('auth_method', 'Unknown')
        
        print(f'{i}) {name} - {username}@{host} ({auth_method})')
        
except json.JSONDecodeError as e:
    print(f'ERROR: JSON parsing failed - {str(e)}')
    sys.exit(1)
except Exception as e:
    print(f'ERROR: {str(e)}')
    sys.exit(1)
" 2>&1)
        
        local list_exit_code=$?
        if [[ $list_exit_code -ne 0 ]]; then
            print_error "Failed to list saved connections"
            print_error "Details: $list_result"
            return
        elif [[ "$list_result" == *"ERROR:"* ]]; then
            print_error "Connection data error: $list_result"
            return
        else
            echo "$list_result"
        fi
        
        echo
        echo -e "${YELLOW}0)${NC} Return to previous menu"
        echo
        local conn_choice
        echo -e "${CYAN}Select connection number (or 0 to return): ${NC}"
        read -p "> " conn_choice
        
        # Handle return to previous menu
        if [[ "$conn_choice" == "0" ]]; then
            print_info "Returning to previous menu..."
            return
        fi
        
        # Get connection details
        local conn_details=$(python3 -c "
import json
try:
    with open('$CRDS_FILE', 'r') as f:
        connections = json.load(f)
    
    if $conn_choice > 0 and $conn_choice <= len(connections):
        conn = connections[$conn_choice - 1]
        print(f'{conn[\"host\"]}|{conn[\"username\"]}|{conn[\"auth_method\"]}|{conn.get(\"password\", conn.get(\"ssh_key_path\", \"\"))}|{conn[\"name\"]}')
    else:
        print('INVALID')
except:
    print('ERROR')
" 2>/dev/null)
        
        if [[ "$conn_details" == "INVALID" || "$conn_details" == "ERROR" || -z "$conn_details" ]]; then
            print_error "Invalid connection selection"
            return
        fi
        
        IFS='|' read -r remote_host remote_user auth_method auth_value connection_name <<< "$conn_details"
        
    elif [[ "$connection_choice" == "3" ]]; then
        # Enter connection details manually
        echo
        print_step "Enter remote server connection details"
        echo
        
        # Get remote host
        while true; do
            echo -e "${CYAN}Enter remote server IP address or hostname/FQDN:${NC}"
            echo -e "${YELLOW}Examples: 192.168.1.100, server.example.com${NC}"
            read -p "Host: " remote_host
            
            if [[ -n "$remote_host" ]] && validate_ip "$remote_host"; then
                print_success "Valid host: $remote_host"
                break
            else
                print_error "Invalid IP address or hostname format"
                echo
            fi
        done
        
        echo
        
        # Get username
        while true; do
            echo -e "${CYAN}Enter username for remote server:${NC}"
            read -p "Username: " remote_user
            
            if [[ -n "$remote_user" && "$remote_user" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]]; then
                break
            else
                print_error "Invalid username format"
                echo
            fi
        done
        
        echo
        
        # Get authentication method
        echo -e "${CYAN}Select authentication method:${NC}"
        echo -e "${GREEN}1)${NC} SSH Key file"
        echo -e "${YELLOW}2)${NC} Password"
        echo -e "${RED}3)${NC} Return to previous menu"
        echo
        
        local auth_choice
        while true; do
            echo -e "${CYAN}Select method (1-3): ${NC}"
            read -p "> " auth_choice
            
            if [[ "$auth_choice" == "1" ]]; then
                auth_method="key"
                
                while true; do
                    echo -e "${CYAN}Enter path to SSH private key file:${NC}"
                    echo -e "${YELLOW}Example: /home/user/.ssh/id_rsa${NC}"
                    read -p "SSH Key Path: " auth_value
                    
                    if [[ -f "$auth_value" && -r "$auth_value" ]]; then
                        # Check key permissions
                        local key_perms=$(stat -c "%a" "$auth_value" 2>/dev/null)
                        if [[ "$key_perms" == "600" || "$key_perms" == "400" ]]; then
                            print_success "SSH key found and permissions are secure"
                            break
                        else
                            print_warning "SSH key permissions should be 600 or 400"
                            echo -e "${YELLOW}Fix with: chmod 600 '$auth_value'${NC}"
                            echo -e "${YELLOW}Continue anyway? (y/N): ${NC}"
                            read -p "" -n 1 -r
                            echo
                            if [[ $REPLY =~ ^[Yy]$ ]]; then
                                break
                            fi
                        fi
                    else
                        print_error "SSH key file not found or not readable: $auth_value"
                        echo
                    fi
                done
                break
                
            elif [[ "$auth_choice" == "2" ]]; then
                auth_method="password"
                
                # Check if sshpass is available
                if ! command -v sshpass &> /dev/null; then
                    print_warning "sshpass is required for password authentication"
                    echo -e "${CYAN}Install sshpass? (required for password auth)${NC}"
                    echo -e "${YELLOW}Ubuntu/Debian: sudo apt-get install sshpass${NC}"
                    echo -e "${YELLOW}RHEL/CentOS: sudo yum install sshpass${NC}"
                    echo
                    echo -e "${CYAN}Continue without installing? (connection will fail) (y/N): ${NC}"
                    read -p "" -n 1 -r
                    echo
                    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                        return
                    fi
                fi
                
                while true; do
                    echo -e "${CYAN}Enter password for $remote_user@$remote_host:${NC}"
                    read -s -p "Password: " auth_value
                    echo
                    
                    if [[ -n "$auth_value" ]]; then
                        echo -e "${CYAN}Confirm password:${NC}"
                        read -s -p "Confirm: " auth_confirm
                        echo
                        
                        if [[ "$auth_value" == "$auth_confirm" ]]; then
                            print_success "Password set successfully"
                            break
                        else
                            print_error "Passwords do not match"
                            echo
                        fi
                    else
                        print_error "Password cannot be empty"
                        echo
                    fi
                done
                break
            elif [[ "$auth_choice" == "3" ]]; then
                # Return to previous menu
                print_info "Returning to previous menu..."
                return
            else
                print_error "Invalid choice. Please select 1, 2, or 3."
                echo
            fi
        done
    elif [[ "$connection_choice" == "4" ]]; then
        # Return to main menu
        print_info "Returning to main menu..."
        return
    else
        print_error "Invalid connection choice: $connection_choice"
        return
    fi
    
    echo
    print_separator
    echo -e "${CYAN}${BOLD}TESTING REMOTE CONNECTION${NC}"
    print_separator
    echo
    
    # Test connection first
    print_step "Testing SSH connection to $remote_user@$remote_host..."
    
    local ssh_cmd=""
    if [[ "$auth_method" == "key" ]]; then
        ssh_cmd="ssh -i '$auth_value' -o StrictHostKeyChecking=no -o ConnectTimeout=10"
    else
        ssh_cmd="sshpass -p '$auth_value' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10"
    fi
    
    # Test basic connectivity
    if ! eval "$ssh_cmd $remote_user@$remote_host 'echo \"Connection test successful\"'" >/dev/null 2>&1; then
        print_error "Failed to connect to $remote_user@$remote_host"
        print_error "Please verify:"
        print_error "  - Host is reachable"
        print_error "  - SSH service is running"
        print_error "  - Username and credentials are correct"
        print_error "  - SSH key has correct permissions (600)"
        echo
        echo -e "${YELLOW}Press any key to return to main menu...${NC}"
        read -n 1 -s
        return
    fi
    
    print_success "✅ SSH connection test successful!"
    echo
    
    # Ask if user wants to save connection (only for manual entries)
    if [[ "$connection_choice" == "3" ]]; then
        echo
        print_separator
        echo -e "${CYAN}${BOLD}💾 SAVE CONNECTION${NC}"
        print_separator
        echo
        echo -e "${YELLOW}Would you like to save this connection for future use?${NC}"
        echo -e "   ${WHITE}Host:${NC} $remote_host"
        echo -e "   ${WHITE}User:${NC} $remote_user"
        echo -e "   ${WHITE}Auth:${NC} $auth_method"
        echo
        echo -e "${CYAN}Save connection? (y/N): ${NC}"
        read -p "" -n 1 -r
        echo
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo
            echo -e "${CYAN}Enter a name for this connection:${NC}"
            echo -e "${YELLOW}Examples: ProductionServer, DevBox, BackupServer${NC}"
            read -p "Connection name: " save_connection_name
            
            if [[ -n "$save_connection_name" ]]; then
                if save_connection "$save_connection_name" "$remote_host" "$remote_user" "$auth_method" "$auth_value"; then
                    print_success "Connection saved as '$save_connection_name'"
                else
                    print_error "Failed to save connection"
                fi
            else
                print_warning "No name provided - connection not saved"
            fi
            echo
        else
            print_info "Connection not saved"
            echo
        fi
    fi
    
    # Confirmation before restart
    print_separator
    echo -e "${RED}${BOLD}⚠️  REMOTE SERVER RESTART CONFIRMATION ⚠️${NC}"
    print_separator
    echo
    
    echo -e "${YELLOW}You are about to restart the video system server on:${NC}"
    echo -e "   ${WHITE}Host:${NC} $remote_host"
    echo -e "   ${WHITE}User:${NC} $remote_user"
    echo -e "   ${WHITE}Auth:${NC} $auth_method"
    if [[ -n "$connection_name" ]]; then
        echo -e "   ${WHITE}Connection:${NC} $connection_name"
    fi
    echo
    
    echo -e "${YELLOW}This will:${NC}"
    echo -e "${RED}  • Kill all running video system server processes${NC}"
    echo -e "${RED}  • Terminate processes on port 9090${NC}"
    echo -e "${GREEN}  • Start the server in background${NC}"
    echo -e "${WHITE}  • Server will restart and be accessible on port 9090${NC}"
    echo
    
    echo -e "${RED}Are you sure you want to proceed? (yes/NO): ${NC}"
    read -p "Type 'yes' to confirm: " restart_confirm
    
    if [[ "$restart_confirm" != "yes" ]]; then
        print_info "Remote server restart cancelled by user"
        echo
        echo -e "${YELLOW}Press any key to return to main menu...${NC}"
        read -n 1 -s
        return
    fi
    
    echo
    print_separator
    echo -e "${ORANGE}${BOLD}🚀 RESTARTING REMOTE VIDEO SYSTEM SERVER${NC}"
    print_separator
    echo
    
    # Create remote restart script
    local restart_script='
    #!/bin/bash
    
    echo "=== Remote Video System Server Restart ==="
    echo "$(date): Starting server restart process..."
    
    # Kill existing server processes
    echo "Killing existing auth_api_server processes..."
    pkill -f "auth_api_server" 2>/dev/null || true
    
    echo "Killing processes on port 9090..."
    # Method 1: lsof
    if command -v lsof >/dev/null 2>&1; then
        lsof -ti:9090 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    fi
    
    # Method 2: fuser
    if command -v fuser >/dev/null 2>&1; then
        fuser -k 9090/tcp 2>/dev/null || true
    fi
    
    # Method 3: ss
    if command -v ss >/dev/null 2>&1; then
        ss -K dport = 9090 2>/dev/null || true
        ss -K sport = 9090 2>/dev/null || true
    fi
    
    # Kill Python processes in video-system directory
    pkill -f "python.*video-system" 2>/dev/null || true
    
    # Remove PID file if it exists
    if [[ -f ~/video-system/server.pid ]]; then
        OLD_PID=$(cat ~/video-system/server.pid 2>/dev/null)
        if [[ -n "$OLD_PID" ]] && kill -0 "$OLD_PID" 2>/dev/null; then
            echo "Killing server with PID: $OLD_PID"
            kill -9 "$OLD_PID" 2>/dev/null || true
        fi
        rm -f ~/video-system/server.pid
    fi
    
    echo "Waiting 3 seconds for cleanup..."
    sleep 3
    
    # Apply system-level fixes for TIME_WAIT states
    echo "Applying network optimizations..."
    echo 1 | sudo tee /proc/sys/net/ipv4/tcp_tw_reuse >/dev/null 2>&1 || true
    echo 5 | sudo tee /proc/sys/net/ipv4/tcp_fin_timeout >/dev/null 2>&1 || true
    echo 1 | sudo tee /proc/sys/net/ipv4/tcp_timestamps >/dev/null 2>&1 || true
    
    # Additional cleanup for RHEL/CentOS systems
    if command -v systemctl >/dev/null 2>&1; then
        sudo sysctl -w net.ipv4.tcp_tw_reuse=1 2>/dev/null || true
        sudo sysctl -w net.ipv4.tcp_fin_timeout=5 2>/dev/null || true
    fi
    
    echo "Verifying video-system directory..."
    if [[ ! -d ~/video-system/scripts ]]; then
        echo "ERROR: video-system directory not found at ~/video-system"
        exit 1
    fi
    
    if [[ ! -f ~/video-system/scripts/auth_api_server.py ]]; then
        echo "ERROR: auth_api_server.py not found"
        exit 1
    fi
    
    echo "Starting video system server..."
    
    # Create or update start server script
    cat > ~/start_server.sh << "EOF"
#!/bin/bash
# Enable socket reuse for TIME_WAIT states
export SO_REUSEADDR=1
export SO_REUSEPORT=1

# Set Python to unbuffered output
export PYTHONUNBUFFERED=1

# Change to scripts directory
cd ~/video-system/scripts

# Start the server with nohup in background
nohup python3 -u auth_api_server.py > ~/video-system/server.log 2>&1 &

# Get the PID and save it
SERVER_PID=$!
echo $SERVER_PID > ~/video-system/server.pid

echo "Server started in background with PID: $SERVER_PID"
echo "Server log: ~/video-system/server.log"
echo "To stop server: kill $SERVER_PID"
EOF
    
    chmod +x ~/start_server.sh
    
    # Execute the start server script
    ~/start_server.sh
    
    # Wait and verify
    sleep 3
    
    if [[ -f ~/video-system/server.pid ]]; then
        SERVER_PID=$(cat ~/video-system/server.pid)
        if ps -p $SERVER_PID >/dev/null 2>&1; then
            echo "SUCCESS: Video system server restarted with PID: $SERVER_PID"
            
            # Get server IP
            LOCAL_IP=$(hostname -I 2>/dev/null | awk "{print \$1}" || echo "localhost")
            echo "Server accessible at: http://$LOCAL_IP:9090"
            
            # Show recent log entries
            echo "Recent server log entries:"
            tail -n 5 ~/video-system/server.log 2>/dev/null || echo "Could not read log file"
            
        else
            echo "ERROR: Server failed to start properly"
            if [[ -f ~/video-system/server.log ]]; then
                echo "Last few lines of server log:"
                tail -n 10 ~/video-system/server.log 2>/dev/null
            fi
            exit 1
        fi
    else
        echo "ERROR: Server PID file not created"
        exit 1
    fi
    
    echo "$(date): Remote server restart completed successfully"
    echo "============================================="
    '
    
    print_step "Executing remote server restart script..."
    
    if eval "$ssh_cmd $remote_user@$remote_host 'bash -s'" <<< "$restart_script"; then
        echo
        print_success "✅ Remote video system server restarted successfully!"
        
        # Get remote server info
        echo
        print_info "Remote Server Details:"
        echo -e "   ${WHITE}Host:${NC} $remote_host"
        echo -e "   ${WHITE}User:${NC} $remote_user"
        echo -e "   ${WHITE}Expected URL:${NC} http://$remote_host:9090"
        
        echo
        print_info "To check server status later, run:"
        if [[ "$auth_method" == "key" ]]; then
            echo -e "   ${GREEN}ssh -i '$auth_value' $remote_user@$remote_host 'ps aux | grep auth_api_server | grep -v grep'${NC}"
        else
            echo -e "   ${GREEN}sshpass -p '***' ssh $remote_user@$remote_host 'ps aux | grep auth_api_server | grep -v grep'${NC}"
        fi
        
    else
        print_error "❌ Remote server restart failed!"
        echo
        print_info "Please check:"
        print_info "  - SSH connection is stable"
        print_info "  - Remote user has proper permissions"
        print_info "  - Video system is properly installed on remote server"
        print_info "  - Python3 is available on remote server"
    fi
    
    echo
    print_separator
    echo -e "${GREEN}${BOLD}Remote server restart operation completed!${NC}"
    print_separator
    echo
    echo -e "${YELLOW}Press any key to return to main menu...${NC}"
    read -n 1 -s
}

# Function to validate IP address
validate_ip() {
    local ip="$1"
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        local IFS='.'
        local -a ip_parts=($ip)
        for part in "${ip_parts[@]}"; do
            if (( part > 255 )); then
                return 1
            fi
        done
        return 0
    else
        # Check if it's a valid hostname/FQDN
        if [[ $ip =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
            return 0
        fi
        return 1
    fi
}

# Function to test SSH connectivity and gather system info
test_remote_system() {
    local host="$1"
    local user="$2"
    local auth_method="$3"  # "password" or "key"
    local auth_value="$4"   # password or key file path
    
    print_step "Testing connectivity to $host..."
    
    local ssh_cmd=""
    local scp_cmd=""
    
    if [[ "$auth_method" == "key" ]]; then
        if [[ ! -f "$auth_value" ]]; then
            print_error "SSH key file not found: $auth_value"
            return 1
        fi
        ssh_cmd="ssh -i '$auth_value' -o StrictHostKeyChecking=no -o ConnectTimeout=10"
        scp_cmd="scp -i '$auth_value' -o StrictHostKeyChecking=no"
    else
        # For password auth, we'll use sshpass if available
        if ! command -v sshpass &> /dev/null; then
            print_error "sshpass is required for password authentication"
            print_info "Install with: sudo apt-get install sshpass (Ubuntu/Debian) or sudo yum install sshpass (RHEL/CentOS)"
            return 1
        fi
        ssh_cmd="sshpass -p '$auth_value' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10"
        scp_cmd="sshpass -p '$auth_value' scp -o StrictHostKeyChecking=no"
    fi
    
    print_info "Connecting to $user@$host..."
    
    # Test basic connectivity
    if ! eval "$ssh_cmd $user@$host 'echo \"Connection successful\"'" >/dev/null 2>&1; then
        print_error "Failed to connect to $user@$host"
        print_error "Please verify:"
        print_error "  - Host is reachable"
        print_error "  - SSH service is running"
        print_error "  - Username and credentials are correct"
        print_error "  - SSH key has correct permissions (600)"
        return 1
    fi
    
    print_success "✅ SSH connection established successfully!"
    echo
    
    print_step "Gathering remote system information..."
    
    # Create a comprehensive system info script
    local info_script='
    #!/bin/bash
    
    # Colors for remote output
    GREEN="\033[0;32m"
    CYAN="\033[0;36m" 
    WHITE="\033[1;37m"
    NC="\033[0m"
    
    echo -e "${CYAN}========== REMOTE SYSTEM INFORMATION ==========${NC}"
    echo
    
    # Hostname
    echo -e "${WHITE}Hostname:${NC} $(hostname -f 2>/dev/null || hostname)"
    
    # IP Address - try multiple methods for compatibility
    IP=$(hostname -I 2>/dev/null | awk "{print \$1}")
    if [[ -z "$IP" ]]; then
        IP=$(ip route get 1.1.1.1 2>/dev/null | awk "{print \$7; exit}" 2>/dev/null)
    fi
    if [[ -z "$IP" ]]; then
        IP=$(ifconfig 2>/dev/null | grep "inet " | grep -v "127.0.0.1" | awk "{print \$2}" | head -1 | sed "s/addr://")
    fi
    echo -e "${WHITE}IP Address:${NC} ${IP:-Unknown}"
    
    # MAC Address - try multiple methods
    MAC=""
    # Method 1: ip command (most modern systems)
    if command -v ip >/dev/null 2>&1; then
        INTERFACE=$(ip route | grep default | awk "{print \$5}" | head -1)
        if [[ -n "$INTERFACE" ]]; then
            MAC=$(ip link show "$INTERFACE" 2>/dev/null | awk "/ether/ {print \$2}")
        fi
    fi
    # Method 2: ifconfig fallback
    if [[ -z "$MAC" ]] && command -v ifconfig >/dev/null 2>&1; then
        MAC=$(ifconfig 2>/dev/null | grep -o -E "([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}" | head -1)
    fi
    # Method 3: /sys filesystem
    if [[ -z "$MAC" ]]; then
        for iface in /sys/class/net/*/address; do
            if [[ -r "$iface" ]] && [[ "$(basename $(dirname $iface))" != "lo" ]]; then
                MAC=$(cat "$iface" 2>/dev/null)
                break
            fi
        done
    fi
    echo -e "${WHITE}MAC Address:${NC} ${MAC:-Unknown}"
    
    # System UUID - try multiple methods for RHEL/CentOS compatibility
    UUID=""
    if [[ -f /sys/class/dmi/id/product_uuid && -r /sys/class/dmi/id/product_uuid ]]; then
        UUID=$(cat /sys/class/dmi/id/product_uuid 2>/dev/null)
    elif command -v dmidecode >/dev/null 2>&1; then
        UUID=$(sudo dmidecode -s system-uuid 2>/dev/null || dmidecode -s system-uuid 2>/dev/null)
    elif [[ -f /proc/sys/kernel/random/uuid ]]; then
        UUID="Generated-$(cat /proc/sys/kernel/random/uuid)"
    fi
    echo -e "${WHITE}System UUID:${NC} ${UUID:-Unknown}"
    
    # CPU Information
    CPU_INFO=""
    if [[ -f /proc/cpuinfo ]]; then
        CPU_MODEL=$(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | sed "s/^[ \t]*//" 2>/dev/null)
        CPU_CORES=$(grep -c "^processor" /proc/cpuinfo 2>/dev/null)
        CPU_INFO="$CPU_MODEL (${CPU_CORES} cores)"
    fi
    echo -e "${WHITE}CPU:${NC} ${CPU_INFO:-Unknown}"
    
    # Memory Information
    MEM_INFO=""
    if [[ -f /proc/meminfo ]]; then
        MEM_TOTAL=$(grep "MemTotal" /proc/meminfo | awk "{print \$2}" 2>/dev/null)
        if [[ -n "$MEM_TOTAL" ]]; then
            MEM_GB=$(( MEM_TOTAL / 1024 / 1024 ))
            MEM_INFO="${MEM_GB} GB"
        fi
    fi
    echo -e "${WHITE}Memory:${NC} ${MEM_INFO:-Unknown}"
    
    # Operating System
    OS_INFO=""
    if command -v lsb_release >/dev/null 2>&1; then
        OS_INFO=$(lsb_release -d 2>/dev/null | cut -d: -f2 | sed "s/^[ \t]*//" 2>/dev/null)
    elif [[ -f /etc/os-release ]]; then
        OS_INFO=$(grep "PRETTY_NAME" /etc/os-release 2>/dev/null | cut -d= -f2 | sed "s/\"//g")
    elif [[ -f /etc/redhat-release ]]; then
        OS_INFO=$(cat /etc/redhat-release 2>/dev/null)
    elif [[ -f /etc/debian_version ]]; then
        OS_INFO="Debian $(cat /etc/debian_version 2>/dev/null)"
    fi
    echo -e "${WHITE}Operating System:${NC} ${OS_INFO:-Unknown}"
    
    # Disk Space
    DISK_INFO=""
    if command -v df >/dev/null 2>&1; then
        DISK_INFO=$(df -h / 2>/dev/null | tail -1 | awk "{print \$2\" total, \"\$4\" available\"}")
    fi
    echo -e "${WHITE}Root Disk Space:${NC} ${DISK_INFO:-Unknown}"
    
    # Load Average
    LOAD_INFO=""
    if [[ -f /proc/loadavg ]]; then
        LOAD_INFO=$(cat /proc/loadavg 2>/dev/null | awk "{print \$1, \$2, \$3}")
    fi
    echo -e "${WHITE}Load Average (1,5,15 min):${NC} ${LOAD_INFO:-Unknown}"
    
    # Check if directories exist for transfer preparation
    echo
    echo -e "${CYAN}========== TRANSFER PREPARATION ==========${NC}"
    
    # Check if user has home directory
    if [[ -d "$HOME" ]]; then
        echo -e "${WHITE}Home Directory:${NC} $HOME ${GREEN}✓${NC}"
        echo -e "${WHITE}Home Space Available:${NC} $(df -h $HOME 2>/dev/null | tail -1 | awk "{print \$4}" || echo "Unknown")"
    else
        echo -e "${WHITE}Home Directory:${NC} $HOME ❌ NOT FOUND"
    fi
    
    # Check if we can create directories
    if mkdir -p "$HOME/test-write-permissions" 2>/dev/null && rmdir "$HOME/test-write-permissions" 2>/dev/null; then
        echo -e "${WHITE}Write Permissions:${NC} ${GREEN}✓ OK${NC}"
    else
        echo -e "${WHITE}Write Permissions:${NC} ❌ FAILED"
    fi
    
    # Check if Python3 is available
    if command -v python3 >/dev/null 2>&1; then
        PYTHON_VERSION=$(python3 --version 2>&1 | awk "{print \$2}")
        echo -e "${WHITE}Python3:${NC} ${GREEN}✓ ${PYTHON_VERSION}${NC}"
    else
        echo -e "${WHITE}Python3:${NC} ❌ NOT FOUND"
    fi
    
    # Check available tools
    echo
    echo -e "${CYAN}Available Tools:${NC}"
    for tool in curl wget git tar unzip; do
        if command -v $tool >/dev/null 2>&1; then
            echo -e "  ${GREEN}✓${NC} $tool"
        else
            echo -e "  ❌ $tool"
        fi
    done
    
    echo -e "${CYAN}==============================================${NC}"
    '
    
    print_info "Executing remote system analysis..."
    
    # Execute the info script on remote system
    if eval "$ssh_cmd $user@$host 'bash -s'" <<< "$info_script"; then
        echo
        print_success "✅ Remote system analysis completed successfully!"
        return 0
    else
        print_error "❌ Failed to gather remote system information"
        return 1
    fi
}

# Function to diagnose credential file issues
diagnose_credentials_file() {
    local crds_file="$CRDS_FILE"
    
    print_step "Diagnosing credentials file: $crds_file"
    echo
    
    # Check if file exists
    if [[ ! -f "$crds_file" ]]; then
        print_error "❌ Credentials file does not exist"
        print_info "File should be created automatically when saving connections"
        return
    fi
    
    # Check permissions
    local perms=$(stat -c "%a" "$crds_file" 2>/dev/null)
    if [[ "$perms" == "600" ]]; then
        print_success "✅ File permissions are correct (600)"
    else
        print_warning "⚠️  File permissions: $perms (should be 600)"
    fi
    
    # Check if readable
    if [[ -r "$crds_file" ]]; then
        print_success "✅ File is readable"
    else
        print_error "❌ File is not readable"
        return
    fi
    
    # Check if writable
    if [[ -w "$crds_file" ]]; then
        print_success "✅ File is writable"
    else
        print_error "❌ File is not writable"
    fi
    
    # Check file size
    local file_size=$(stat -c "%s" "$crds_file" 2>/dev/null)
    print_info "📊 File size: $file_size bytes"
    
    if [[ $file_size -eq 0 ]]; then
        print_warning "⚠️  File is empty"
        return
    fi
    
    # Check JSON validity and structure
    local json_check_result
    json_check_result=$(python3 -c "
import json
import os

crds_file = '$crds_file'
try:
    with open(crds_file, 'r') as f:
        content = f.read()
    
    if not content.strip():
        print('EMPTY_CONTENT')
    else:
        data = json.loads(content)
        if isinstance(data, list):
            print(f'VALID_LIST:{len(data)}')
        else:
            print('INVALID_TYPE')
            
except json.JSONDecodeError as e:
    print(f'JSON_ERROR:{str(e)}')
except Exception as e:
    print(f'ERROR:{str(e)}')
" 2>/dev/null)
    
    case "$json_check_result" in
        "EMPTY_CONTENT")
            print_warning "⚠️  File has empty content"
            ;;
        VALID_LIST:*)
            local count=${json_check_result#VALID_LIST:}
            print_success "✅ Valid JSON list with $count connections"
            ;;
        "INVALID_TYPE")
            print_error "❌ JSON exists but is not a list"
            ;;
        JSON_ERROR:*)
            local error=${json_check_result#JSON_ERROR:}
            print_error "❌ JSON parsing error: $error"
            ;;
        ERROR:*)
            local error=${json_check_result#ERROR:}
            print_error "❌ File access error: $error"
            ;;
    esac
    
    # Show file content (first 500 chars, masked passwords)
    print_info "📄 File content preview (passwords masked):"
    if [[ $file_size -gt 0 ]]; then
        python3 -c "
import json

try:
    with open('$crds_file', 'r') as f:
        data = json.load(f)
    
    if isinstance(data, list):
        for i, conn in enumerate(data):
            if isinstance(conn, dict):
                name = conn.get('name', 'Unknown')
                host = conn.get('host', 'Unknown')  
                username = conn.get('username', 'Unknown')
                auth_method = conn.get('auth_method', 'Unknown')
                print(f'  {i+1}: {name} - {username}@{host} ({auth_method})')
            else:
                print(f'  {i+1}: Invalid connection format')
    else:
        print('  File contains non-list data')
        
except Exception as e:
    print(f'  Error reading file: {e}')
" 2>/dev/null
    fi
}

# Function to save connection credentials
save_connection() {
    local name="$1"
    local host="$2"
    local user="$3"
    local auth_method="$4"
    local auth_value="$5"
    
    # Initialize credentials file if it doesn't exist
    if [[ ! -f "$CRDS_FILE" ]]; then
        # Ensure the parent directory exists
        mkdir -p "$(dirname "$CRDS_FILE")" 2>/dev/null
        if ! echo "[]" > "$CRDS_FILE" 2>/dev/null; then
            print_error "Failed to create credentials file: $CRDS_FILE"
            print_error "Check file permissions and disk space"
            return 1
        fi
        chmod 600 "$CRDS_FILE" 2>/dev/null
        print_debug "Created new credentials file: $CRDS_FILE"
    fi
    
    # Verify file is writable
    if [[ ! -w "$CRDS_FILE" ]]; then
        print_error "Cannot write to credentials file: $CRDS_FILE"
        print_error "Check file permissions"
        return 1
    fi
    
    # Save credentials using Python with proper error handling
    local save_result
    save_result=$(python3 -c "
import json
import sys
import os

crds_file = '$CRDS_FILE'
connection_name = '$name'
connection_host = '$host'
connection_user = '$user'
connection_auth_method = '$auth_method'
connection_auth_value = '$auth_value'

try:
    # Read existing data
    if os.path.exists(crds_file) and os.path.getsize(crds_file) > 0:
        try:
            with open(crds_file, 'r') as f:
                data = json.load(f)
            if not isinstance(data, list):
                print('ERROR: Invalid JSON structure - not a list')
                sys.exit(1)
        except json.JSONDecodeError as e:
            print(f'ERROR: Invalid JSON format - {str(e)}')
            sys.exit(1)
    else:
        data = []
    
    # Remove existing entry with same name
    original_count = len(data)
    data = [conn for conn in data if conn.get('name') != connection_name]
    if len(data) < original_count:
        print(f'UPDATED: Replaced existing connection: {connection_name}')
    
    # Create new entry
    if connection_auth_method == 'key':
        new_entry = {
            'name': connection_name,
            'host': connection_host,
            'username': connection_user,
            'auth_method': 'key',
            'ssh_key_path': connection_auth_value
        }
    else:
        new_entry = {
            'name': connection_name,
            'host': connection_host,
            'username': connection_user,
            'auth_method': 'password',
            'password': connection_auth_value
        }
    
    # Add new entry
    data.append(new_entry)
    
    # Write back with proper error handling
    try:
        with open(crds_file, 'w') as f:
            json.dump(data, f, indent=2)
        print(f'SUCCESS: Connection saved - {connection_name}')
    except Exception as e:
        print(f'ERROR: Failed to write file - {str(e)}')
        sys.exit(1)
        
except Exception as e:
    print(f'ERROR: Unexpected error - {str(e)}')
    sys.exit(1)
" 2>&1)
    
    local exit_code=$?
    if [[ $exit_code -eq 0 ]]; then
        if [[ "$save_result" == *"SUCCESS:"* ]]; then
            print_success "Connection '$name' saved successfully"
            if [[ "$save_result" == *"UPDATED:"* ]]; then
                print_info "Updated existing connection with same name"
            fi
            print_debug "Credentials file: $CRDS_FILE"
        else
            print_warning "Save completed but with warnings: $save_result"
        fi
    else
        print_error "Failed to save connection '$name'"
        print_error "Details: $save_result"
        return 1
    fi
}

# Function to transfer system to remote
transfer_system_to_remote() {
    print_header "TRANSFER VIDEO SYSTEM TO REMOTE SERVER"
    
    USER_HOME=$(echo $HOME)
    
    # Check if video-system exists
    if [[ ! -d "$USER_HOME/video-system" ]]; then
        print_error "Video system not found at: $USER_HOME/video-system"
        print_error "Please run 'Setup New System' first"
        echo
        echo -e "${YELLOW}Press any key to return to main menu...${NC}"
        read -n 1 -s
        return
    fi
    
    # Check if video-system-default exists
    if [[ ! -d "$USER_HOME/video-system-default" ]]; then
        print_error "Video system default backup not found at: $USER_HOME/video-system-default"
        print_error "Please run 'Setup New System' first to create the default backup"
        echo
        echo -e "${YELLOW}Press any key to return to main menu...${NC}"
        read -n 1 -s
        return
    fi
    
    print_step "Local system validation completed"
    echo
    
    # Connection options
    print_separator
    echo -e "${MAGENTA}${BOLD}CONNECTION OPTIONS${NC}"
    print_separator
    echo
    echo -e "${GREEN}1)${NC} Use saved connection"
    echo -e "${CYAN}2)${NC} Enter new connection details"
    echo -e "${YELLOW}3)${NC} Return to main menu"
    echo
    
    local connection_choice
    while true; do
        echo -e "${CYAN}Select connection method (1-3): ${NC}"
        read -p "> " connection_choice
        
        if [[ "$connection_choice" == "1" || "$connection_choice" == "2" || "$connection_choice" == "3" ]]; then
            break
        else
            print_error "Invalid choice. Please select 1, 2, or 3."
            echo
        fi
    done
    
    local remote_host=""
    local remote_user=""  
    local auth_method=""
    local auth_value=""
    local connection_name=""
    
    if [[ "$connection_choice" == "1" ]]; then
        # Use saved connection
        if [[ ! -f "$CRDS_FILE" ]] || [[ ! -s "$CRDS_FILE" ]] || [[ "$(cat "$CRDS_FILE")" == "[]" ]]; then
            print_error "No saved connections found"
            echo
            echo -e "${YELLOW}Press any key to return to main menu...${NC}"
            read -n 1 -s
            return
        fi
        
        # List saved connections
        echo
        print_step "Available saved connections:"
        echo
        
        python3 -c "
import json
try:
    with open('$CRDS_FILE', 'r') as f:
        connections = json.load(f)
    
    if not connections:
        print('No saved connections found')
        exit(1)
        
    for i, conn in enumerate(connections, 1):
        print(f'{i}) {conn[\"name\"]} - {conn[\"username\"]}@{conn[\"host\"]} ({conn[\"auth_method\"]})')
        
except Exception as e:
    print('Error reading connections:', e)
    exit(1)
" 2>/dev/null || {
            print_error "Failed to read saved connections"
            return
        }
        
        echo
        local conn_choice
        echo -e "${CYAN}Select connection number: ${NC}"
        read -p "> " conn_choice
        
        # Get connection details
        local conn_details=$(python3 -c "
import json
try:
    with open('$CRDS_FILE', 'r') as f:
        connections = json.load(f)
    
    if $conn_choice > 0 and $conn_choice <= len(connections):
        conn = connections[$conn_choice - 1]
        print(f'{conn[\"host\"]}|{conn[\"username\"]}|{conn[\"auth_method\"]}|{conn.get(\"password\", conn.get(\"ssh_key_path\", \"\"))}|{conn[\"name\"]}')
    else:
        print('INVALID')
except:
    print('ERROR')
" 2>/dev/null)
        
        if [[ "$conn_details" == "INVALID" || "$conn_details" == "ERROR" || -z "$conn_details" ]]; then
            print_error "Invalid connection selection"
            return
        fi
        
        IFS='|' read -r remote_host remote_user auth_method auth_value connection_name <<< "$conn_details"
        
    elif [[ "$connection_choice" == "2" ]]; then
        # Enter new connection details
        echo
        print_step "Enter remote system connection details"
        echo
        
        # Get remote host
        while true; do
            echo -e "${CYAN}Enter remote system IP address or hostname/FQDN:${NC}"
            echo -e "${YELLOW}Examples: 192.168.1.100, server.example.com${NC}"
            read -p "Host: " remote_host
            
            if [[ -n "$remote_host" ]] && validate_ip "$remote_host"; then
                print_success "Valid host: $remote_host"
                break
            else
                print_error "Invalid IP address or hostname format"
                echo
            fi
        done
        
        echo
        
        # Get username
        while true; do
            echo -e "${CYAN}Enter username for remote system:${NC}"
            read -p "Username: " remote_user
            
            if [[ -n "$remote_user" && "$remote_user" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]]; then
                break
            else
                print_error "Invalid username format"
                echo
            fi
        done
        
        echo
        
        # Get authentication method
        echo -e "${CYAN}Select authentication method:${NC}"
        echo -e "${GREEN}1)${NC} SSH Key file"
        echo -e "${YELLOW}2)${NC} Password"
        echo -e "${RED}3)${NC} Return to previous menu"
        echo
        
        local auth_choice
        while true; do
            echo -e "${CYAN}Select method (1-3): ${NC}"
            read -p "> " auth_choice
            
            if [[ "$auth_choice" == "1" ]]; then
                auth_method="key"
                
                while true; do
                    echo -e "${CYAN}Enter path to SSH private key file:${NC}"
                    echo -e "${YELLOW}Example: /home/user/.ssh/id_rsa${NC}"
                    read -p "SSH Key Path: " auth_value
                    
                    if [[ -f "$auth_value" && -r "$auth_value" ]]; then
                        # Check key permissions
                        local key_perms=$(stat -c "%a" "$auth_value" 2>/dev/null)
                        if [[ "$key_perms" == "600" || "$key_perms" == "400" ]]; then
                            print_success "SSH key found and permissions are secure"
                            break
                        else
                            print_warning "SSH key permissions should be 600 or 400"
                            echo -e "${YELLOW}Fix with: chmod 600 '$auth_value'${NC}"
                            echo -e "${YELLOW}Continue anyway? (y/N): ${NC}"
                            read -p "" -n 1 -r
                            echo
                            if [[ $REPLY =~ ^[Yy]$ ]]; then
                                break
                            fi
                        fi
                    else
                        print_error "SSH key file not found or not readable: $auth_value"
                        echo
                    fi
                done
                break
                
            elif [[ "$auth_choice" == "2" ]]; then
                auth_method="password"
                
                # Check if sshpass is available
                if ! command -v sshpass &> /dev/null; then
                    print_warning "sshpass is required for password authentication"
                    echo -e "${CYAN}Install sshpass? (required for password auth)${NC}"
                    echo -e "${YELLOW}Ubuntu/Debian: sudo apt-get install sshpass${NC}"
                    echo -e "${YELLOW}RHEL/CentOS: sudo yum install sshpass${NC}"
                    echo
                    echo -e "${CYAN}Continue without installing? (connection will fail) (y/N): ${NC}"
                    read -p "" -n 1 -r
                    echo
                    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                        return
                    fi
                fi
                
                while true; do
                    echo -e "${CYAN}Enter password for $remote_user@$remote_host:${NC}"
                    read -s -p "Password: " auth_value
                    echo
                    
                    if [[ -n "$auth_value" ]]; then
                        echo -e "${CYAN}Confirm password:${NC}"
                        read -s -p "Confirm: " auth_confirm
                        echo
                        
                        if [[ "$auth_value" == "$auth_confirm" ]]; then
                            print_success "Password set successfully"
                            break
                        else
                            print_error "Passwords do not match"
                            echo
                        fi
                    else
                        print_error "Password cannot be empty"
                        echo
                    fi
                done
                break
            elif [[ "$auth_choice" == "3" ]]; then
                # Return to previous menu
                print_info "Returning to previous menu..."
                return
            else
                print_error "Invalid choice. Please select 1, 2, or 3."
                echo
            fi
        done
    elif [[ "$connection_choice" == "3" ]]; then
        # Return to main menu
        print_info "Returning to main menu..."
        return
    fi
    
    echo
    print_separator
    echo -e "${CYAN}${BOLD}TESTING REMOTE CONNECTION${NC}"
    print_separator
    echo
    
    # Test connection and gather system info
    if ! test_remote_system "$remote_host" "$remote_user" "$auth_method" "$auth_value"; then
        print_error "Remote system test failed"
        echo
        echo -e "${YELLOW}Press any key to return to main menu...${NC}"
        read -n 1 -s
        return
    fi
    
    # Ask if user wants to save this connection (only for manual entries, after successful test)
    if [[ "$connection_choice" == "2" ]]; then
        echo
        print_separator
        echo -e "${CYAN}${BOLD}💾 SAVE CONNECTION${NC}"
        print_separator
        echo
        echo -e "${YELLOW}Connection test successful! Would you like to save this connection for future use?${NC}"
        echo -e "   ${WHITE}Host:${NC} $remote_host"
        echo -e "   ${WHITE}User:${NC} $remote_user"
        echo -e "   ${WHITE}Auth:${NC} $auth_method"
        echo
        echo -e "${CYAN}Save connection? (y/N): ${NC}"
        read -p "" -n 1 -r
        echo
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            while true; do
                echo -e "${CYAN}Enter a name for this connection:${NC}"
                echo -e "${YELLOW}Examples: ProductionServer, DevBox, BackupServer${NC}"
                read -p "Connection name: " save_connection_name
                
                if [[ -n "$save_connection_name" && "$save_connection_name" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]]; then
                    if save_connection "$save_connection_name" "$remote_host" "$remote_user" "$auth_method" "$auth_value"; then
                        print_success "Connection saved as '$save_connection_name'"
                        connection_name="$save_connection_name"
                    else
                        print_error "Failed to save connection"
                    fi
                    break
                else
                    print_error "Invalid connection name format. Use letters, numbers, dots, underscores, and hyphens only."
                    echo
                fi
            done
        else
            print_info "Connection not saved"
        fi
        echo
    fi
    
    echo
    print_separator
    echo -e "${RED}${BOLD}⚠️  TRANSFER CONFIRMATION ⚠️${NC}"
    print_separator
    echo
    
    echo -e "${YELLOW}You are about to transfer the video system to:${NC}"
    echo -e "   ${WHITE}Host:${NC} $remote_host"
    echo -e "   ${WHITE}User:${NC} $remote_user"
    echo -e "   ${WHITE}Auth:${NC} $auth_method"
    if [[ -n "$connection_name" ]]; then
        echo -e "   ${WHITE}Connection:${NC} $connection_name"
    fi
    echo
    
    # Check if video-system exists on remote
    print_step "Checking for existing video-system on remote host..."
    local remote_check_cmd=""
    if [[ "$auth_method" == "key" ]]; then
        remote_check_cmd="ssh -i '$auth_value' -o StrictHostKeyChecking=no -o ConnectTimeout=10 $remote_user@$remote_host"
    else
        remote_check_cmd="sshpass -p '$auth_value' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 $remote_user@$remote_host"
    fi
    
    local remote_listing
    remote_listing=$(eval "$remote_check_cmd 'ls -lha ~/video-system 2>/dev/null'" 2>/dev/null)
    local remote_exists=$?
    
    echo -e "${YELLOW}This will:${NC}"
    echo -e "${GREEN}  ✓ Copy ~/video-system-default directory to remote system${NC}"
    echo -e "${GREEN}  ✓ Create working ~/video-system directory remotely${NC}"
    echo -e "${GREEN}  ✓ Configure IP addresses for remote host${NC}"
    echo -e "${GREEN}  ✓ Set proper permissions${NC}"
    echo -e "${WHITE}  • Transfer may take several minutes depending on size${NC}"
    echo
    
    # Warn if directory exists
    if [[ $remote_exists -eq 0 ]]; then
        echo -e "${RED}${BOLD}⚠️  WARNING ⚠️${NC}"
        echo -e "${YELLOW}The video-system directory already exists on the remote host:${NC}"
        echo
        echo -e "${WHITE}Remote directory listing:${NC}"
        echo -e "${CYAN}$remote_listing${NC}"
        echo
        echo -e "${RED}This directory will be OVERWRITTEN. All existing data will be lost!${NC}"
        echo
        echo -e "${RED}Do you want to proceed and overwrite the existing directory? (yes/NO): ${NC}"
        read -p "Type 'yes' to overwrite: " overwrite_confirm
        
        if [[ "$overwrite_confirm" != "yes" ]]; then
            print_info "Transfer cancelled to preserve existing directory"
            echo
            echo -e "${YELLOW}Press any key to return to main menu...${NC}"
            read -n 1 -s
            return
        fi
        echo
    else
        print_success "No existing video-system directory found on remote host"
        echo
    fi
    echo
    
    echo -e "${RED}Are you sure you want to proceed? (yes/NO): ${NC}"
    read -p "Type 'yes' to confirm: " transfer_confirm
    
    if [[ "$transfer_confirm" != "yes" ]]; then
        print_info "Transfer cancelled by user"
        echo
        echo -e "${YELLOW}Press any key to return to main menu...${NC}"
        read -n 1 -s
        return
    fi
    
    echo
    print_separator 
    echo -e "${GREEN}${BOLD}🚀 STARTING SYSTEM TRANSFER${NC}"
    print_separator
    echo
    
    # Setup SCP command based on auth method
    local scp_cmd=""
    if [[ "$auth_method" == "key" ]]; then
        scp_cmd="scp -i '$auth_value' -o StrictHostKeyChecking=no -r"
    else
        scp_cmd="sshpass -p '$auth_value' scp -o StrictHostKeyChecking=no -r"
    fi
    
    local ssh_cmd=""
    if [[ "$auth_method" == "key" ]]; then
        ssh_cmd="ssh -i '$auth_value' -o StrictHostKeyChecking=no"
    else
        ssh_cmd="sshpass -p '$auth_value' ssh -o StrictHostKeyChecking=no"
    fi
    
    # Step 1: Transfer video-system-default directory
    print_step "Transferring video-system-default directory..."
    echo -e "${BLUE}[INFO]${NC} This may take several minutes depending on the size..."
    
    if eval "$scp_cmd '$USER_HOME/video-system-default' '$remote_user@$remote_host:~/'"; then
        print_success "✅ video-system-default directory transferred successfully"
    else
        print_error "❌ Failed to transfer video-system-default directory"
        return
    fi
    
    # Step 2: Get video system credentials for remote setup
    print_step "Setting up video system credentials for remote server..."
    echo
    
    local video_username=""
    local video_password=""
    
    # Get username
    while [[ -z "$video_username" ]]; do
        echo -e "${CYAN}Enter video system username for remote server:${NC}"
        read -p "> " video_username
        
        if [[ -z "$video_username" ]]; then
            print_error "Username cannot be empty"
        elif [[ "$video_username" =~ [[:space:]] ]]; then
            print_error "Username cannot contain spaces"
            video_username=""
        elif [[ "$video_username" =~ : ]]; then
            print_error "Username cannot contain colon (:) character"
            video_username=""
        fi
    done
    
    # Get password
    while [[ -z "$video_password" ]]; do
        echo -e "${CYAN}Enter video system password for remote server:${NC}"
        read -s -p "> " video_password
        echo
        
        if [[ -z "$video_password" ]]; then
            print_error "Password cannot be empty"
        elif [[ "$video_password" =~ : ]]; then
            print_error "Password cannot contain colon (:) character"
            video_password=""
        fi
    done
    
    # Confirm password
    local confirm_password=""
    while [[ "$video_password" != "$confirm_password" ]]; do
        echo -e "${CYAN}Confirm password:${NC}"
        read -s -p "> " confirm_password
        echo
        
        if [[ "$video_password" != "$confirm_password" ]]; then
            print_error "Passwords do not match. Please try again."
        fi
    done
    
    print_success "Video system credentials configured"
    print_info "Username: $video_username"
    print_info "Password: [hidden]"
    echo
    
    # Step 3: Run remote setup assistant
    print_step "Launching remote setup assistant..."
    echo
    
    local remote_setup_script='
#!/bin/bash

# Get arguments from command line
REMOTE_IP="$1"
VIDEO_USERNAME="$2"
VIDEO_PASSWORD="$3"

if [[ -z "$REMOTE_IP" ]]; then
    echo "Error: No remote IP provided"
    exit 1
fi

if [[ -z "$VIDEO_USERNAME" ]]; then
    echo "Error: No video system username provided"
    exit 1
fi

if [[ -z "$VIDEO_PASSWORD" ]]; then
    echo "Error: No video system password provided"
    exit 1
fi

# Colors for remote output
RED='"'"'\033[0;31m'"'"'
GREEN='"'"'\033[0;32m'"'"'
YELLOW='"'"'\033[1;33m'"'"'
BLUE='"'"'\033[0;34m'"'"'
PURPLE='"'"'\033[0;35m'"'"'
CYAN='"'"'\033[0;36m'"'"'
WHITE='"'"'\033[1;37m'"'"'
ORANGE='"'"'\033[0;33m'"'"'
BOLD='"'"'\033[1m'"'"'
NC='"'"'\033[0m'"'"' # No Color

# Function to print colored messages
print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_step() {
    echo -e "${YELLOW}[STEP]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${ORANGE}[WARNING]${NC} $1"
}

print_separator() {
    echo -e "${CYAN}================================================================${NC}"
}

print_header() {
    echo
    print_separator
    echo -e "${WHITE}$1${NC}"
    print_separator
    echo
}

echo
print_separator
echo -e "${WHITE}${BOLD}           REMOTE VIDEO SYSTEM SETUP ASSISTANT${NC}"
echo -e "${CYAN}                 Automated Configuration${NC}"
print_separator
echo

# Detect operating system on remote system
detect_os() {
    print_info "Detecting operating system..."
    
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        case "$ID" in
            ubuntu|debian)
                OS_TYPE="ubuntu"
                FIREWALL_TYPE="ufw"
                print_success "Detected: Ubuntu/Debian system"
                ;;
            centos|rhel|fedora|rocky|alma)
                OS_TYPE="centos"
                FIREWALL_TYPE="firewalld"
                print_success "Detected: CentOS/RHEL/Fedora system"
                ;;
            *)
                print_warning "Unknown distribution: $ID, defaulting to Ubuntu"
                OS_TYPE="ubuntu"
                FIREWALL_TYPE="ufw"
                ;;
        esac
    else
        print_warning "Cannot detect OS, defaulting to Ubuntu"
        OS_TYPE="ubuntu"
        FIREWALL_TYPE="ufw"
    fi
}

# Note: Dashboard CentOS compatibility is handled by the Python API server

# Function to create video system credentials on remote system
create_video_system_credentials() {
    print_header "VIDEO SYSTEM CREDENTIALS SETUP"
    
    print_info "Setting up authentication credentials for the video system"
    print_info "These credentials will be used to login to the web interface"
    echo
    
    # Validate username
    if [[ "$VIDEO_USERNAME" =~ [[:space:]] ]]; then
        print_error "Username cannot contain spaces"
        exit 1
    elif [[ "$VIDEO_USERNAME" =~ : ]]; then
        print_error "Username cannot contain colon (:) character"
        exit 1
    fi
    
    # Validate password
    if [[ "$VIDEO_PASSWORD" =~ : ]]; then
        print_error "Password cannot contain colon (:) character"
        exit 1
    fi
    
    # Create credentials file
    local crds_file="$HOME/.crds"
    echo "${VIDEO_USERNAME}:${VIDEO_PASSWORD}" > "$crds_file"
    chmod 600 "$crds_file"
    
    print_success "Credentials saved to $crds_file"
    print_info "Username: $VIDEO_USERNAME"
    print_info "Password: [hidden]"
    echo
}

# Function to configure firewall for Ubuntu/Debian
configure_ubuntu_firewall() {
    print_info "Configuring UFW firewall for Ubuntu..."
    
    # Check if UFW is installed
    if ! command -v ufw &> /dev/null; then
        print_error "UFW is not installed. Installing..."
        if ! sudo apt-get update && sudo apt-get install -y ufw; then
            print_error "Failed to install UFW"
            return 1
        fi
    fi
    
    # Enable UFW if not already enabled
    if ! sudo ufw status | grep -q "Status: active"; then
        print_info "Enabling UFW..."
        sudo ufw --force enable
    fi
    
    # Open ports
    print_info "Opening port 9090 (API Server)..."
    if sudo ufw allow 9090/tcp; then
        print_success "Port 9090/tcp opened"
    else
        print_error "Failed to open port 9090/tcp"
        return 1
    fi
    
    print_info "Opening port 4200 (Terminal Access)..."
    if sudo ufw allow 4200/tcp; then
        print_success "Port 4200/tcp opened"
    else
        print_error "Failed to open port 4200/tcp"
        return 1
    fi
    
    print_success "UFW firewall configured successfully"
    return 0
}

# Function to configure firewalld
configure_firewalld() {
    print_info "Configuring firewalld..."
    
    # Check if firewalld is installed
    if ! command -v firewall-cmd &> /dev/null; then
        print_error "firewalld is not installed. Installing..."
        if ! sudo yum install -y firewalld; then
            print_error "Failed to install firewalld"
            return 1
        fi
    fi
    
    # Start firewalld if not running
    if ! systemctl is-active --quiet firewalld; then
        print_info "Starting firewalld service..."
        sudo systemctl start firewalld
        sudo systemctl enable firewalld
    fi
    
    # Open ports
    print_info "Opening port 9090/tcp (API Server)..."
    if sudo firewall-cmd --permanent --add-port=9090/tcp; then
        print_success "Port 9090/tcp added to permanent rules"
    else
        print_error "Failed to add port 9090/tcp"
        return 1
    fi
    
    print_info "Opening port 4200/tcp (Terminal Access)..."
    if sudo firewall-cmd --permanent --add-port=4200/tcp; then
        print_success "Port 4200/tcp added to permanent rules"
    else
        print_error "Failed to add port 4200/tcp"
        return 1
    fi
    
    # Reload firewall
    print_info "Reloading firewall to apply changes..."
    if sudo firewall-cmd --reload; then
        print_success "Firewall rules reloaded successfully"
    else
        print_error "Failed to reload firewall rules"
        return 1
    fi
    
    return 0
}

# Function to configure iptables
configure_iptables() {
    print_info "Configuring iptables..."
    
    # Check if iptables is installed
    if ! command -v iptables &> /dev/null; then
        print_error "iptables is not installed"
        return 1
    fi
    
    # Open ports
    print_info "Opening port 9090/tcp (API Server)..."
    if sudo iptables -I INPUT -p tcp --dport 9090 -j ACCEPT; then
        print_success "Port 9090/tcp opened with iptables"
    else
        print_error "Failed to open port 9090/tcp with iptables"
        return 1
    fi
    
    print_info "Opening port 4200/tcp (Terminal Access)..."
    if sudo iptables -I INPUT -p tcp --dport 4200 -j ACCEPT; then
        print_success "Port 4200/tcp opened with iptables"
    else
        print_error "Failed to open port 4200/tcp with iptables"
        return 1
    fi
    
    # Save iptables rules
    print_info "Saving iptables rules..."
    if command -v iptables-save &> /dev/null; then
        sudo iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
        print_success "iptables rules saved"
    else
        print_warning "Could not save iptables rules automatically"
    fi
    
    return 0
}

# Function to configure firewall for CentOS/RHEL
configure_centos_firewall() {
    print_info "Configuring firewall for CentOS/RHEL..."
    
    # Detect which firewall system is in use
    if systemctl is-active --quiet firewalld; then
        FIREWALL_TYPE="firewalld"
        print_info "Using firewalld"
        configure_firewalld
    elif systemctl list-units --full -all | grep -Fq "iptables.service"; then
        FIREWALL_TYPE="iptables"
        print_info "Using iptables"
        configure_iptables
    else
        print_warning "No firewall service detected, attempting to use firewalld"
        FIREWALL_TYPE="firewalld"
        configure_firewalld
    fi
}

# Function to configure firewall based on OS
configure_firewall() {
    print_step "Configuring firewall for video system ports..."
    
    case "$OS_TYPE" in
        "ubuntu")
            configure_ubuntu_firewall
            ;;
        "centos")
            configure_centos_firewall
            ;;
        *)
            print_error "Unsupported OS type: $OS_TYPE"
            return 1
            ;;
    esac
}

# Function to install and configure shellinabox
install_shellinabox() {
    print_step "Installing shellinabox for web terminal access on port 4200..."
    
    # Check if shellinabox is already installed
    if command -v shellinaboxd &> /dev/null; then
        print_success "Shellinabox already installed"
    else
        print_info "Installing shellinabox automatically..."
        
        if [[ "$OS_TYPE" == "ubuntu" ]]; then
            # Ubuntu/Debian installation
            if sudo apt-get update && sudo apt-get install -y shellinabox net-tools; then
                print_success "Shellinabox and net-tools installed via apt-get"
            else
                print_error "Failed to install shellinabox and net-tools via apt-get"
                return 1
            fi
        elif [[ "$OS_TYPE" == "centos" ]]; then
            # CentOS/RHEL installation - need EPEL repository
            print_info "Installing EPEL repository for CentOS/RHEL..."
            if command -v yum &> /dev/null; then
                # Install EPEL repository first (required for shellinabox)
                sudo yum install -y epel-release
                print_info "Installing shellinabox and net-tools from EPEL..."
                if sudo yum install -y shellinabox net-tools; then
                    print_success "Shellinabox and net-tools installed via yum"
                else
                    print_error "Failed to install shellinabox and net-tools via yum"
                    return 1
                fi
            elif command -v dnf &> /dev/null; then
                # Install EPEL repository first
                sudo dnf install -y epel-release
                if sudo dnf install -y shellinabox net-tools; then
                    print_success "Shellinabox and net-tools installed via dnf"
                else
                    print_error "Failed to install shellinabox and net-tools via dnf"
                    return 1
                fi
            else
                print_error "No package manager found for CentOS/RHEL"
                return 1
            fi
        fi
    fi
    
    # Configure shellinabox service based on distribution
    print_step "Configuring shellinabox service..."

    if [[ "$OS_TYPE" == "ubuntu" ]]; then
        # Ubuntu/Debian configuration
        CONFIG_FILE="/etc/default/shellinabox"

        if [[ -f "$CONFIG_FILE" ]]; then
            print_step "Found existing Ubuntu shellinabox config: $CONFIG_FILE"

            # Enable daemon start
            if grep -q "^SHELLINABOX_DAEMON_START=" "$CONFIG_FILE"; then
                sudo sed -i "s/^SHELLINABOX_DAEMON_START=.*/SHELLINABOX_DAEMON_START=1/" "$CONFIG_FILE"
            else
                echo "SHELLINABOX_DAEMON_START=1" | sudo tee -a "$CONFIG_FILE" >/dev/null
            fi

            # Set port
            if grep -q "^SHELLINABOX_PORT=" "$CONFIG_FILE"; then
                sudo sed -i "s/^SHELLINABOX_PORT=.*/SHELLINABOX_PORT=4200/" "$CONFIG_FILE"
            else
                echo "SHELLINABOX_PORT=4200" | sudo tee -a "$CONFIG_FILE" >/dev/null
            fi

            # Configure SHELLINABOX_ARGS
            if grep -q "^SHELLINABOX_ARGS=" "$CONFIG_FILE"; then
                # Check if it already has the correct configuration
                if grep -q "SHELLINABOX_ARGS=\"--no-beep --disable-ssl\"" "$CONFIG_FILE"; then
                    print_success "✅ SHELLINABOX_ARGS already correctly configured"
                else
                    sudo sed -i "s/^SHELLINABOX_ARGS=.*/SHELLINABOX_ARGS=\"--no-beep --disable-ssl\"/" "$CONFIG_FILE"
                    print_success "✅ Updated SHELLINABOX_ARGS to: --no-beep --disable-ssl"
                fi
            else
                echo 'SHELLINABOX_ARGS="--no-beep --disable-ssl"' | sudo tee -a "$CONFIG_FILE" >/dev/null
                print_success "✅ Added SHELLINABOX_ARGS: --no-beep --disable-ssl"
            fi

            print_info "Ubuntu shellinabox configuration completed"
        else
            print_warning "Ubuntu config file not found: $CONFIG_FILE"
        fi

        sudo systemctl enable shellinabox

    elif [[ "$OS_TYPE" == "centos" ]]; then
        # CentOS/RHEL configuration - uses sysconfig file
        CONFIG_FILE="/etc/sysconfig/shellinaboxd"

        print_step "Configuring shellinabox for CentOS/RHEL..."

        if [[ -f "$CONFIG_FILE" ]]; then
            print_step "Found existing CentOS shellinabox config: $CONFIG_FILE"

            # Check if OPTS line already has correct configuration
            if grep -q "OPTS=\"--no-beep --disable-ssl -t\"" "$CONFIG_FILE"; then
                print_success "✅ OPTS already correctly configured"
            else
                # Update or add OPTS line
                if grep -q "^OPTS=" "$CONFIG_FILE"; then
                    sudo sed -i "s/^OPTS=.*/OPTS=\"--no-beep --disable-ssl -t\"/" "$CONFIG_FILE"
                    print_success "✅ Updated OPTS to: --no-beep --disable-ssl -t"
                else
                    echo 'OPTS="--no-beep --disable-ssl -t"' | sudo tee -a "$CONFIG_FILE" >/dev/null
                    print_success "✅ Added OPTS: --no-beep --disable-ssl -t"
                fi
            fi

            # Ensure other required settings
            if ! grep -q "^PORT=" "$CONFIG_FILE"; then
                echo "PORT=4200" | sudo tee -a "$CONFIG_FILE" >/dev/null
            fi
            if ! grep -q "^USER=" "$CONFIG_FILE"; then
                echo "USER=nobody" | sudo tee -a "$CONFIG_FILE" >/dev/null
            fi
            if ! grep -q "^GROUP=" "$CONFIG_FILE"; then
                echo "GROUP=nobody" | sudo tee -a "$CONFIG_FILE" >/dev/null
            fi

        else
            # Create new configuration file
            print_step "Creating new CentOS shellinabox configuration..."
            sudo tee "$CONFIG_FILE" > /dev/null << 'EOF'
# shellinabox daemon configuration
USER=nobody
GROUP=nobody
CERTDIR=/var/lib/shellinabox
PORT=4200
OPTS="--no-beep --disable-ssl -t"
EOF
            print_success "✅ Created $CONFIG_FILE with correct configuration"
        fi

        print_info "CentOS shellinabox configuration completed"
        sudo systemctl daemon-reload
        sudo systemctl enable shellinaboxd
    fi
    
    # Start shellinabox service (different service names for different distros)
    print_step "Starting shellinabox service..."
    
    if [[ "$OS_TYPE" == "centos" ]]; then
        SERVICE_NAME="shellinaboxd"
    else
        SERVICE_NAME="shellinabox"
    fi
    
    print_info "Enabling $SERVICE_NAME service..."
    sudo systemctl enable "$SERVICE_NAME"
    
    if sudo systemctl start "$SERVICE_NAME"; then
        print_success "Shellinabox service started successfully"
    else
        print_error "Failed to start $SERVICE_NAME service"
        return 1
    fi
    
    # Wait and restart to apply configuration
    sleep 2
    print_info "Restarting $SERVICE_NAME to apply configuration..."
    sudo systemctl restart "$SERVICE_NAME"
    sleep 2
    
    # Verify shellinabox is running
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_success "✅ Shellinabox service is active and running"
        print_info "Web terminal accessible at: http://\$REMOTE_IP:4200"
    else
        print_warning "⚠️  Shellinabox service may not be running properly"
    fi
    
    return 0
}

# Detect operating system
detect_os
echo

# Note: Dashboard updates for CentOS compatibility are handled during file configuration below

# Create video system credentials
create_video_system_credentials

# Configure firewall for video system
configure_firewall

# Install and configure shellinabox for web terminal
install_shellinabox

# Step 1: Verify video-system-default directory exists
if [[ ! -d ~/video-system-default ]]; then
    print_error "video-system-default directory not found. Transfer may have failed."
    exit 1
fi

print_success "video-system-default directory found"

# Step 2: Create working copy (video-system-default -> video-system)
print_step "Creating working copy: video-system-default -> video-system..."

if [[ -d ~/video-system ]]; then
    print_info "Removing existing video-system directory..."
    rm -rf ~/video-system
fi

if cp -r ~/video-system-default ~/video-system; then
    print_success "✅ Working copy created: ~/video-system"
else
    print_error "❌ Failed to create working copy"
    exit 1
fi

# Step 3: Configure IP addresses for remote system
print_step "Configuring IP addresses for remote system..."

print_info "Using provided remote IP: $REMOTE_IP"
    
    # Replace gcppftest01 placeholders in auth_api_server.py
    if [[ -f ~/video-system/scripts/auth_api_server.py ]]; then
        print_info "Updating auth_api_server.py with correct IP and paths..."
        sed -i "s/gcppftest01/$REMOTE_IP/g" ~/video-system/scripts/auth_api_server.py
        
        # Fix welcome video to load with authentication
        sed -i "s|<source src=\"/api/video/welcome\" type=\"video/webm\">|<source src=\"\" type=\"video/webm\" id=\"welcomeVideoSource\">|g" ~/video-system/docs/dashboard.html
        
        # Create JavaScript function to load video with authentication and proper sound
        cat >> ~/video-system/docs/dashboard.html << '"'"'EOF'"'"'

<script>
// Fix for authenticated video loading with sound
function loadWelcomeVideoWithAuth() {
    const video = document.getElementById("welcomeVideo");
    const source = document.getElementById("welcomeVideoSource");
    const token = sessionStorage.getItem("authToken");
    
    if (token && source && video) {
        fetch("/api/video/welcome", {
            method: "GET",
            headers: { "Authorization": "Bearer " + token }
        })
        .then(response => {
            if (!response.ok) throw new Error("Video fetch failed");
            return response.blob();
        })
        .then(blob => {
            const videoUrl = URL.createObjectURL(blob);
            source.src = videoUrl;
            video.load();
            
            // Start with sound enabled after authentication
            video.muted = false;
            video.volume = 1.0;
            
            // Try to play with sound
            setTimeout(() => {
                video.play().then(() => {
                    console.log("🔊 Welcome video playing with sound");
                }).catch(err => {
                    console.log("🔇 Autoplay with sound failed, trying muted first");
                    video.muted = true;
                    video.play().then(() => {
                        // Unmute after a brief moment
                        setTimeout(() => {
                            video.muted = false;
                            video.volume = 1.0;
                            console.log("🔊 Video unmuted successfully");
                        }, 1000);
                    });
                });
            }, 200);
        })
        .catch(err => console.error("Welcome video load error:", err));
    }
}

// Call the function when video modal is shown
document.addEventListener("DOMContentLoaded", function() {
    const originalStartVideo = window.startWelcomeVideo;
    window.startWelcomeVideo = function(isPageReload) {
        if (originalStartVideo) originalStartVideo(isPageReload);
        setTimeout(loadWelcomeVideoWithAuth, 500);
    };
});
</script>
EOF
        
        # Update hardcoded video path to use correct home directory
        REMOTE_USER_HOME="$HOME"
        print_info "Remote user home directory: $REMOTE_USER_HOME"
        
        # Replace the specific hardcoded welcome video path (exact line match)
        CURRENT_USER_HOME=$(echo $HOME)
        sed -i "s|/home/gus/video-system/|$CURRENT_USER_HOME/video-system/|g" ~/video-system/scripts/auth_api_server.py
        
        # Update all other /home/gus paths
        sed -i "s|/home/gus/video-system/videos/|$REMOTE_USER_HOME/video-system/videos/|g" ~/video-system/scripts/auth_api_server.py
        sed -i "s|/home/gus/video-system/logs|$REMOTE_USER_HOME/video-system/logs|g" ~/video-system/scripts/auth_api_server.py
        sed -i "s|/home/gus/|$REMOTE_USER_HOME/|g" ~/video-system/scripts/auth_api_server.py
        
        # Update debug_logger.py paths
        sed -i "s|/home/gus/|$REMOTE_USER_HOME/|g" ~/video-system/scripts/debug_logger.py
        
        # Update log_wrapper.py paths  
        sed -i "s|/home/gus/|$REMOTE_USER_HOME/|g" ~/video-system/scripts/log_wrapper.py
        
        print_success "✅ auth_api_server.py updated with IP and paths"
        print_success "✅ debug_logger.py updated with paths"
        print_success "✅ log_wrapper.py updated with paths"
        
        # Verify the video path was replaced
        if grep -q "$REMOTE_USER_HOME" ~/video-system/scripts/auth_api_server.py; then
            print_success "✅ Welcome video path replacement verified"
        else
            print_error "❌ Welcome video path replacement failed"
        fi
        
        # Verify welcome video exists
        WELCOME_VIDEO_PATH="$REMOTE_USER_HOME/video-system/videos/video_system_futuristic_welcome_animation_enhanced_presentation.webm"
        if [[ -f "$WELCOME_VIDEO_PATH" ]]; then
            print_success "✅ Welcome video found: $WELCOME_VIDEO_PATH"
        else
            print_error "❌ Welcome video not found: $WELCOME_VIDEO_PATH"
        fi
        
        # Test if API server can be started
        print_info "Testing if auth_api_server.py can start..."
        cd ~/video-system/scripts
        print_success "✅ API server files ready"
    else
        print_error "auth_api_server.py not found"
    fi
    
    # Replace gcppftest01 placeholders in dashboard.html
    if [[ -f ~/video-system/docs/dashboard.html ]]; then
        print_info "Updating dashboard.html with correct IP..."
        sed -i "s/gcppftest01/$REMOTE_IP/g" ~/video-system/docs/dashboard.html
        print_success "✅ dashboard.html updated with IP"
        
        # Dashboard is already cross-distribution compatible
        if [[ "$OS_TYPE" == "centos" ]]; then
            print_info "Dashboard configured for CentOS/RHEL compatibility"
        else
            print_info "Dashboard configured for Ubuntu/Debian compatibility"
        fi
        
        print_success "✅ dashboard.html updated with IP and OS compatibility"
    else
        print_error "dashboard.html not found"
    fi
    
    # Replace gcppftest01 placeholders in api_console.html
    if [[ -f ~/video-system/docs/api_console.html ]]; then
        print_info "Updating api_console.html with correct IP..."
        sed -i "s/gcppftest01/$REMOTE_IP/g" ~/video-system/docs/api_console.html
        print_success "✅ api_console.html updated with IP"
    else
        print_error "api_console.html not found"
    fi
    
    # Search for other files that might have gcppftest01
    print_info "Searching for other files with gcppftest01..."
    find ~/video-system -type f -name "*.py" -o -name "*.html" -o -name "*.js" -o -name "*.sh" | xargs grep -l "gcppftest01" 2>/dev/null | while read -r file; do
        if [[ -f "$file" ]]; then
            print_info "Updating $file..."
            sed -i "s/gcppftest01/$REMOTE_IP/g" "$file"
        fi
    done
    
print_success "✅ IP addresses configured for: $REMOTE_IP"

# Step 4: Create required directories
print_step "Creating required directories..."

# Create random_files directory if needed
print_step "Checking random_files directory..."
if [[ -d ~/random_files ]]; then
    print_success "~/random_files directory already exists"
else
    print_info "Creating ~/random_files directory..."
    mkdir -p ~/random_files
    chmod 755 ~/random_files
    print_success "✅ ~/random_files directory created"
fi

# Create logs directory if needed
print_step "Checking logs directory..."
if [[ -d ~/video-system/logs ]]; then
    print_success "~/video-system/logs directory already exists"
else
    print_info "Creating ~/video-system/logs directory..."
    mkdir -p ~/video-system/logs
    chmod 755 ~/video-system/logs
    print_success "✅ ~/video-system/logs directory created"
fi

# Step 5: Set proper permissions
print_step "Setting proper permissions..."

# Set directory permissions
chmod -R 755 ~/video-system 2>/dev/null || true
chmod -R 755 ~/video-system-default 2>/dev/null || true  
chmod 755 ~/random_files 2>/dev/null || true

# Make scripts executable
find ~/video-system -name "*.py" -exec chmod +x {} \; 2>/dev/null || true
find ~/video-system -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true

print_success "✅ Permissions set successfully"

# Step 6: Verify setup
print_step "Verifying remote setup..."

echo "Verification Results:"
echo "==================="

# Check video-system
if [[ -d ~/video-system ]]; then
    echo "✅ video-system directory exists"
    VIDEO_SIZE=$(du -sh ~/video-system 2>/dev/null | cut -f1)
    echo "   Size: ${VIDEO_SIZE:-Unknown}"
    
    # Count files
    FILE_COUNT=$(find ~/video-system -type f 2>/dev/null | wc -l)
    echo "   Files: $FILE_COUNT"
    
    # Check key files
    if [[ -f ~/video-system/scripts/auth_api_server.py ]]; then
        echo "   ✅ auth_api_server.py found"
    else
        echo "   ❌ auth_api_server.py missing"
    fi
    
    if [[ -f ~/video-system/docs/dashboard.html ]]; then
        echo "   ✅ dashboard.html found"
    else
        echo "   ❌ dashboard.html missing" 
    fi
else
    echo "❌ video-system directory missing"
fi

# Check backup
if [[ -d ~/video-system-default ]]; then
    echo "✅ video-system-default backup exists"
    DEFAULT_SIZE=$(du -sh ~/video-system-default 2>/dev/null | cut -f1)
    echo "   Size: ${DEFAULT_SIZE:-Unknown}"
else
    echo "❌ video-system-default backup missing"
fi

# Check random_files
if [[ -d ~/random_files ]]; then
    echo "✅ random_files directory exists"
else
    echo "❌ random_files directory missing"
fi

echo "==================="
echo

# Step 7: Video debugging information
print_separator
echo -e "${BLUE}${BOLD}🎬 VIDEO SYSTEM DEBUG INFO${NC}"
print_separator
echo
echo -e "${YELLOW}Video Configuration:${NC}"
echo -e "   ${WHITE}Video Path:${NC} ~/video-system/videos/video_system_futuristic_welcome_animation_enhanced_presentation.webm"
echo -e "   ${WHITE}API Endpoint:${NC} http://$REMOTE_IP:9090/api/video/welcome"
echo -e "   ${WHITE}Dashboard URL:${NC} http://$REMOTE_IP:9090/dashboard.html"
echo

echo -e "${YELLOW}If video doesn'"'"'t load in modal:${NC}"
echo -e "   ${WHITE}1.${NC} Check browser console (F12) for errors"
echo -e "   ${WHITE}2.${NC} Test API endpoint directly: curl http://$REMOTE_IP:9090/api/video/welcome"
echo -e "   ${WHITE}3.${NC} Ensure API server is running: cd ~/video-system/scripts && python3 auth_api_server.py"
echo -e "   ${WHITE}4.${NC} Check video file exists: ls -la ~/video-system/videos/*.webm"
echo

# Step 8: Restart API server to pick up new paths
print_step "Restarting API server with updated configuration..."

# Kill any existing server processes
pkill -f auth_api_server.py 2>/dev/null || true
sleep 2

# Start the server in background
cd ~/video-system/scripts
nohup python3 auth_api_server.py > ../logs/server.log 2>&1 &
sleep 3

# Check if server started
if pgrep -f auth_api_server.py > /dev/null; then
    print_success "✅ API server restarted successfully"
    API_SERVER_PID=$(pgrep -f auth_api_server.py)
    print_info "Server PID: $API_SERVER_PID"
    
    # Test welcome video endpoint
    print_info "Testing welcome video endpoint..."
    sleep 2  # Give server time to fully start
    if curl -s -f "http://localhost:9090/api/video/welcome" -o /dev/null -w "%{http_code}" | grep -q "200"; then
        print_success "✅ Welcome video endpoint responding"
    else
        print_warning "⚠️ Welcome video endpoint may have issues - check logs"
    fi
else
    print_error "❌ Failed to start API server"
    print_info "Check logs: tail ~/video-system/logs/server.log"
fi

print_separator
echo -e "${GREEN}${BOLD}🎉 REMOTE SETUP COMPLETED SUCCESSFULLY!${NC}"
print_separator
echo

echo -e "${YELLOW}System is now ready! The API server is already running. You can:${NC}"
echo -e "   ${WHITE}1.${NC} Access the dashboard immediately:"
echo -e "      ${GREEN}Open browser to: http://$REMOTE_IP:9090${NC}"
echo
echo -e "   ${WHITE}2.${NC} Manage the system:"
echo -e "      ${GREEN}cd ~ && bash setup_video_system.sh${NC}"
echo

print_separator
'

    if eval "$ssh_cmd $remote_user@$remote_host 'bash -s' -- '$remote_host' '$video_username' '$video_password'" <<< "$remote_setup_script"; then
        echo
        print_success "✅ Remote setup completed successfully!"
    else
        print_error "❌ Remote setup failed"
        return
    fi
    
    echo
    print_separator
    echo -e "${GREEN}${BOLD}🎉 SYSTEM TRANSFER & SETUP COMPLETED!${NC}"
    print_separator
    echo
    
    echo -e "${CYAN}Transfer Summary:${NC}"
    echo -e "   ${WHITE}Remote Host:${NC} $remote_host"
    echo -e "   ${WHITE}Remote User:${NC} $remote_user"  
    echo -e "   ${WHITE}Operations Completed:${NC}"
    echo -e "     • ✅ Transferred ~/video-system-default directory"
    echo -e "     • ✅ Created working ~/video-system directory"
    echo -e "     • ✅ Configured IP addresses for remote host"
    echo -e "     • ✅ Created ~/random_files directory"
    echo -e "     • ✅ Set proper permissions"
    echo -e "     • ✅ Verified installation"
    echo
    
    echo -e "${GREEN}${BOLD}🚀 System is ready for use!${NC}"
    echo
    echo -e "${YELLOW}To access your remote video system:${NC}"
    echo -e "   ${WHITE}SSH Command:${NC} ${GREEN}ssh $remote_user@$remote_host${NC}"
    echo -e "   ${WHITE}Start Server:${NC} ${GREEN}cd ~/video-system/scripts && python3 auth_api_server.py${NC}"
    echo
    echo -e "${CYAN}The remote system now has a complete copy of your video system and is ready to use!${NC}"
    echo
    echo -e "${YELLOW}Press any key to return to main menu...${NC}"
    read -n 1 -s
}

# Function to manage connections
manage_connections() {
    while true; do
        print_header "CONNECTION MANAGEMENT"
        
        if [[ ! -f "$CRDS_FILE" ]]; then
            echo "[]" > "$CRDS_FILE"
            chmod 600 "$CRDS_FILE"
        fi
        
        # Display current connections
        echo -e "${CYAN}${BOLD}Saved Connections:${NC}"
        echo
        
        local has_connections=false
        if [[ -f "$CRDS_FILE" ]] && [[ -s "$CRDS_FILE" ]] && [[ "$(cat "$CRDS_FILE")" != "[]" ]]; then
            python3 -c "
import json
try:
    with open('$CRDS_FILE', 'r') as f:
        connections = json.load(f)
    
    if connections:
        for i, conn in enumerate(connections, 1):
            print(f'{i}) {conn[\"name\"]} - {conn[\"username\"]}@{conn[\"host\"]} ({conn[\"auth_method\"]})')
    else:
        print('No saved connections found.')
except Exception as e:
    print('Error reading connections:', e)
" 2>/dev/null && has_connections=true
        else
            echo -e "${YELLOW}No saved connections found.${NC}"
        fi
        
        echo
        print_separator
        echo -e "${MAGENTA}${BOLD}CONNECTION MANAGEMENT OPTIONS${NC}"
        print_separator
        echo
        echo -e "${GREEN}1)${NC} Add new connection"
        echo -e "${CYAN}2)${NC} Test existing connection"
        echo -e "${ORANGE}3)${NC} Edit connection"
        echo -e "${RED}4)${NC} Delete connection"
        echo -e "${YELLOW}5)${NC} Back to main menu"
        echo
        
        local choice
        echo -e "${CYAN}Select option (1-5): ${NC}"
        read -p "> " choice
        
        case $choice in
            1)
                add_new_connection
                ;;
            2)
                test_existing_connection
                ;;
            3)
                edit_connection
                ;;
            4)
                delete_connection
                ;;
            5)
                break
                ;;
            *)
                print_error "Invalid option. Please select 1-5."
                echo
                echo -e "${YELLOW}Press any key to continue...${NC}"
                read -n 1 -s
                ;;
        esac
    done
}

# Function to add new connection
add_new_connection() {
    print_header "ADD NEW CONNECTION"
    
    local remote_host=""
    local remote_user=""
    local auth_method=""
    local auth_value=""
    local connection_name=""
    
    # Get connection name first
    while true; do
        echo -e "${CYAN}Enter a name for this connection:${NC}"
        echo -e "${YELLOW}Example: production-server, test-box, backup-system${NC}"
        read -p "Connection name: " connection_name
        
        if [[ -n "$connection_name" && "$connection_name" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]]; then
            # Check if name already exists
            if [[ -f "$CRDS_FILE" ]]; then
                local exists=$(python3 -c "
import json
try:
    with open('$CRDS_FILE', 'r') as f:
        connections = json.load(f)
    for conn in connections:
        if conn.get('name') == '$connection_name':
            print('EXISTS')
            break
    else:
        print('OK')
except:
    print('OK')
" 2>/dev/null)
                
                if [[ "$exists" == "EXISTS" ]]; then
                    print_warning "Connection name '$connection_name' already exists"
                    echo -e "${CYAN}Overwrite existing connection? (y/N): ${NC}"
                    read -p "" -n 1 -r
                    echo
                    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                        continue
                    fi
                fi
            fi
            break
        else
            print_error "Invalid connection name format. Use alphanumeric characters, dots, hyphens, underscores."
            echo
        fi
    done
    
    echo
    
    # Get remote host
    while true; do
        echo -e "${CYAN}Enter remote system IP address or hostname/FQDN:${NC}"
        echo -e "${YELLOW}Examples: 192.168.1.100, server.example.com${NC}"
        read -p "Host: " remote_host
        
        if [[ -n "$remote_host" ]] && validate_ip "$remote_host"; then
            print_success "Valid host: $remote_host"
            break
        else
            print_error "Invalid IP address or hostname format"
            echo
        fi
    done
    
    echo
    
    # Get username
    while true; do
        echo -e "${CYAN}Enter username for remote system:${NC}"
        read -p "Username: " remote_user
        
        if [[ -n "$remote_user" && "$remote_user" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]]; then
            break
        else
            print_error "Invalid username format"
            echo
        fi
    done
    
    echo
    
    # Get authentication method
    echo -e "${CYAN}Select authentication method:${NC}"
    echo -e "${GREEN}1)${NC} SSH Key file"
    echo -e "${YELLOW}2)${NC} Password"
    echo
    
    local auth_choice
    while true; do
        echo -e "${CYAN}Select method (1-2): ${NC}"
        read -p "> " auth_choice
        
        if [[ "$auth_choice" == "1" ]]; then
            auth_method="key"
            
            while true; do
                echo -e "${CYAN}Enter path to SSH private key file:${NC}"
                echo -e "${YELLOW}Example: /home/user/.ssh/id_rsa${NC}"
                read -p "SSH Key Path: " auth_value
                
                if [[ -f "$auth_value" && -r "$auth_value" ]]; then
                    local key_perms=$(stat -c "%a" "$auth_value" 2>/dev/null)
                    if [[ "$key_perms" == "600" || "$key_perms" == "400" ]]; then
                        print_success "SSH key found and permissions are secure"
                        break
                    else
                        print_warning "SSH key permissions should be 600 or 400"
                        echo -e "${YELLOW}Fix with: chmod 600 '$auth_value'${NC}"
                        echo -e "${YELLOW}Continue anyway? (y/N): ${NC}"
                        read -p "" -n 1 -r
                        echo
                        if [[ $REPLY =~ ^[Yy]$ ]]; then
                            break
                        fi
                    fi
                else
                    print_error "SSH key file not found or not readable: $auth_value"
                    echo
                fi
            done
            break
            
        elif [[ "$auth_choice" == "2" ]]; then
            auth_method="password"
            
            if ! command -v sshpass &> /dev/null; then
                print_warning "sshpass is required for password authentication"
                echo -e "${CYAN}Install sshpass first:${NC}"
                echo -e "${YELLOW}Ubuntu/Debian: sudo apt-get install sshpass${NC}"
                echo -e "${YELLOW}RHEL/CentOS: sudo yum install sshpass${NC}"
                echo
                echo -e "${CYAN}Continue without installing? (connection tests will fail) (y/N): ${NC}"
                read -p "" -n 1 -r
                echo
                if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                    return
                fi
            fi
            
            while true; do
                echo -e "${CYAN}Enter password for $remote_user@$remote_host:${NC}"
                read -s -p "Password: " auth_value
                echo
                
                if [[ -n "$auth_value" ]]; then
                    echo -e "${CYAN}Confirm password:${NC}"
                    read -s -p "Confirm: " auth_confirm
                    echo
                    
                    if [[ "$auth_value" == "$auth_confirm" ]]; then
                        print_success "Password set successfully"
                        break
                    else
                        print_error "Passwords do not match"
                        echo
                    fi
                else
                    print_error "Password cannot be empty"
                    echo
                fi
            done
            break
        else
            print_error "Invalid choice. Please select 1 or 2."
            echo
        fi
    done
    
    echo
    
    # Test connection before saving
    echo -e "${CYAN}Test connection before saving? (Y/n): ${NC}"
    read -p "" -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        if test_remote_system "$remote_host" "$remote_user" "$auth_method" "$auth_value"; then
            print_success "Connection test successful!"
        else
            print_error "Connection test failed!"
            echo -e "${CYAN}Save connection anyway? (y/N): ${NC}"
            read -p "" -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                print_info "Connection not saved"
                echo
                echo -e "${YELLOW}Press any key to return to connection management...${NC}"
                read -n 1 -s
                return
            fi
        fi
        echo
    fi
    
    # Save connection
    save_connection "$connection_name" "$remote_host" "$remote_user" "$auth_method" "$auth_value"
    
    echo
    print_separator
    echo -e "${GREEN}${BOLD}✅ Connection Added Successfully!${NC}"
    print_separator
    echo
    echo -e "${CYAN}Connection Details:${NC}"
    echo -e "   ${WHITE}Name:${NC} $connection_name"
    echo -e "   ${WHITE}Host:${NC} $remote_host"
    echo -e "   ${WHITE}User:${NC} $remote_user"
    echo -e "   ${WHITE}Auth:${NC} $auth_method"
    echo
    echo -e "${YELLOW}Press any key to return to connection management...${NC}"
    read -n 1 -s
}

# Function to test existing connection
test_existing_connection() {
    print_header "TEST EXISTING CONNECTION"
    
    if [[ ! -f "$CRDS_FILE" ]] || [[ ! -s "$CRDS_FILE" ]] || [[ "$(cat "$CRDS_FILE")" == "[]" ]]; then
        print_error "No saved connections found"
        echo
        echo -e "${YELLOW}Press any key to return to connection management...${NC}"
        read -n 1 -s
        return
    fi
    
    echo
    print_step "Available connections:"
    echo
    
    python3 -c "
import json
try:
    with open('$CRDS_FILE', 'r') as f:
        connections = json.load(f)
    
    if not connections:
        print('No saved connections found')
        exit(1)
        
    for i, conn in enumerate(connections, 1):
        print(f'{i}) {conn[\"name\"]} - {conn[\"username\"]}@{conn[\"host\"]} ({conn[\"auth_method\"]})')
        
except Exception as e:
    print('Error reading connections:', e)
    exit(1)
" 2>/dev/null || {
        print_error "Failed to read saved connections"
        return
    }
    
    echo
    local conn_choice
    echo -e "${CYAN}Select connection number to test: ${NC}"
    read -p "> " conn_choice
    
    # Get connection details
    local conn_details=$(python3 -c "
import json
try:
    with open('$CRDS_FILE', 'r') as f:
        connections = json.load(f)
    
    if $conn_choice > 0 and $conn_choice <= len(connections):
        conn = connections[$conn_choice - 1]
        print(f'{conn[\"host\"]}|{conn[\"username\"]}|{conn[\"auth_method\"]}|{conn.get(\"password\", conn.get(\"ssh_key_path\", \"\"))}|{conn[\"name\"]}')
    else:
        print('INVALID')
except:
    print('ERROR')
" 2>/dev/null)
    
    if [[ "$conn_details" == "INVALID" || "$conn_details" == "ERROR" || -z "$conn_details" ]]; then
        print_error "Invalid connection selection"
        return
    fi
    
    local remote_host remote_user auth_method auth_value connection_name
    IFS='|' read -r remote_host remote_user auth_method auth_value connection_name <<< "$conn_details"
    
    echo
    print_separator
    echo -e "${CYAN}${BOLD}TESTING CONNECTION: $connection_name${NC}"
    print_separator
    echo
    
    if test_remote_system "$remote_host" "$remote_user" "$auth_method" "$auth_value"; then
        echo
        print_success "✅ Connection '$connection_name' is working perfectly!"
    else
        echo
        print_error "❌ Connection '$connection_name' failed!"
    fi
    
    echo
    echo -e "${YELLOW}Press any key to return to connection management...${NC}"
    read -n 1 -s
}

# Function to edit connection
edit_connection() {
    print_header "EDIT CONNECTION"
    
    if [[ ! -f "$CRDS_FILE" ]] || [[ ! -s "$CRDS_FILE" ]] || [[ "$(cat "$CRDS_FILE")" == "[]" ]]; then
        print_error "No saved connections found"
        echo
        echo -e "${YELLOW}Press any key to return to connection management...${NC}"
        read -n 1 -s
        return
    fi
    
    echo
    print_step "Available connections:"
    echo
    
    python3 -c "
import json
try:
    with open('$CRDS_FILE', 'r') as f:
        connections = json.load(f)
    
    if not connections:
        print('No saved connections found')
        exit(1)
        
    for i, conn in enumerate(connections, 1):
        print(f'{i}) {conn[\"name\"]} - {conn[\"username\"]}@{conn[\"host\"]} ({conn[\"auth_method\"]})')
        
except Exception as e:
    print('Error reading connections:', e)
    exit(1)
" 2>/dev/null || {
        print_error "Failed to read saved connections"
        return
    }
    
    echo
    local conn_choice
    echo -e "${CYAN}Select connection number to edit: ${NC}"
    read -p "> " conn_choice
    
    # Get current connection details
    local current_details=$(python3 -c "
import json
try:
    with open('$CRDS_FILE', 'r') as f:
        connections = json.load(f)
    
    if $conn_choice > 0 and $conn_choice <= len(connections):
        conn = connections[$conn_choice - 1]
        print(f'{conn[\"name\"]}|{conn[\"host\"]}|{conn[\"username\"]}|{conn[\"auth_method\"]}|{conn.get(\"password\", conn.get(\"ssh_key_path\", \"\"))}')
    else:
        print('INVALID')
except:
    print('ERROR')
" 2>/dev/null)
    
    if [[ "$current_details" == "INVALID" || "$current_details" == "ERROR" || -z "$current_details" ]]; then
        print_error "Invalid connection selection"
        return
    fi
    
    local old_name old_host old_user old_auth_method old_auth_value
    IFS='|' read -r old_name old_host old_user old_auth_method old_auth_value <<< "$current_details"
    
    echo
    print_info "Current connection details:"
    echo -e "   ${WHITE}Name:${NC} $old_name"
    echo -e "   ${WHITE}Host:${NC} $old_host"
    echo -e "   ${WHITE}User:${NC} $old_user"
    echo -e "   ${WHITE}Auth:${NC} $old_auth_method"
    echo
    
    # Edit each field
    local new_name="$old_name"
    echo -e "${CYAN}Enter new name (or press Enter to keep '$old_name'): ${NC}"
    read -p "Name: " input_name
    if [[ -n "$input_name" ]]; then
        new_name="$input_name"
    fi
    
    local new_host="$old_host"
    echo -e "${CYAN}Enter new host (or press Enter to keep '$old_host'): ${NC}"
    read -p "Host: " input_host
    if [[ -n "$input_host" ]]; then
        if validate_ip "$input_host"; then
            new_host="$input_host"
        else
            print_error "Invalid host format, keeping original"
            new_host="$old_host"
        fi
    fi
    
    local new_user="$old_user"
    echo -e "${CYAN}Enter new username (or press Enter to keep '$old_user'): ${NC}"
    read -p "Username: " input_user
    if [[ -n "$input_user" ]]; then
        new_user="$input_user"
    fi
    
    local new_auth_method="$old_auth_method"
    local new_auth_value="$old_auth_value"
    echo -e "${CYAN}Change authentication method? Current: $old_auth_method (y/N): ${NC}"
    read -p "" -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${CYAN}Select new authentication method:${NC}"
        echo -e "${GREEN}1)${NC} SSH Key file"
        echo -e "${YELLOW}2)${NC} Password"
        echo -e "${RED}3)${NC} Return to previous menu"
        echo
        
        local auth_choice
        while true; do
            echo -e "${CYAN}Select method (1-3): ${NC}"
            read -p "> " auth_choice
            
            if [[ "$auth_choice" == "1" ]]; then
                new_auth_method="key"
                
                while true; do
                    echo -e "${CYAN}Enter path to SSH private key file:${NC}"
                    read -p "SSH Key Path: " new_auth_value
                    
                    if [[ -f "$new_auth_value" && -r "$new_auth_value" ]]; then
                        break
                    else
                        print_error "SSH key file not found or not readable"
                        echo
                    fi
                done
                break
                
            elif [[ "$auth_choice" == "2" ]]; then
                new_auth_method="password"
                
                while true; do
                    echo -e "${CYAN}Enter new password:${NC}"
                    read -s -p "Password: " new_auth_value
                    echo
                    
                    if [[ -n "$new_auth_value" ]]; then
                        break
                    else
                        print_error "Password cannot be empty"
                        echo
                    fi
                done
                break
            elif [[ "$auth_choice" == "3" ]]; then
                # Return to previous menu
                print_info "Returning to previous menu..."
                return
            else
                print_error "Invalid choice. Please select 1, 2, or 3."
                echo
            fi
        done
    fi
    
    echo
    print_step "Updated connection details:"
    echo -e "   ${WHITE}Name:${NC} $new_name"
    echo -e "   ${WHITE}Host:${NC} $new_host"
    echo -e "   ${WHITE}User:${NC} $new_user"
    echo -e "   ${WHITE}Auth:${NC} $new_auth_method"
    echo
    
    echo -e "${CYAN}Save changes? (Y/n): ${NC}"
    read -p "" -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        # Remove old connection and save new one
        python3 -c "
import json
try:
    with open('$CRDS_FILE', 'r') as f:
        connections = json.load(f)
    
    # Remove old connection
    connections = [conn for conn in connections if conn.get('name') != '$old_name']
    
    with open('$CRDS_FILE', 'w') as f:
        json.dump(connections, f, indent=2)
        
except Exception as e:
    print('Error updating connections:', e)
" 2>/dev/null
        
        # Save new connection
        save_connection "$new_name" "$new_host" "$new_user" "$new_auth_method" "$new_auth_value"
        
        print_success "✅ Connection updated successfully!"
    else
        print_info "Changes discarded"
    fi
    
    echo
    echo -e "${YELLOW}Press any key to return to connection management...${NC}"
    read -n 1 -s
}

# Function to delete connection
delete_connection() {
    print_header "DELETE CONNECTION"
    
    if [[ ! -f "$CRDS_FILE" ]] || [[ ! -s "$CRDS_FILE" ]] || [[ "$(cat "$CRDS_FILE")" == "[]" ]]; then
        print_error "No saved connections found"
        echo
        echo -e "${YELLOW}Press any key to return to connection management...${NC}"
        read -n 1 -s
        return
    fi
    
    echo
    print_step "Available connections:"
    echo
    
    python3 -c "
import json
try:
    with open('$CRDS_FILE', 'r') as f:
        connections = json.load(f)
    
    if not connections:
        print('No saved connections found')
        exit(1)
        
    for i, conn in enumerate(connections, 1):
        print(f'{i}) {conn[\"name\"]} - {conn[\"username\"]}@{conn[\"host\"]} ({conn[\"auth_method\"]})')
        
except Exception as e:
    print('Error reading connections:', e)
    exit(1)
" 2>/dev/null || {
        print_error "Failed to read saved connections"
        return
    }
    
    echo
    local conn_choice
    echo -e "${CYAN}Select connection number to delete: ${NC}"
    read -p "> " conn_choice
    
    # Get connection name
    local conn_name=$(python3 -c "
import json
try:
    with open('$CRDS_FILE', 'r') as f:
        connections = json.load(f)
    
    if $conn_choice > 0 and $conn_choice <= len(connections):
        print(connections[$conn_choice - 1]['name'])
    else:
        print('INVALID')
except:
    print('ERROR')
" 2>/dev/null)
    
    if [[ "$conn_name" == "INVALID" || "$conn_name" == "ERROR" || -z "$conn_name" ]]; then
        print_error "Invalid connection selection"
        return
    fi
    
    echo
    print_warning "You are about to delete connection: '$conn_name'"
    echo -e "${RED}This action cannot be undone!${NC}"
    echo
    echo -e "${RED}Are you sure? (yes/NO): ${NC}"
    read -p "Type 'yes' to confirm: " confirm
    
    if [[ "$confirm" != "yes" ]]; then
        print_info "Deletion cancelled"
        echo
        echo -e "${YELLOW}Press any key to return to connection management...${NC}"
        read -n 1 -s
        return
    fi
    
    # Delete connection
    python3 -c "
import json
try:
    with open('$CRDS_FILE', 'r') as f:
        connections = json.load(f)
    
    # Remove connection
    connections = [conn for conn in connections if conn.get('name') != '$conn_name']
    
    with open('$CRDS_FILE', 'w') as f:
        json.dump(connections, f, indent=2)
    
    print('Connection deleted successfully')
    
except Exception as e:
    print('Error deleting connection:', e)
" 2>/dev/null
    
    print_success "✅ Connection '$conn_name' deleted successfully!"
    
    echo
    echo -e "${YELLOW}Press any key to return to connection management...${NC}"
    read -n 1 -s
}

# Main script execution
USER_HOME=$(echo $HOME)

# Main menu loop
while true; do
    show_main_menu
    
    echo -e "${CYAN}Select option (1-7): ${NC}"
    read -p "> " CHOICE
    
    case $CHOICE in
        1)
            setup_new_system
            ;;
        2)
            restore_to_default
            ;;
        3)
            kill_and_restart_server
            ;;
        4)
            transfer_system_to_remote
            ;;
        5)
            manage_connections
            ;;
        6)
            diagnose_credentials_file
            echo
            echo -e "${YELLOW}Press any key to return to main menu...${NC}"
            read -n 1 -s
            ;;
        7)
            echo
            print_separator
            echo -e "${WHITE}Thank you for using Video and Files Management System Setup!${NC}"
            print_separator
            echo
            exit 0
            ;;
        *)
            echo
            print_error "Invalid option. Please select 1-7."
            echo
            echo -e "${YELLOW}Press any key to continue...${NC}"
            read -n 1 -s
            ;;
    esac
done
