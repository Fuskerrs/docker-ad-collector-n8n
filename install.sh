#!/bin/bash

################################################################################
# AD Collector for n8n - Installation Script
# Version: 1.0.0
# Description: Automated installation script with dependency checks
################################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Default values
INSTALL_DIR="$HOME/ad-collector"
DEFAULT_PORT=8443
MIN_DISK_SPACE_MB=2048

################################################################################
# Helper Functions
################################################################################

print_header() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ ERROR: $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  WARNING: $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_step() {
    echo -e "${CYAN}▶ $1${NC}"
}

check_root() {
    if [ "$EUID" -eq 0 ]; then
        print_warning "Running as root. This is not recommended for production."

        # Check if we have an interactive terminal
        if [ -t 0 ]; then
            # Interactive mode - ask for confirmation
            read -p "Continue anyway? (y/n): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        else
            # Non-interactive mode (e.g., curl | bash) - just warn and continue
            echo "Non-interactive mode detected. Continuing installation..."
        fi
    fi
}

################################################################################
# System Detection and Checks
################################################################################

detect_os() {
    print_step "Detecting operating system..."

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
        OS_NAME=$PRETTY_NAME
    else
        print_error "Cannot detect OS. /etc/os-release not found."
        exit 1
    fi

    print_success "Detected: $OS_NAME"

    case $OS in
        centos|rhel|almalinux|rocky|fedora)
            PACKAGE_MANAGER="dnf"
            if ! command -v dnf &> /dev/null; then
                PACKAGE_MANAGER="yum"
            fi
            ;;
        ubuntu|debian)
            PACKAGE_MANAGER="apt"
            ;;
        *)
            print_warning "Unsupported OS: $OS. Proceeding anyway..."
            PACKAGE_MANAGER="unknown"
            ;;
    esac
}

check_disk_space() {
    print_step "Checking available disk space..."

    AVAILABLE_MB=$(df -m "$HOME" | awk 'NR==2 {print $4}')

    if [ "$AVAILABLE_MB" -lt "$MIN_DISK_SPACE_MB" ]; then
        print_error "Insufficient disk space. Available: ${AVAILABLE_MB}MB, Required: ${MIN_DISK_SPACE_MB}MB"
        exit 1
    fi

    print_success "Disk space OK (${AVAILABLE_MB}MB available)"
}

check_memory() {
    print_step "Checking available memory..."

    TOTAL_MEM_MB=$(free -m | awk 'NR==2{print $2}')
    AVAILABLE_MEM_MB=$(free -m | awk 'NR==2{print $7}')

    print_success "Memory: ${AVAILABLE_MEM_MB}MB available / ${TOTAL_MEM_MB}MB total"

    if [ "$AVAILABLE_MEM_MB" -lt 512 ]; then
        print_warning "Low available memory (${AVAILABLE_MEM_MB}MB). Consider freeing up some RAM."
    fi
}

check_docker() {
    print_step "Checking Docker installation..."

    if command -v docker &> /dev/null; then
        DOCKER_VERSION=$(docker --version | awk '{print $3}' | sed 's/,//')
        print_success "Docker is installed (version $DOCKER_VERSION)"

        # Check if Docker is running
        if ! docker info &> /dev/null; then
            print_warning "Docker is installed but not running."
            print_step "Starting Docker service..."

            if [ "$PACKAGE_MANAGER" = "dnf" ] || [ "$PACKAGE_MANAGER" = "yum" ]; then
                sudo systemctl start docker
                sudo systemctl enable docker
            else
                sudo service docker start
            fi

            sleep 2

            if docker info &> /dev/null; then
                print_success "Docker started successfully"
            else
                print_error "Failed to start Docker"
                exit 1
            fi
        fi

        return 0
    else
        print_warning "Docker is not installed"
        return 1
    fi
}

detect_docker_compose() {
    print_step "Detecting Docker Compose version..."

    # Check for Docker Compose v2 (plugin)
    if docker compose version &> /dev/null; then
        DOCKER_COMPOSE_CMD="docker compose"
        DOCKER_COMPOSE_VERSION=$(docker compose version --short 2>/dev/null || echo "v2")
        print_success "Docker Compose v2 detected ($DOCKER_COMPOSE_VERSION)"
        return 0
    # Check for Docker Compose v1 (standalone)
    elif command -v docker-compose &> /dev/null; then
        DOCKER_COMPOSE_CMD="docker-compose"
        DOCKER_COMPOSE_VERSION=$(docker-compose version --short 2>/dev/null || echo "v1")
        print_success "Docker Compose v1 detected ($DOCKER_COMPOSE_VERSION)"
        return 0
    else
        print_error "Docker Compose not found"
        print_info "Installing Docker Compose plugin..."

        # Try to install compose plugin
        if [ "$PACKAGE_MANAGER" = "dnf" ] || [ "$PACKAGE_MANAGER" = "yum" ]; then
            sudo $PACKAGE_MANAGER install -y docker-compose-plugin
        elif [ "$PACKAGE_MANAGER" = "apt" ]; then
            sudo apt-get update && sudo apt-get install -y docker-compose-plugin
        else
            print_error "Cannot auto-install Docker Compose"
            return 1
        fi

        # Re-check
        if docker compose version &> /dev/null; then
            DOCKER_COMPOSE_CMD="docker compose"
            print_success "Docker Compose plugin installed"
            return 0
        else
            return 1
        fi
    fi
}

install_docker() {
    print_header "Installing Docker"

    case $PACKAGE_MANAGER in
        dnf|yum)
            print_step "Installing Docker on RHEL-based system..."
            sudo $PACKAGE_MANAGER install -y $PACKAGE_MANAGER-plugins-core
            sudo $PACKAGE_MANAGER config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
            sudo $PACKAGE_MANAGER install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
            sudo systemctl start docker
            sudo systemctl enable docker
            ;;
        apt)
            print_step "Installing Docker on Debian-based system..."
            sudo apt-get update
            sudo apt-get install -y ca-certificates curl gnupg
            sudo install -m 0755 -d /etc/apt/keyrings
            curl -fsSL https://download.docker.com/linux/$OS/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
            sudo chmod a+r /etc/apt/keyrings/docker.gpg
            echo \
              "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$OS \
              "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
              sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
            sudo apt-get update
            sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
            ;;
        *)
            print_error "Cannot install Docker automatically on this OS"
            print_info "Please install Docker manually: https://docs.docker.com/engine/install/"
            exit 1
            ;;
    esac

    # Add current user to docker group
    if ! groups $USER | grep &>/dev/null '\bdocker\b'; then
        print_step "Adding user to docker group..."
        sudo usermod -aG docker $USER
        print_warning "You need to log out and log back in for group changes to take effect"
        print_info "After re-login, run this script again"
        exit 0
    fi

    print_success "Docker installed successfully"
}

check_curl() {
    if ! command -v curl &> /dev/null; then
        print_step "Installing curl..."
        case $PACKAGE_MANAGER in
            dnf|yum)
                sudo $PACKAGE_MANAGER install -y curl
                ;;
            apt)
                sudo apt-get update && sudo apt-get install -y curl
                ;;
        esac
    fi
}

check_ldap_utils() {
    if ! command -v ldapsearch &> /dev/null; then
        print_step "Installing LDAP utilities..."
        case $PACKAGE_MANAGER in
            dnf|yum)
                sudo $PACKAGE_MANAGER install -y openldap-clients
                ;;
            apt)
                sudo apt-get update && sudo apt-get install -y ldap-utils
                ;;
        esac
    fi
}

################################################################################
# Certificate Auto-Fetch
################################################################################

auto_fetch_certificate() {
    print_header "Automatic Certificate Retrieval"

    echo -e "${BOLD}Fetching AD Root CA Certificate automatically...${NC}"
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}📋 Required Permissions:${NC}"
    echo ""
    echo -e "${BOLD}Minimum permissions needed:${NC}"
    echo -e "  ✓ ${GREEN}Domain User${NC} (standard authenticated user)"
    echo -e "  ✓ ${GREEN}Read access${NC} to Public Key Services container"
    echo -e "  ✓ ${GREEN}LDAP read access${NC} (granted by default to all domain users)"
    echo ""
    echo -e "${CYAN}The service account you provided has these rights by default.${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    # Extract DC host from LDAP_URL
    LDAP_HOST=$(echo "$LDAP_URL" | sed -E 's|ldaps?://([^:]+).*|\1|')
    LDAP_PORT=$(echo "$LDAP_URL" | grep -oP ':\K[0-9]+$' || echo "636")

    # Determine if using LDAPS
    if [[ "$LDAP_URL" =~ ^ldaps:// ]]; then
        LDAP_PROTOCOL="ldaps"
    else
        LDAP_PROTOCOL="ldap"
    fi

    print_step "Attempting to fetch certificate from $LDAP_HOST..."
    echo ""

    # Try to find the CA certificate
    # Method 1: Query the AIA container for the CA certificate
    print_info "Searching for Root CA certificate in Active Directory..."

    # Extract domain components for CA search
    DOMAIN_DN="$LDAP_BASE_DN"

    # Try multiple common CA locations
    CA_SEARCH_BASES=(
        "CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,$DOMAIN_DN"
        "CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,$DOMAIN_DN"
        "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,$DOMAIN_DN"
    )

    CERT_FETCHED=false

    for CA_BASE in "${CA_SEARCH_BASES[@]}"; do
        print_step "Trying: $CA_BASE"

        # Use LDAPTLS_REQCERT=never to bypass cert verification during fetch
        CERT_DATA=$(LDAPTLS_REQCERT=never ldapsearch -x -H "${LDAP_PROTOCOL}://${LDAP_HOST}:${LDAP_PORT}" \
            -D "$LDAP_BIND_DN" \
            -w "$LDAP_BIND_PASSWORD" \
            -b "$CA_BASE" \
            -s sub \
            "(objectClass=*)" \
            cACertificate \
            -o ldif-wrap=no 2>/dev/null | \
            grep "cACertificate::" | \
            head -1 | \
            sed 's/cACertificate:: //')

        if [ -n "$CERT_DATA" ]; then
            print_success "Found certificate at: $CA_BASE"

            # Decode base64 and convert DER to PEM
            mkdir -p ./certs
            echo "$CERT_DATA" | base64 -d | \
                openssl x509 -inform DER -outform PEM > ./certs/ad-root-ca.crt 2>/dev/null

            if [ -f "./certs/ad-root-ca.crt" ] && [ -s "./certs/ad-root-ca.crt" ]; then
                # Verify it's a valid certificate
                CERT_SUBJECT=$(openssl x509 -in ./certs/ad-root-ca.crt -noout -subject 2>/dev/null | sed 's/subject=//')
                CERT_ISSUER=$(openssl x509 -in ./certs/ad-root-ca.crt -noout -issuer 2>/dev/null | sed 's/issuer=//')

                echo ""
                print_success "Certificate retrieved and saved successfully!"
                echo ""
                echo -e "${BOLD}Certificate Details:${NC}"
                echo -e "  Subject: ${CYAN}$CERT_SUBJECT${NC}"
                echo -e "  Issuer:  ${CYAN}$CERT_ISSUER${NC}"
                echo ""

                chmod 644 ./certs/ad-root-ca.crt
                CERT_FETCHED=true
                CERT_CONTENT=$(cat ./certs/ad-root-ca.crt)
                break
            fi
        fi
    done

    if [ "$CERT_FETCHED" = false ]; then
        print_warning "Could not automatically fetch the certificate"
        echo ""
        echo -e "${YELLOW}This can happen if:${NC}"
        echo -e "  • Your AD doesn't store certs in standard locations"
        echo -e "  • The service account lacks read permissions"
        echo -e "  • Network connectivity issues"
        echo ""

        read -p "Do you want to manually paste the certificate? (y/n): " -n 1 -r
        echo ""

        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo ""
            echo -e "   ${YELLOW}Paste your ROOT CA certificate below:${NC}"
            echo -e "   ${CYAN}(Start with -----BEGIN CERTIFICATE-----)${NC}"
            echo -e "   ${CYAN}(End with -----END CERTIFICATE-----)${NC}"
            echo -e "   ${CYAN}(Press CTRL+D on a new line when finished)${NC}"
            echo ""

            CERT_CONTENT=$(cat)

            if [[ $CERT_CONTENT == *"BEGIN CERTIFICATE"* ]] && [[ $CERT_CONTENT == *"END CERTIFICATE"* ]]; then
                mkdir -p ./certs
                echo "$CERT_CONTENT" > ./certs/ad-root-ca.crt
                print_success "Certificate saved manually"
                CERT_FETCHED=true
            else
                print_error "Invalid certificate format"
                CERT_CONTENT=""
            fi
        else
            CERT_CONTENT=""
        fi
    fi

    echo ""
}

################################################################################
# Interactive Configuration
################################################################################

show_prerequisites() {
    print_header "Prerequisites Checklist"

    echo -e "${BOLD}Before starting, please gather the following information:${NC}"
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${YELLOW}📋 Active Directory Information:${NC}"
    echo -e "   ${BOLD}1.${NC} LDAP/LDAPS Server URL"
    echo -e "      Example: ldaps://dc.example.com:636"
    echo -e "      ${CYAN}Tip: Use LDAPS (port 636) for encrypted connections${NC}"
    echo ""
    echo -e "   ${BOLD}2.${NC} Base DN (Distinguished Name)"
    echo -e "      Example: DC=example,DC=com"
    echo ""
    echo -e "   ${BOLD}3.${NC} Service Account Credentials"
    echo -e "      Bind DN: CN=n8n-service,CN=Users,DC=example,DC=com"
    echo -e "      Password: [your service account password]"
    echo ""
    echo -e "      ${CYAN}${BOLD}Required Permissions for Service Account:${NC}"
    echo -e "      ${GREEN}✓ Domain User${NC} (standard authenticated user) - ${CYAN}Already granted${NC}"
    echo -e "      ${GREEN}✓ Read${NC} on target OUs/Users/Groups - ${YELLOW}Required for operations${NC}"
    echo -e "      ${GREEN}✓ Read${NC} Public Key Services container - ${CYAN}For auto cert retrieval${NC}"
    echo -e "      ${GREEN}✓ Create/Modify${NC} users/groups - ${YELLOW}For create/modify operations${NC}"
    echo ""
    echo -e "      ${BOLD}Recommended delegated permissions:${NC}"
    echo -e "      • Reset user passwords and force password change at next logon"
    echo -e "      • Create, delete, and manage user accounts"
    echo -e "      • Modify the membership of a group"
    echo ""
    echo -e "${YELLOW}🔒 TLS Certificate:${NC}"
    echo -e "   ${GREEN}✓ Automatically retrieved${NC} from Active Directory"
    echo -e "   ${CYAN}The script will fetch the Root CA certificate using your service account${NC}"
    echo -e "   ${CYAN}No manual export needed!${NC}"
    echo ""
    echo -e "${YELLOW}⚙️  Optional Settings (v2.3.0+ Security Enhancements):${NC}"
    echo -e "   • Installation directory (default: ~/ad-collector)"
    echo -e "   • Collector port (default: 8443)"
    echo -e "   • Token expiry duration (default: 1h) ${CYAN}[v2.3.0: Changed from 365d]${NC}"
    echo -e "   • Token usage quota (default: 3 uses) ${CYAN}[v2.4.0: Prevents stolen token abuse]${NC}"
    echo -e "   • Binding address (default: 127.0.0.1) ${CYAN}[v2.3.0: localhost only]${NC}"
    echo -e "   • Rate limiting (default: enabled, 100 req/min) ${CYAN}[v2.3.0]${NC}"
    echo -e "   • Read-only mode (default: disabled) ${CYAN}[v2.3.0]${NC}"
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    read -p "Press ENTER when you're ready to continue... "
    echo ""
}

get_user_input() {
    print_header "Configuration"

    # Check if running in non-interactive mode
    if [ ! -t 0 ]; then
        echo ""
        print_error "This installation script requires interactive terminal access."
        echo ""
        echo -e "${BOLD}You are running this via pipe (e.g., 'curl | bash') which doesn't support interactive prompts.${NC}"
        echo ""
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${BOLD}Quick Installation (Docker Compose):${NC}"
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "${YELLOW}# 1. Create installation directory${NC}"
        echo -e "  mkdir -p ~/ad-collector && cd ~/ad-collector"
        echo ""
        echo -e "${YELLOW}# 2. Create docker-compose.yml${NC}"
        echo -e "  cat > docker-compose.yml <<'EOF'"
        echo -e "  services:"
        echo -e "    ad-collector:"
        echo -e "      image: fuskerrs97/ad-collector-n8n:latest"
        echo -e "      container_name: ad-collector"
        echo -e "      restart: unless-stopped"
        echo -e "      ports:"
        echo -e "        - \"127.0.0.1:8443:8443\"  # Bind to localhost only"
        echo -e "      environment:"
        echo -e "        - LDAP_URL=ldaps://dc.example.com:636"
        echo -e "        - LDAP_BASE_DN=DC=example,DC=com"
        echo -e "        - LDAP_BIND_DN=CN=service,CN=Users,DC=example,DC=com"
        echo -e "        - LDAP_BIND_PASSWORD=YourPassword"
        echo -e "        - LDAP_TLS_VERIFY=false  # Set to true for production"
        echo -e "        - TOKEN_EXPIRY=1h  # Default in v2.3.0"
        echo -e "        # - BIND_ADDRESS=0.0.0.0  # Uncomment to expose on all interfaces"
        echo -e "        # - READ_ONLY_MODE=true  # Uncomment for read-only deployment"
        echo -e "  EOF"
        echo ""
        echo -e "${YELLOW}# 3. Start the collector${NC}"
        echo -e "  docker compose up -d"
        echo ""
        echo -e "${YELLOW}# 4. Get your API token${NC}"
        echo -e "  docker compose logs | grep 'API Token'"
        echo ""
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${BOLD}OR use the interactive installer:${NC}"
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "  ${YELLOW}wget https://raw.githubusercontent.com/Fuskerrs/docker-ad-collector-n8n/main/install.sh${NC}"
        echo -e "  ${YELLOW}chmod +x install.sh${NC}"
        echo -e "  ${YELLOW}./install.sh${NC}"
        echo ""
        echo -e "${CYAN}Full documentation: https://github.com/Fuskerrs/docker-ad-collector-n8n${NC}"
        echo ""
        exit 1
    fi

    echo -e "${BOLD}Let's configure your AD Collector...${NC}"
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    # Installation directory
    echo -e "${YELLOW}📁 Installation Directory${NC}"
    read -p "   Where to install? [$INSTALL_DIR]: " input
    INSTALL_DIR=${input:-$INSTALL_DIR}
    echo ""

    # LDAP URL
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}🔌 Active Directory Connection${NC}"
    echo ""
    while true; do
        read -p "   LDAP/LDAPS URL (ex: ldaps://dc.example.com:636): " LDAP_URL
        if [[ $LDAP_URL =~ ^ldaps?:// ]]; then
            break
        else
            print_error "   Invalid URL. Must start with ldap:// or ldaps://"
        fi
    done
    echo ""

    # Base DN
    while true; do
        read -p "   Base DN (ex: DC=example,DC=com): " LDAP_BASE_DN
        if [[ $LDAP_BASE_DN =~ DC= ]]; then
            break
        else
            print_error "   Invalid Base DN. Must contain DC="
        fi
    done
    echo ""

    # Bind DN
    while true; do
        read -p "   Bind DN (ex: CN=n8n-service,CN=Users,DC=example,DC=com): " LDAP_BIND_DN
        if [[ -n $LDAP_BIND_DN ]]; then
            break
        else
            print_error "   Bind DN cannot be empty"
        fi
    done
    echo ""

    # Bind Password
    while true; do
        read -sp "   Bind Password: " LDAP_BIND_PASSWORD
        echo ""
        if [[ -n $LDAP_BIND_PASSWORD ]]; then
            read -sp "   Confirm Password: " LDAP_BIND_PASSWORD_CONFIRM
            echo ""
            if [ "$LDAP_BIND_PASSWORD" = "$LDAP_BIND_PASSWORD_CONFIRM" ]; then
                break
            else
                print_error "   Passwords do not match. Please try again."
                echo ""
            fi
        else
            print_error "   Password cannot be empty"
        fi
    done
    echo ""

    # TLS Verify
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}🔒 TLS Certificate Verification${NC}"
    echo ""
    echo -e "${BOLD}For production environments, TLS verification is recommended.${NC}"
    echo ""
    read -p "   Enable TLS certificate verification? (y/n) [y]: " -n 1 -r
    echo ""
    echo ""

    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        LDAP_TLS_VERIFY="true"

        echo -e "${GREEN}✓ TLS verification enabled${NC}"
        echo ""
        echo -e "${BOLD}The script will automatically retrieve the Root CA certificate${NC}"
        echo -e "${BOLD}from Active Directory using your service account.${NC}"
        echo ""

        # Note: Certificate will be fetched after create_project when we're in the right directory
        CERT_CONTENT="AUTO_FETCH"
    else
        LDAP_TLS_VERIFY="false"
        CERT_CONTENT=""
        print_info "   Certificate verification disabled"
        print_warning "   This is NOT recommended for production environments"
        echo ""
    fi

    # Port
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}⚙️  Optional Settings${NC}"
    echo ""
    read -p "   Collector port [$DEFAULT_PORT]: " input
    PORT=${input:-$DEFAULT_PORT}
    echo ""

    # Token expiry
    read -p "   Token expiry (e.g., 1h, 24h, 7d) [1h]: " input
    TOKEN_EXPIRY=${input:-1h}
    echo ""
}

show_configuration_summary() {
    echo ""
    print_header "Configuration Summary"

    echo -e "${BOLD}Installation Settings:${NC}"
    echo -e "  Directory:     $INSTALL_DIR"
    echo -e "  Port:          $PORT"
    echo ""
    echo -e "${BOLD}Active Directory Settings:${NC}"
    echo -e "  LDAP URL:      $LDAP_URL"
    echo -e "  Base DN:       $LDAP_BASE_DN"
    echo -e "  Bind DN:       $LDAP_BIND_DN"
    echo -e "  TLS Verify:    $LDAP_TLS_VERIFY"
    echo -e "  Token Expiry:  $TOKEN_EXPIRY"
    echo ""

    read -p "Proceed with installation? (y/n): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Installation cancelled"
        exit 0
    fi
}

################################################################################
# Rollback Functions
################################################################################

restore_backup() {
    if [ -n "$BACKUP_DIR" ] && [ -d "$BACKUP_DIR" ]; then
        print_warning "Installation failed - restoring backup..."
        rm -rf "$INSTALL_DIR"
        mv "$BACKUP_DIR" "$INSTALL_DIR"
        print_info "Backup restored to $INSTALL_DIR"
    fi
}

cleanup_on_error() {
    print_error "Installation encountered an error"
    if [ -d "$INSTALL_DIR" ] && [ ! -f "$INSTALL_DIR/.env" ]; then
        # If .env doesn't exist, it's a failed new installation
        print_step "Cleaning up failed installation..."
        rm -rf "$INSTALL_DIR"
        print_info "Cleanup complete"
    fi
}

################################################################################
# Installation
################################################################################

create_project() {
    print_header "Creating Project"

    # Check if directory exists and create backup
    if [ -d "$INSTALL_DIR" ]; then
        BACKUP_DIR="${INSTALL_DIR}.backup.$(date +%Y%m%d_%H%M%S)"
        print_step "Existing installation found - creating backup..."
        mv "$INSTALL_DIR" "$BACKUP_DIR"
        print_success "Backup created: $BACKUP_DIR"
    fi

    print_step "Creating directory: $INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"

    # Secure directory permissions
    chmod 700 "$INSTALL_DIR"

    # Set trap for error handling
    trap 'restore_backup' ERR

    cd "$INSTALL_DIR"

    # Create docker-compose.yml
    print_step "Creating docker-compose.yml..."
    cat > docker-compose.yml <<EOF
services:
  ad-collector:
    image: fuskerrs97/ad-collector-n8n:latest
    container_name: ad-collector
    restart: unless-stopped
    ports:
      - "$PORT:8443"
    env_file:
      - .env
    environment:
      # Show token on first installation (you can remove this after getting the token)
      - SHOW_TOKEN=true
      # Bind to all interfaces inside container (required for Docker port mapping)
      - BIND_ADDRESS=0.0.0.0
    volumes:
      - ./certs:/app/certs:ro
      - ./token-data:/app/token-data
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://127.0.0.1:8443/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 5s
EOF

    # Create .env
    print_step "Creating .env configuration..."
    cat > .env <<EOF
# ============================================================================
# AD Collector Configuration v2.3.0
# ============================================================================

# ============================================================================
# Active Directory Configuration
# ============================================================================
LDAP_URL=$LDAP_URL
LDAP_BASE_DN=$LDAP_BASE_DN
LDAP_BIND_DN=$LDAP_BIND_DN
LDAP_BIND_PASSWORD=$LDAP_BIND_PASSWORD

# ============================================================================
# TLS/Security Settings
# ============================================================================
# TLS certificate verification (default: true for security)
LDAP_TLS_VERIFY=$LDAP_TLS_VERIFY

# Skip certificate hostname verification (default: false)
# LDAP_SKIP_CERT_HOSTNAME_CHECK=false

# LDAP connection timeouts (milliseconds)
# LDAP_TIMEOUT=10000
# LDAP_CONNECT_TIMEOUT=5000

# ============================================================================
# Network & Binding (v2.3.0 Security Enhancement)
# ============================================================================
# Binding address (default: 127.0.0.1 for localhost only)
# Set to 0.0.0.0 to expose on all interfaces (requires proper firewall)
# BIND_ADDRESS=127.0.0.1

# Port for the collector service
PORT=8443

# ============================================================================
# JWT Authentication (v2.3.0 Security Enhancement)
# ============================================================================
# Token expiration time (default: 1h)
# Examples: 1h, 24h, 7d, 30d
TOKEN_EXPIRY=$TOKEN_EXPIRY

# Token usage quota (v2.4.0 Security Enhancement)
# Maximum number of times a token can be used before being exhausted
# Default: 3 uses per token (prevents stolen token abuse)
# Set to 'unlimited' or '0' to disable quota
# TOKEN_MAX_USES=3

# Show token in startup logs (default: false)
# WARNING: Only set to 'true' in development/testing environments
# SHOW_TOKEN=false

# Provide your own API token (optional, auto-generated if not set)
# API_TOKEN=your-secure-token-here

# ============================================================================
# Rate Limiting (v2.3.0 Security Enhancement)
# ============================================================================
# Enable rate limiting (default: true)
# RATE_LIMIT_ENABLED=true

# Rate limit window in milliseconds (default: 60000 = 1 minute)
# RATE_LIMIT_WINDOW_MS=60000

# Maximum requests per window (default: 100)
# RATE_LIMIT_MAX_REQUESTS=100

# ============================================================================
# Access Control (v2.3.0 Security Enhancement)
# ============================================================================
# Read-only mode - disables all modification endpoints (default: false)
# When enabled: only queries allowed, no create/modify/delete operations
# READ_ONLY_MODE=false

# ============================================================================
# Notes:
# ============================================================================
# - Lines starting with # are comments
# - Uncomment (remove #) to activate optional settings
# - Changes require container restart: docker compose restart
# - Security best practices:
#   * Use BIND_ADDRESS=127.0.0.1 and reverse proxy with TLS
#   * Keep TOKEN_EXPIRY short (1h-24h) for production
#   * Keep TOKEN_MAX_USES low (3-10) to limit stolen token impact
#   * Enable LDAP_TLS_VERIFY=true for production
#   * Consider READ_ONLY_MODE=true for monitoring-only deployments
# ============================================================================
EOF

    # Secure .env file
    chmod 600 .env

    # Handle certificate
    if [ "$CERT_CONTENT" = "AUTO_FETCH" ]; then
        # Automatically fetch certificate from AD
        auto_fetch_certificate
    elif [ -n "$CERT_CONTENT" ]; then
        # Manual certificate was provided
        print_step "Creating AD Root CA certificate..."
        mkdir -p ./certs
        echo "$CERT_CONTENT" > ./certs/ad-root-ca.crt
        chmod 644 ./certs/ad-root-ca.crt
        print_success "Certificate saved to ./certs/ad-root-ca.crt"
    fi

    # Create token-data directory for token file persistence
    mkdir -p ./token-data
    chmod 700 ./token-data

    print_success "Project created at $INSTALL_DIR"
}

pull_and_start() {
    print_header "Starting AD Collector"

    print_step "Pulling Docker image from Docker Hub..."
    $DOCKER_COMPOSE_CMD pull

    print_step "Starting container..."
    $DOCKER_COMPOSE_CMD up -d

    print_step "Waiting for container to be ready..."
    sleep 5

    # Check container status
    if $DOCKER_COMPOSE_CMD ps | grep -q "Up"; then
        print_success "Container started successfully"
    else
        print_error "Container failed to start"
        echo ""
        echo "Logs:"
        $DOCKER_COMPOSE_CMD logs
        exit 1
    fi
}

get_token() {
    print_step "Retrieving API token..."

    sleep 3  # Wait for container to start and write token file

    # Try to read from token file (primary method since v2.4.0)
    if [ -f "./token-data/ad-collector-token.txt" ]; then
        TOKEN=$(cat ./token-data/ad-collector-token.txt 2>/dev/null | tr -d '\n')
    fi

    # Fallback to logs if token file doesn't exist
    if [ -z "$TOKEN" ]; then
        TOKEN=$($DOCKER_COMPOSE_CMD logs ad-collector 2>/dev/null | grep -oP 'API Token:\s*\K[^\s]+' | head -1)
    fi

    if [ -z "$TOKEN" ]; then
        # Second fallback method
        TOKEN=$($DOCKER_COMPOSE_CMD logs ad-collector 2>/dev/null | grep -A 1 "API Token:" | tail -1 | sed 's/.*| //' | xargs)
    fi

    if [ -z "$TOKEN" ]; then
        print_warning "Could not retrieve token automatically"
        print_info "Check: cat $INSTALL_DIR/token-data/ad-collector-token.txt"
        print_info "Or run: $DOCKER_COMPOSE_CMD logs | grep 'API Token'"
    else
        print_success "Token retrieved from file"
    fi
}

################################################################################
# Network Testing
################################################################################

test_network_connectivity() {
    print_header "Network Connectivity Tests"

    # Extract LDAP host and port
    LDAP_HOST=$(echo "$LDAP_URL" | sed -E 's|ldaps?://([^:]+).*|\1|')
    LDAP_PORT=$(echo "$LDAP_URL" | grep -oP ':\K[0-9]+$' || echo "636")

    print_step "Testing connectivity to $LDAP_HOST:$LDAP_PORT..."

    # Test 1: DNS resolution
    if command -v nslookup &> /dev/null; then
        if nslookup "$LDAP_HOST" &> /dev/null; then
            print_success "DNS resolution successful"
        else
            print_warning "DNS resolution failed for $LDAP_HOST"
        fi
    fi

    # Test 2: Port connectivity
    if timeout 5 bash -c "cat < /dev/null > /dev/tcp/$LDAP_HOST/$LDAP_PORT" 2>/dev/null; then
        print_success "Port $LDAP_PORT is reachable on $LDAP_HOST"
    else
        print_error "Cannot reach $LDAP_HOST:$LDAP_PORT"
        print_warning "Check firewall rules and network connectivity"
        print_info "You may need to open port $LDAP_PORT in your firewall"

        read -p "Continue anyway? (y/n): " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi

    # Test 3: Check local firewall for collector port
    print_step "Checking if port $PORT is available..."
    if command -v netstat &> /dev/null; then
        if netstat -tuln 2>/dev/null | grep -q ":$PORT "; then
            print_warning "Port $PORT is already in use"
            read -p "Continue anyway? (y/n): " -n 1 -r
            echo ""
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        else
            print_success "Port $PORT is available"
        fi
    fi
}

################################################################################
# Testing
################################################################################

test_connection() {
    print_header "Connection Tests"

    # Get server IP
    SERVER_IP=$(hostname -I | awk '{print $1}')

    # Test 1: Health check
    print_step "Test 1/3: Health check..."
    HEALTH_RESPONSE=$(curl -s http://localhost:$PORT/health 2>/dev/null || echo "failed")

    if echo "$HEALTH_RESPONSE" | grep -q '"status":"ok"'; then
        print_success "Health check passed"
        HEALTH_STATUS="✅ OK"
    else
        print_error "Health check failed"
        HEALTH_STATUS="❌ Failed"
    fi

    # Test 2: LDAP connection
    print_step "Test 2/3: LDAP connection test..."
    if [ -n "$TOKEN" ]; then
        LDAP_RESPONSE=$(curl -s -X POST http://localhost:$PORT/api/test-connection \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" 2>/dev/null || echo "failed")

        if echo "$LDAP_RESPONSE" | grep -q '"connected":true'; then
            print_success "LDAP connection successful"
            LDAP_STATUS="✅ Connected"
        else
            print_error "LDAP connection failed"
            LDAP_STATUS="❌ Failed"
            echo "Response: $LDAP_RESPONSE"
        fi
    else
        print_warning "Skipping LDAP test (no token)"
        LDAP_STATUS="⚠️ Skipped"
    fi

    # Test 3: Network accessibility
    print_step "Test 3/3: Network accessibility..."
    if curl -s http://$SERVER_IP:$PORT/health &>/dev/null; then
        print_success "Accessible from network"
        NETWORK_STATUS="✅ Accessible"
    else
        print_warning "May not be accessible from other machines"
        NETWORK_STATUS="⚠️ Check firewall"
    fi
}

################################################################################
# Final Summary
################################################################################

show_summary() {
    print_header "Installation Complete!"

    # Get server IP
    SERVER_IP=$(hostname -I | awk '{print $1}')

    # Summary table
    echo ""
    echo -e "${BOLD}╔════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║                    AD Collector Installation Summary                  ║${NC}"
    echo -e "${BOLD}╠════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BOLD}║ Service Information                                                    ║${NC}"
    echo -e "${BOLD}╠════════════════════════════════════════════════════════════════════════╣${NC}"
    printf "║ %-30s %-41s ║\n" "Container Status:" "$($DOCKER_COMPOSE_CMD ps --format '{{.State}}' 2>/dev/null | head -1)"
    printf "║ %-30s %-41s ║\n" "Health Status:" "$HEALTH_STATUS"
    printf "║ %-30s %-41s ║\n" "LDAP Connection:" "$LDAP_STATUS"
    printf "║ %-30s %-41s ║\n" "Network Status:" "$NETWORK_STATUS"
    echo -e "${BOLD}╠════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BOLD}║ Connection Details                                                     ║${NC}"
    echo -e "${BOLD}╠════════════════════════════════════════════════════════════════════════╣${NC}"
    printf "║ %-30s %-41s ║\n" "Local URL:" "http://localhost:$PORT"
    printf "║ %-30s %-41s ║\n" "Network URL:" "http://$SERVER_IP:$PORT"
    printf "║ %-30s %-41s ║\n" "Health Endpoint:" "http://$SERVER_IP:$PORT/health"
    echo -e "${BOLD}╠════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BOLD}║ Active Directory Settings                                              ║${NC}"
    echo -e "${BOLD}╠════════════════════════════════════════════════════════════════════════╣${NC}"
    printf "║ %-30s %-41s ║\n" "LDAP URL:" "${LDAP_URL:0:41}"
    printf "║ %-30s %-41s ║\n" "Base DN:" "${LDAP_BASE_DN:0:41}"
    printf "║ %-30s %-41s ║\n" "TLS Verify:" "$LDAP_TLS_VERIFY"
    echo -e "${BOLD}╚════════════════════════════════════════════════════════════════════════╝${NC}"

    # Token displayed SEPARATELY for easy copy-paste
    echo ""
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${YELLOW}🔑 Your API Token (save this!)${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    if [ -n "$TOKEN" ]; then
        echo -e "${GREEN}${TOKEN}${NC}"
        echo ""
        echo -e "${YELLOW}⚠️  IMPORTANT: This token will not be shown again after this installation.${NC}"
        echo -e "${YELLOW}   Copy it now and store it securely!${NC}"
        echo ""
        echo -e "${CYAN}   Token is also saved to: ${INSTALL_DIR}/token-data/ad-collector-token.txt${NC}"
        echo -e "${CYAN}   Remove SHOW_TOKEN=true from docker-compose.yml for production${NC}"
    else
        echo -e "${RED}Could not retrieve token automatically.${NC}"
        echo -e "${YELLOW}Check: cat $INSTALL_DIR/token-data/ad-collector-token.txt${NC}"
        echo -e "${YELLOW}Or run: docker compose logs | grep 'API Token'${NC}"
    fi
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo ""

    echo -e "${BOLD}${GREEN}Next Steps:${NC}"
    echo ""
    echo -e "  ${BOLD}1. Copy your API token${NC} (displayed above)"
    echo ""
    echo -e "  ${BOLD}2. Configure n8n credentials:${NC}"
    echo -e "     • Go to n8n → Credentials → Active Directory API"
    echo -e "     • Connection Mode: ${CYAN}Collector${NC}"
    echo -e "     • Collector URL: ${CYAN}http://$SERVER_IP:$PORT${NC}"
    echo -e "     • API Token: ${CYAN}[paste token from above]${NC}"
    echo -e "     • Skip SSL Verification: ${CYAN}✓ Checked${NC}"
    echo ""
    echo -e "  ${BOLD}3. Useful commands:${NC}"
    echo -e "     • View logs:          ${CYAN}cd $INSTALL_DIR && docker compose logs -f${NC}"
    echo -e "     • View token:         ${CYAN}cat $INSTALL_DIR/token${NC}"
    echo -e "     • Stop collector:     ${CYAN}cd $INSTALL_DIR && docker compose stop${NC}"
    echo -e "     • Start collector:    ${CYAN}cd $INSTALL_DIR && docker compose start${NC}"
    echo -e "     • Restart:            ${CYAN}cd $INSTALL_DIR && docker compose restart${NC}"
    echo -e "     • Remove:             ${CYAN}cd $INSTALL_DIR && docker compose down${NC}"
    echo ""
    echo -e "  ${BOLD}4. Documentation:${NC}"
    echo -e "     • Docker Hub: ${CYAN}https://hub.docker.com/r/fuskerrs97/ad-collector-n8n${NC}"
    echo -e "     • GitHub:     ${CYAN}https://github.com/Fuskerrs/docker-ad-collector-n8n${NC}"
    echo ""

    # Save summary to file
    SUMMARY_FILE="$INSTALL_DIR/INSTALLATION_SUMMARY.txt"
    {
        echo "AD Collector Installation Summary"
        echo "=================================="
        echo ""
        echo "Installation Date: $(date)"
        echo "Installation Directory: $INSTALL_DIR"
        echo ""
        echo "Connection Details:"
        echo "  Local URL: http://localhost:$PORT"
        echo "  Network URL: http://$SERVER_IP:$PORT"
        echo ""
        echo "API Token:"
        echo "$TOKEN"
        echo ""
        echo "LDAP Configuration:"
        echo "  URL: $LDAP_URL"
        echo "  Base DN: $LDAP_BASE_DN"
        echo "  Bind DN: $LDAP_BIND_DN"
        echo "  TLS Verify: $LDAP_TLS_VERIFY"
    } > "$SUMMARY_FILE"

    print_info "Installation summary saved to: $SUMMARY_FILE"
}

################################################################################
# Utility Functions
################################################################################

reset_token() {
    print_header "Resetting API Token"

    if [ ! -f "docker-compose.yml" ]; then
        print_error "Not in AD Collector directory"
        print_info "cd to your installation directory first"
        exit 1
    fi

    # Initialize Docker Compose command
    if ! detect_docker_compose; then
        print_error "Docker Compose is required"
        exit 1
    fi

    print_step "Restarting container to generate new token..."
    $DOCKER_COMPOSE_CMD restart

    sleep 3

    # More robust token extraction
    NEW_TOKEN=$($DOCKER_COMPOSE_CMD logs ad-collector 2>/dev/null | grep -oP 'API Token:\s*\K[^\s]+' | head -1)

    if [ -z "$NEW_TOKEN" ]; then
        # Fallback
        NEW_TOKEN=$($DOCKER_COMPOSE_CMD logs ad-collector 2>/dev/null | grep -A 1 "API Token:" | tail -1 | sed 's/.*| //' | xargs)
    fi

    if [ -n "$NEW_TOKEN" ]; then
        echo ""
        print_success "New token generated:"
        echo ""
        echo -e "${CYAN}$NEW_TOKEN${NC}"
        echo ""
    else
        print_error "Could not retrieve new token"
        print_info "Run: $DOCKER_COMPOSE_CMD logs | grep 'API Token'"
    fi
}

show_token() {
    if [ ! -f "docker-compose.yml" ]; then
        print_error "Not in AD Collector directory"
        exit 1
    fi

    # Initialize Docker Compose command
    if ! detect_docker_compose; then
        print_error "Docker Compose is required"
        exit 1
    fi

    print_step "Retrieving current token..."

    # Try to read from token file first
    if [ -f "./token" ]; then
        CURRENT_TOKEN=$(cat ./token 2>/dev/null | tr -d '\n')
    fi

    # Fallback to logs if token file doesn't exist
    if [ -z "$CURRENT_TOKEN" ]; then
        CURRENT_TOKEN=$($DOCKER_COMPOSE_CMD logs ad-collector 2>/dev/null | grep -oP 'API Token:\s*\K[^\s]+' | head -1)
    fi

    if [ -z "$CURRENT_TOKEN" ]; then
        # Second fallback
        CURRENT_TOKEN=$($DOCKER_COMPOSE_CMD logs ad-collector 2>/dev/null | grep -A 1 "API Token:" | tail -1 | sed 's/.*| //' | xargs)
    fi

    if [ -n "$CURRENT_TOKEN" ]; then
        echo ""
        echo -e "${BOLD}Current API Token:${NC}"
        echo ""
        echo -e "${CYAN}$CURRENT_TOKEN${NC}"
        echo ""
    else
        print_error "Could not retrieve token"
        print_info "Token file: ./token may not exist"
        print_info "Container may not be running. Start it with: $DOCKER_COMPOSE_CMD up -d"
    fi
}

show_status() {
    if [ ! -f "docker-compose.yml" ]; then
        print_error "Not in AD Collector directory"
        exit 1
    fi

    # Initialize Docker Compose command
    if ! detect_docker_compose; then
        print_error "Docker Compose is required"
        exit 1
    fi

    print_header "AD Collector Status"

    $DOCKER_COMPOSE_CMD ps

    echo ""
    print_step "Health check..."

    PORT=$(grep -E "^\s*-\s*\"[0-9]+:8443\"" docker-compose.yml | sed 's/.*"\([0-9]*\):.*/\1/')
    HEALTH=$(curl -s http://localhost:$PORT/health 2>/dev/null || echo "failed")

    if echo "$HEALTH" | grep -q '"status":"ok"'; then
        print_success "Service is healthy"
        # Validate python3 is available
        if command -v python3 &> /dev/null; then
            echo "$HEALTH" | python3 -m json.tool 2>/dev/null || echo "$HEALTH"
        else
            echo "$HEALTH"
        fi
    else
        print_error "Service is not responding"
    fi
}

update() {
    print_header "Updating AD Collector"

    if [ ! -f "docker-compose.yml" ]; then
        print_error "Not in AD Collector directory"
        print_info "cd to your installation directory first"
        exit 1
    fi

    # Initialize Docker Compose command
    if ! detect_docker_compose; then
        print_error "Docker Compose is required"
        exit 1
    fi

    print_step "Creating backup of current configuration..."
    cp .env .env.backup.$(date +%Y%m%d_%H%M%S)
    print_success "Configuration backed up"

    print_step "Pulling latest Docker image..."
    $DOCKER_COMPOSE_CMD pull

    print_step "Restarting with new image..."
    $DOCKER_COMPOSE_CMD up -d

    print_step "Waiting for container to be ready..."
    sleep 5

    # Check if update was successful
    if $DOCKER_COMPOSE_CMD ps | grep -q "Up"; then
        print_success "Update completed successfully"

        # Show new version
        NEW_VERSION=$(curl -s http://localhost:8443/health 2>/dev/null | grep -oP '"version":"[^"]+' | cut -d'"' -f4)
        if [ -n "$NEW_VERSION" ]; then
            print_info "Current version: $NEW_VERSION"
        fi
    else
        print_error "Update failed - container not running"
        print_info "Check logs: $DOCKER_COMPOSE_CMD logs"
    fi
}

uninstall() {
    print_header "Uninstalling AD Collector"

    if [ ! -f "docker-compose.yml" ]; then
        print_error "Not in AD Collector directory"
        exit 1
    fi

    # Initialize Docker Compose command
    if ! detect_docker_compose; then
        print_error "Docker Compose is required"
        exit 1
    fi

    print_warning "This will remove the container and all data"
    read -p "Are you sure? (yes/no): " -r

    if [ "$REPLY" != "yes" ]; then
        print_info "Uninstall cancelled"
        exit 0
    fi

    print_step "Stopping and removing container..."
    $DOCKER_COMPOSE_CMD down

    print_step "Removing Docker image..."
    docker rmi fuskerrs97/ad-collector-n8n:latest 2>/dev/null || true

    CURRENT_DIR=$(pwd)
    cd ..

    print_step "Removing installation directory..."
    read -p "Remove directory $CURRENT_DIR? (y/n): " -n 1 -r
    echo ""

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$CURRENT_DIR"
        print_success "Uninstall complete"
    else
        print_info "Directory preserved: $CURRENT_DIR"
    fi
}

################################################################################
# Main
################################################################################

show_usage() {
    echo "AD Collector for n8n - Installation Script"
    echo ""
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  (no option)        Run interactive installation"
    echo "  --update           Update to latest version"
    echo "  --reset-token      Regenerate API token"
    echo "  --get-token        Display current API token"
    echo "  --status           Show collector status"
    echo "  --uninstall        Remove AD Collector"
    echo "  --help             Show this help message"
    echo ""
}

main() {
    # Parse arguments
    case "${1:-}" in
        --update)
            update
            exit 0
            ;;
        --reset-token)
            reset_token
            exit 0
            ;;
        --get-token)
            show_token
            exit 0
            ;;
        --status)
            show_status
            exit 0
            ;;
        --uninstall)
            uninstall
            exit 0
            ;;
        --help)
            show_usage
            exit 0
            ;;
        "")
            # Continue with installation
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac

    # Installation flow
    print_header "AD Collector for n8n - Installation"

    echo -e "${BOLD}This script will install and configure AD Collector${NC}"
    echo ""

    check_root
    detect_os
    check_disk_space
    check_memory
    check_curl
    check_ldap_utils

    if ! check_docker; then
        read -p "Docker is not installed. Install it now? (y/n): " -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            install_docker
        else
            print_error "Docker is required. Please install it manually."
            exit 1
        fi
    fi

    # Detect Docker Compose version
    if ! detect_docker_compose; then
        print_error "Docker Compose is required but could not be installed"
        exit 1
    fi

    show_prerequisites
    get_user_input
    show_configuration_summary
    test_network_connectivity
    create_project
    pull_and_start
    get_token
    test_connection
    show_summary

    echo ""
    print_success "Installation completed successfully! 🎉"
    echo ""

    # Cleanup: Remove token file after user confirmation
    if [ -f "$INSTALL_DIR/token-data/ad-collector-token.txt" ]; then
        echo ""
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${BOLD}Security Cleanup${NC}"
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "${YELLOW}The API token is currently saved in: ${INSTALL_DIR}/token-data/ad-collector-token.txt${NC}"
        echo -e "${YELLOW}For security, it's recommended to delete this file after copying the token.${NC}"
        echo ""
        read -p "Press ENTER to delete the token file (or Ctrl+C to keep it)... "

        rm -f "$INSTALL_DIR/token-data/ad-collector-token.txt"
        print_success "Token file deleted for security"
        echo -e "${CYAN}You can still view the token in logs with: docker compose logs | grep 'API Token'${NC}"
        echo ""
    fi
}

# Run main function
main "$@"
