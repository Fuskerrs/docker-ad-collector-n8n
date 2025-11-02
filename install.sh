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

################################################################################
# Interactive Configuration
################################################################################

get_user_input() {
    print_header "Configuration"

    # Check if running in non-interactive mode
    if [ ! -t 0 ]; then
        echo ""
        print_error "This script requires interactive input for configuration."
        echo ""
        echo -e "${BOLD}You are running this script in non-interactive mode (e.g., via 'curl | bash').${NC}"
        echo ""
        echo -e "${CYAN}To install AD Collector, please use one of these methods:${NC}"
        echo ""
        echo -e "${BOLD}Method 1: Download and run (Recommended)${NC}"
        echo -e "  ${YELLOW}wget https://raw.githubusercontent.com/Fuskerrs/docker-ad-collector-n8n/main/install.sh${NC}"
        echo -e "  ${YELLOW}chmod +x install.sh${NC}"
        echo -e "  ${YELLOW}./install.sh${NC}"
        echo ""
        echo -e "${BOLD}Method 2: Use Docker Compose directly${NC}"
        echo -e "  See: ${CYAN}https://github.com/Fuskerrs/docker-ad-collector-n8n#installation${NC}"
        echo ""
        exit 1
    fi

    echo -e "${BOLD}Please provide the following information:${NC}"
    echo ""

    # Installation directory
    read -p "Installation directory [$INSTALL_DIR]: " input
    INSTALL_DIR=${input:-$INSTALL_DIR}

    # LDAP URL
    echo ""
    echo -e "${YELLOW}Active Directory Configuration:${NC}"
    while true; do
        read -p "LDAP/LDAPS URL (e.g., ldaps://dc.example.com:636): " LDAP_URL
        if [[ $LDAP_URL =~ ^ldaps?:// ]]; then
            break
        else
            print_error "Invalid LDAP URL. Must start with ldap:// or ldaps://"
        fi
    done

    # Base DN
    while true; do
        read -p "Base DN (e.g., DC=example,DC=com): " LDAP_BASE_DN
        if [[ $LDAP_BASE_DN =~ DC= ]]; then
            break
        else
            print_error "Invalid Base DN. Must contain DC="
        fi
    done

    # Bind DN
    while true; do
        read -p "Bind DN (e.g., CN=service,CN=Users,DC=example,DC=com): " LDAP_BIND_DN
        if [[ -n $LDAP_BIND_DN ]]; then
            break
        else
            print_error "Bind DN cannot be empty"
        fi
    done

    # Bind Password
    while true; do
        read -sp "Bind Password: " LDAP_BIND_PASSWORD
        echo ""
        if [[ -n $LDAP_BIND_PASSWORD ]]; then
            read -sp "Confirm Password: " LDAP_BIND_PASSWORD_CONFIRM
            echo ""
            if [ "$LDAP_BIND_PASSWORD" = "$LDAP_BIND_PASSWORD_CONFIRM" ]; then
                break
            else
                print_error "Passwords do not match"
            fi
        else
            print_error "Password cannot be empty"
        fi
    done

    # TLS Verify
    echo ""
    read -p "Verify TLS certificates? (y/n) [n]: " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        LDAP_TLS_VERIFY="true"
    else
        LDAP_TLS_VERIFY="false"
    fi

    # Port
    echo ""
    read -p "Collector port [$DEFAULT_PORT]: " input
    PORT=${input:-$DEFAULT_PORT}

    # Token expiry
    read -p "Token expiry (e.g., 365d, 1y) [365d]: " input
    TOKEN_EXPIRY=${input:-365d}
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
# Installation
################################################################################

create_project() {
    print_header "Creating Project"

    print_step "Creating directory: $INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"
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
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:8443/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 5s
EOF

    # Create .env
    print_step "Creating .env configuration..."
    cat > .env <<EOF
# Active Directory Configuration
LDAP_URL=$LDAP_URL
LDAP_BASE_DN=$LDAP_BASE_DN
LDAP_BIND_DN=$LDAP_BIND_DN
LDAP_BIND_PASSWORD=$LDAP_BIND_PASSWORD

# Security Settings
LDAP_TLS_VERIFY=$LDAP_TLS_VERIFY

# Optional Settings
PORT=8443
TOKEN_EXPIRY=$TOKEN_EXPIRY
EOF

    # Secure .env file
    chmod 600 .env

    print_success "Project created at $INSTALL_DIR"
}

pull_and_start() {
    print_header "Starting AD Collector"

    print_step "Pulling Docker image from Docker Hub..."
    docker compose pull

    print_step "Starting container..."
    docker compose up -d

    print_step "Waiting for container to be ready..."
    sleep 5

    # Check container status
    if docker compose ps | grep -q "Up"; then
        print_success "Container started successfully"
    else
        print_error "Container failed to start"
        echo ""
        echo "Logs:"
        docker compose logs
        exit 1
    fi
}

get_token() {
    print_step "Retrieving API token..."

    sleep 2
    TOKEN=$(docker compose logs ad-collector 2>/dev/null | grep -A 1 "API Token:" | tail -1 | sed 's/ad-collector  | //' | xargs)

    if [ -z "$TOKEN" ]; then
        print_warning "Could not retrieve token automatically"
        print_info "Run: docker compose logs | grep 'API Token'"
    else
        print_success "Token retrieved"
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
    printf "║ %-30s %-41s ║\n" "Container Status:" "$(docker compose ps --format '{{.State}}' 2>/dev/null | head -1)"
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
    echo -e "${BOLD}╠════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BOLD}║ API Token (save this!)                                                 ║${NC}"
    echo -e "${BOLD}╠════════════════════════════════════════════════════════════════════════╣${NC}"

    if [ -n "$TOKEN" ]; then
        # Split token in lines of 70 chars
        echo "$TOKEN" | fold -w 70 | while read line; do
            printf "║ %-72s ║\n" "$line"
        done
    else
        printf "║ %-72s ║\n" "Run: docker compose logs | grep 'API Token'"
    fi

    echo -e "${BOLD}╚════════════════════════════════════════════════════════════════════════╝${NC}"

    echo ""
    echo -e "${BOLD}${GREEN}Next Steps:${NC}"
    echo ""
    echo -e "  ${BOLD}1.${NC} Configure n8n credentials:"
    echo -e "     • Connection Mode: ${CYAN}Collector${NC}"
    echo -e "     • Collector URL: ${CYAN}http://$SERVER_IP:$PORT${NC}"
    echo -e "     • API Token: ${CYAN}[token above]${NC}"
    echo -e "     • Skip SSL Verification: ${CYAN}✓ Checked${NC}"
    echo ""
    echo -e "  ${BOLD}2.${NC} Useful commands:"
    echo -e "     • View logs:        ${CYAN}cd $INSTALL_DIR && docker compose logs -f${NC}"
    echo -e "     • Stop collector:   ${CYAN}cd $INSTALL_DIR && docker compose stop${NC}"
    echo -e "     • Start collector:  ${CYAN}cd $INSTALL_DIR && docker compose start${NC}"
    echo -e "     • Restart (new token): ${CYAN}cd $INSTALL_DIR && docker compose restart${NC}"
    echo -e "     • Remove:           ${CYAN}cd $INSTALL_DIR && docker compose down${NC}"
    echo ""
    echo -e "  ${BOLD}3.${NC} Documentation:"
    echo -e "     • Docker Hub: ${CYAN}https://hub.docker.com/r/fuskerrs97/ad-collector-n8n${NC}"
    echo -e "     • GitHub: ${CYAN}https://github.com/Fuskerrs/docker-ad-collector-n8n${NC}"
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

    print_step "Restarting container to generate new token..."
    docker compose restart

    sleep 3

    NEW_TOKEN=$(docker compose logs ad-collector 2>/dev/null | grep -A 1 "API Token:" | tail -1 | sed 's/ad-collector  | //' | xargs)

    if [ -n "$NEW_TOKEN" ]; then
        echo ""
        print_success "New token generated:"
        echo ""
        echo -e "${CYAN}$NEW_TOKEN${NC}"
        echo ""
    else
        print_error "Could not retrieve new token"
        print_info "Run: docker compose logs | grep 'API Token'"
    fi
}

show_token() {
    if [ ! -f "docker-compose.yml" ]; then
        print_error "Not in AD Collector directory"
        exit 1
    fi

    print_step "Retrieving current token..."

    CURRENT_TOKEN=$(docker compose logs ad-collector 2>/dev/null | grep -A 1 "API Token:" | tail -1 | sed 's/ad-collector  | //' | xargs)

    if [ -n "$CURRENT_TOKEN" ]; then
        echo ""
        echo -e "${BOLD}Current API Token:${NC}"
        echo ""
        echo -e "${CYAN}$CURRENT_TOKEN${NC}"
        echo ""
    else
        print_error "Could not retrieve token"
        print_info "Container may not be running. Start it with: docker compose up -d"
    fi
}

show_status() {
    if [ ! -f "docker-compose.yml" ]; then
        print_error "Not in AD Collector directory"
        exit 1
    fi

    print_header "AD Collector Status"

    docker compose ps

    echo ""
    print_step "Health check..."

    PORT=$(grep -E "^\s*-\s*\"[0-9]+:8443\"" docker-compose.yml | sed 's/.*"\([0-9]*\):.*/\1/')
    HEALTH=$(curl -s http://localhost:$PORT/health 2>/dev/null || echo "failed")

    if echo "$HEALTH" | grep -q '"status":"ok"'; then
        print_success "Service is healthy"
        echo "$HEALTH" | python3 -m json.tool 2>/dev/null || echo "$HEALTH"
    else
        print_error "Service is not responding"
    fi
}

uninstall() {
    print_header "Uninstalling AD Collector"

    if [ ! -f "docker-compose.yml" ]; then
        print_error "Not in AD Collector directory"
        exit 1
    fi

    print_warning "This will remove the container and all data"
    read -p "Are you sure? (yes/no): " -r

    if [ "$REPLY" != "yes" ]; then
        print_info "Uninstall cancelled"
        exit 0
    fi

    print_step "Stopping and removing container..."
    docker compose down

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

    get_user_input
    show_configuration_summary
    create_project
    pull_and_start
    get_token
    test_connection
    show_summary

    echo ""
    print_success "Installation completed successfully! 🎉"
    echo ""
}

# Run main function
main "$@"
