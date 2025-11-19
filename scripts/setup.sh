#!/bin/bash
#
# setup.sh - Install and configure safe-apt system
#
# This script sets up the complete safe-apt environment including
# directory structure, dependencies, and configuration.
#

set -euo pipefail

# Configuration
INSTALL_DIR="${INSTALL_DIR:-/opt/apt-mirror-system}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
SCANNER_TYPE="${SCANNER_TYPE:-trivy}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        log "Please run: sudo $0"
        exit 1
    fi
}

check_dependencies() {
    log "Checking system dependencies..."

    local missing_deps=()

    # Check for required commands
    for cmd in aptly gpg nginx python3 pip3; do
        if ! command -v "${cmd}" &> /dev/null; then
            missing_deps+=("${cmd}")
        fi
    done

    # Check for scanner
    if [ "${SCANNER_TYPE}" = "trivy" ]; then
        if ! command -v trivy &> /dev/null; then
            missing_deps+=("trivy")
        fi
    elif [ "${SCANNER_TYPE}" = "grype" ]; then
        if ! command -v grype &> /dev/null; then
            missing_deps+=("grype")
        fi
    fi

    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log "Please install missing dependencies and re-run setup"
        log ""
        log "Installation commands:"
        log "  Ubuntu/Debian: apt-get install aptly gnupg nginx python3 python3-pip"
        log "  Trivy: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
        log "  Grype: https://github.com/anchore/grype#installation"
        exit 1
    fi

    log "All dependencies satisfied"
}

create_directories() {
    log "Creating directory structure..."

    mkdir -p "${INSTALL_DIR}"/{scans,snapshots,approvals,logs,scripts}
    mkdir -p /var/lib/aptly
    mkdir -p /var/log/apt-mirror-system

    # Set permissions
    chmod 755 "${INSTALL_DIR}"
    chmod 755 "${INSTALL_DIR}"/{scans,snapshots,approvals,logs,scripts}

    log "Directories created"
}

install_python_packages() {
    log "Installing Python dependencies..."

    ${PYTHON_BIN} -m pip install -r "${REPO_DIR}/requirements.txt"

    log "Python dependencies installed"
}

copy_scripts() {
    log "Copying scripts to ${INSTALL_DIR}/scripts..."

    cp "${REPO_DIR}"/scripts/*.sh "${INSTALL_DIR}/scripts/"
    chmod +x "${INSTALL_DIR}"/scripts/*.sh

    log "Scripts installed"
}

setup_configuration() {
    log "Setting up configuration..."

    local config_file="${INSTALL_DIR}/config.yaml"

    if [ -f "${config_file}" ]; then
        log_warning "Configuration file already exists: ${config_file}"
        log_warning "Skipping configuration setup"
        return
    fi

    # Copy template
    cp "${REPO_DIR}/config/config.yaml.example" "${config_file}"

    log "Configuration template created at ${config_file}"
    log "Please edit this file to customize your setup"
}

setup_aptly() {
    log "Setting up Aptly mirror..."

    # Check if aptly is configured
    if [ ! -f ~/.aptly.conf ]; then
        log "Creating default Aptly configuration..."

        cat > ~/.aptly.conf <<EOF
{
  "rootDir": "/var/lib/aptly",
  "downloadConcurrency": 4,
  "downloadSpeedLimit": 0,
  "architectures": ["amd64"],
  "dependencyFollowSuggests": false,
  "dependencyFollowRecommends": false,
  "dependencyFollowAllVariants": false,
  "dependencyFollowSource": false,
  "dependencyVerboseResolve": false,
  "gpgDisableSign": false,
  "gpgDisableVerify": false,
  "gpgProvider": "gpg",
  "downloadSourcePackages": false,
  "skipLegacyPool": true,
  "ppaDistributorID": "ubuntu",
  "ppaCodename": "",
  "skipContentsPublishing": false,
  "FileSystemPublishEndpoints": {},
  "S3PublishEndpoints": {},
  "SwiftPublishEndpoints": {}
}
EOF
    fi

    log "Aptly configuration ready"
    log_warning "You need to manually create mirrors using 'aptly mirror create'"
}

setup_nginx() {
    log "Setting up Nginx configuration..."

    local nginx_config_src="${REPO_DIR}/config/nginx-apt-mirror.conf.example"
    local nginx_config_dst="/etc/nginx/sites-available/apt-mirror"

    if [ -f "${nginx_config_dst}" ]; then
        log_warning "Nginx configuration already exists: ${nginx_config_dst}"
        log_warning "Skipping Nginx setup"
        return
    fi

    cp "${nginx_config_src}" "${nginx_config_dst}"

    log "Nginx configuration created at ${nginx_config_dst}"
    log_warning "Please edit the configuration and update:"
    log_warning "  - server_name"
    log_warning "  - SSL certificate paths"
    log_warning "Then enable the site:"
    log_warning "  sudo ln -s /etc/nginx/sites-available/apt-mirror /etc/nginx/sites-enabled/"
    log_warning "  sudo nginx -t"
    log_warning "  sudo systemctl reload nginx"
}

setup_cron() {
    log "Setting up cron jobs..."

    local cron_file="/etc/cron.d/safe-apt"

    if [ -f "${cron_file}" ]; then
        log_warning "Cron file already exists: ${cron_file}"
        log_warning "Skipping cron setup"
        return
    fi

    cat > "${cron_file}" <<EOF
# safe-apt automated pipeline
# Runs daily at 2 AM

# Daily pipeline run
0 2 * * * root ${INSTALL_DIR}/scripts/run-pipeline.sh

# Nightly rescan (at 3 AM)
0 3 * * * root ${INSTALL_DIR}/scripts/rescan-packages.sh \$(aptly snapshot list -raw | grep "^approved-" | sort -r | head -n 1)
EOF

    chmod 644 "${cron_file}"

    log "Cron jobs configured"
    log "Pipeline will run daily at 2:00 AM"
    log "Rescan will run daily at 3:00 AM"
}

print_summary() {
    log ""
    log "========================================="
    log "safe-apt installation complete!"
    log "========================================="
    log ""
    log "Next steps:"
    log "1. Edit configuration: ${INSTALL_DIR}/config.yaml"
    log "2. Create Aptly mirror:"
    log "   aptly mirror create ubuntu-jammy http://archive.ubuntu.com/ubuntu jammy main restricted universe multiverse"
    log "3. Generate GPG key for repository signing (if needed):"
    log "   gpg --full-generate-key"
    log "4. Configure Nginx:"
    log "   - Edit /etc/nginx/sites-available/apt-mirror"
    log "   - Set up SSL certificates"
    log "   - Enable the site and reload nginx"
    log "5. Run the pipeline manually:"
    log "   ${INSTALL_DIR}/scripts/run-pipeline.sh"
    log "6. Configure clients to use the mirror:"
    log "   deb https://apt.internal.example.com jammy main"
    log ""
    log "Documentation: ${REPO_DIR}/README.md"
    log "========================================="
}

main() {
    log "Starting safe-apt setup..."

    check_root
    check_dependencies
    create_directories
    install_python_packages
    copy_scripts
    setup_configuration
    setup_aptly
    setup_nginx
    setup_cron
    print_summary
}

main "$@"
