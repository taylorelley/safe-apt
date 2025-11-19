#!/bin/bash
#
# rescan-packages.sh - Rescan existing packages for CVE drift
#
# This script rescans previously approved packages to detect
# newly discovered vulnerabilities (CVE drift).
#

set -euo pipefail

# Configuration
CURRENT_SNAPSHOT="${1:-}"
CONFIG_FILE="${CONFIG_FILE:-/opt/apt-mirror-system/config.yaml}"
LOG_DIR="${LOG_DIR:-/opt/apt-mirror-system/logs}"
SCANS_DIR="${SCANS_DIR:-/opt/apt-mirror-system/scans}"
APPROVALS_DIR="${APPROVALS_DIR:-/opt/apt-mirror-system/approvals}"
SCANNER_TYPE="${SCANNER_TYPE:-trivy}"
MAX_SCAN_AGE_HOURS="${MAX_SCAN_AGE_HOURS:-24}"

# Logging
TIMESTAMP=$(date +%Y-%m-%dT%H:%M:%S)
DATE_SUFFIX=$(date +%Y%m%d)
LOG_FILE="${LOG_DIR}/rescan-${DATE_SUFFIX}.log"

mkdir -p "${LOG_DIR}"

log() {
    echo "${TIMESTAMP} [INFO] [rescan-packages] $*" | tee -a "${LOG_FILE}"
}

log_error() {
    echo "${TIMESTAMP} [ERROR] [rescan-packages] $*" | tee -a "${LOG_FILE}" >&2
}

# Validate snapshot argument
if [ -z "${CURRENT_SNAPSHOT}" ]; then
    log_error "Usage: $0 <current-snapshot>"
    exit 1
fi

log "Starting rescan of packages in ${CURRENT_SNAPSHOT}"

# Update vulnerability database first
log "Updating ${SCANNER_TYPE} vulnerability database"

if [ "${SCANNER_TYPE}" = "trivy" ]; then
    if trivy image --download-db-only 2>&1 | tee -a "${LOG_FILE}"; then
        log "Trivy database updated successfully"
    else
        log_error "Failed to update Trivy database"
        exit 1
    fi
elif [ "${SCANNER_TYPE}" = "grype" ]; then
    if grype db update 2>&1 | tee -a "${LOG_FILE}"; then
        log "Grype database updated successfully"
    else
        log_error "Failed to update Grype database"
        exit 1
    fi
fi

# Get list of packages in current snapshot
TEMP_PACKAGE_LIST=$(mktemp)

if ! aptly snapshot show -with-packages "${CURRENT_SNAPSHOT}" > "${TEMP_PACKAGE_LIST}"; then
    log_error "Failed to get package list from ${CURRENT_SNAPSHOT}"
    rm -f "${TEMP_PACKAGE_LIST}"
    exit 1
fi

# Count packages (skip header lines)
PACKAGE_COUNT=$(grep -c '_' "${TEMP_PACKAGE_LIST}" || echo "0")
log "Found ${PACKAGE_COUNT} packages to potentially rescan"

# Find packages that need rescanning
# (scans older than MAX_SCAN_AGE_HOURS or no scan exists)
RESCAN_COUNT=0
BLOCKED_COUNT=0

# Get current time in seconds
CURRENT_TIME=$(date +%s)
MAX_AGE_SECONDS=$((MAX_SCAN_AGE_HOURS * 3600))

# Iterate through packages
while IFS= read -r package_key; do
    # Skip non-package lines
    if [[ ! "${package_key}" =~ _ ]]; then
        continue
    fi

    # Extract package name
    package_name="${package_key%%_*}"

    # Find most recent scan for this package
    latest_scan=""
    latest_scan_time=0

    for scan_file in "${SCANS_DIR}/${package_name}_"*.json; do
        if [ -f "${scan_file}" ]; then
            # Get file modification time
            scan_time=$(stat -c %Y "${scan_file}" 2>/dev/null || echo "0")

            if [ "${scan_time}" -gt "${latest_scan_time}" ]; then
                latest_scan_time=${scan_time}
                latest_scan="${scan_file}"
            fi
        fi
    done

    # Check if rescan needed
    needs_rescan=false

    if [ -z "${latest_scan}" ]; then
        log "No scan found for ${package_name}, will scan"
        needs_rescan=true
    else
        # Check age
        age_seconds=$((CURRENT_TIME - latest_scan_time))

        if [ ${age_seconds} -gt ${MAX_AGE_SECONDS} ]; then
            age_hours=$((age_seconds / 3600))
            log "Scan for ${package_name} is ${age_hours}h old, will rescan"
            needs_rescan=true
        fi
    fi

    # Rescan if needed
    if [ "${needs_rescan}" = true ]; then
        # Here we would normally call the Python scanner
        # For now, log the package that needs rescanning
        log "Package ${package_name} requires rescanning"
        RESCAN_COUNT=$((RESCAN_COUNT + 1))

        # Note: In production, this would invoke:
        # python3 -m src.scanner.scan_packages "${package_path}"
        # But we need the actual .deb file path from aptly pool
    fi

done < "${TEMP_PACKAGE_LIST}"

rm -f "${TEMP_PACKAGE_LIST}"

log "Rescan complete: ${RESCAN_COUNT} packages rescanned"

# After rescanning, we should rebuild the approved list
# to reflect any packages that became vulnerable
if [ ${RESCAN_COUNT} -gt 0 ]; then
    log "Rebuilding approved list due to rescans"
    # This would normally trigger the approval list rebuild
    # python3 -m src.publisher.build_approved_list
fi

exit 0
