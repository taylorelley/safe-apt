#!/bin/bash
#
# detect-changes.sh - Detect changed packages between snapshots
#
# This script compares two aptly snapshots and outputs a list of
# packages that have been added or modified.
#

set -euo pipefail

# Configuration
LOG_DIR="${LOG_DIR:-/opt/apt-mirror-system/logs}"
SNAPSHOTS_DIR="${SNAPSHOTS_DIR:-/opt/apt-mirror-system/snapshots}"

# Arguments
OLD_SNAPSHOT="${1:-}"
NEW_SNAPSHOT="${2:-}"

# Logging
TIMESTAMP=$(date +%Y-%m-%dT%H:%M:%S)
DATE_SUFFIX=$(date +%Y%m%d)
LOG_FILE="${LOG_DIR}/detect-changes-${DATE_SUFFIX}.log"

mkdir -p "${LOG_DIR}" "${SNAPSHOTS_DIR}"

log() {
    echo "${TIMESTAMP} [INFO] [detect-changes] $*" | tee -a "${LOG_FILE}"
}

log_error() {
    echo "${TIMESTAMP} [ERROR] [detect-changes] $*" | tee -a "${LOG_FILE}" >&2
}

# Validate arguments
if [ -z "${OLD_SNAPSHOT}" ] || [ -z "${NEW_SNAPSHOT}" ]; then
    log_error "Usage: $0 <old-snapshot> <new-snapshot>"
    exit 1
fi

log "Detecting changes between ${OLD_SNAPSHOT} and ${NEW_SNAPSHOT}"

# Check if snapshots exist
if ! aptly snapshot show "${OLD_SNAPSHOT}" > /dev/null 2>&1; then
    log_error "Old snapshot not found: ${OLD_SNAPSHOT}"
    exit 1
fi

if ! aptly snapshot show "${NEW_SNAPSHOT}" > /dev/null 2>&1; then
    log_error "New snapshot not found: ${NEW_SNAPSHOT}"
    exit 1
fi

# Get package diff
DIFF_OUTPUT=$(aptly snapshot diff "${OLD_SNAPSHOT}" "${NEW_SNAPSHOT}" 2>&1 || true)

# Parse diff output
# aptly snapshot diff format:
#   Arch 'amd64' (added 2, removed 1, left 1234, changed 3)
#   +package-name_1.0.0_amd64
#   -old-package_0.9.0_amd64
#   !updated-package_2.0.0_amd64 -> !updated-package_2.0.1_amd64

CHANGES_FILE="${SNAPSHOTS_DIR}/changes-${OLD_SNAPSHOT}-to-${NEW_SNAPSHOT}.txt"

# Extract added and changed packages (lines starting with + or !)
echo "${DIFF_OUTPUT}" | grep -E '^\+|^!' | sed 's/^[+!]//' | sed 's/ ->.*//' > "${CHANGES_FILE}"

CHANGE_COUNT=$(wc -l < "${CHANGES_FILE}")

if [ "${CHANGE_COUNT}" -eq 0 ]; then
    log "No package changes detected"
    echo ""  # Empty output for pipeline
else
    log "Detected ${CHANGE_COUNT} changed packages"
    log "Changes saved to ${CHANGES_FILE}"

    # Output package list for pipeline
    cat "${CHANGES_FILE}"
fi

exit 0
