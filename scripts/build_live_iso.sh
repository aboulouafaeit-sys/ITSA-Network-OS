#!/bin/bash
# ==============================================================================
# ITSA Network OS — Automated Debian Live ISO Build Script
# ==============================================================================
# This script orchestrates the creation of a bootable Debian 13 (Trixie) live ISO
# containing the ITSA Network OS application, networking stack, and security tools.
#
# SAFETY INVARIANT:
# This script requires live-build (lb) and root privileges for chroot operations,
# and should be executed in a dedicated VM, container, or Debian build server.
# It does NOT touch host disks, Windows partitions, or EFI bootloaders.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
LIVE_DIR="${PROJECT_ROOT}/debian-live"
BUILD_OUTPUT="${PROJECT_ROOT}/build-output"

echo "============================================================"
echo "      ITSA Network OS — Debian Live ISO Builder             "
echo "============================================================"

# Pre-flight check 1: Running as root?
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Error: live-build requires root privileges to mount chroot loop devices."
    echo "    Please run this build script with sudo or within a privileged build container."
    exit 1
fi

# Pre-flight check 2: live-build installed?
if ! command -v lb &> /dev/null; then
    echo "[!] Error: 'live-build' toolchain is not installed."
    echo "    Install required build packages via:"
    echo "    sudo apt-get update && sudo apt-get install -y live-build debootstrap squashfs-tools xorriso"
    exit 1
fi

# Pre-flight check 3: Disk space (need at least 8 GB free)
FREE_KB=$(df -k "${PROJECT_ROOT}" | awk 'NR==2 {print $4}')
FREE_GB=$((FREE_KB / 1024 / 1024))
if [ "${FREE_GB}" -lt 8 ]; then
    echo "[!] Warning: Low disk space detected (${FREE_GB} GB free). live-build requires at least 8 GB."
    read -p "Proceed anyway? (y/N): " -r CONFIRM
    if [[ ! "${CONFIRM}" =~ ^[Yy]$ ]]; then
        echo "Aborted by user."
        exit 1
    fi
fi

# Step 1: Prepare output directory
mkdir -p "${BUILD_OUTPUT}"
cd "${LIVE_DIR}"

# Step 2: Clean any stale artifacts
echo "[*] Cleaning previous build cache..."
lb clean --purge

# Step 3: Copy current source into chroot staging
echo "[*] Staging ITSA Network OS package source..."
mkdir -p "${LIVE_DIR}/config/includes.chroot/tmp/itsa-src"
cp -r "${PROJECT_ROOT}/pyproject.toml" "${LIVE_DIR}/config/includes.chroot/tmp/itsa-src/"
cp -r "${PROJECT_ROOT}/README.md" "${LIVE_DIR}/config/includes.chroot/tmp/itsa-src/"
cp -r "${PROJECT_ROOT}/src" "${LIVE_DIR}/config/includes.chroot/tmp/itsa-src/"

# Step 4: Configure live-build
echo "[*] Executing auto/config..."
chmod +x auto/config
./auto/config

# Step 5: Execute build
echo "[*] Starting live-build image generation (this may take 15-30 minutes)..."
lb build

# Step 6: Move generated ISO to build-output and generate checksum
if [ -f "live-image-amd64.hybrid.iso" ]; then
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    FINAL_ISO="${BUILD_OUTPUT}/itsa-network-os-debian13-${TIMESTAMP}.iso"
    mv "live-image-amd64.hybrid.iso" "${FINAL_ISO}"
    sha256sum "${FINAL_ISO}" > "${FINAL_ISO}.sha256"

    echo "============================================================"
    echo " [OK] Live ISO Build Successful!"
    echo " ISO Location: ${FINAL_ISO}"
    echo " SHA256 Hash : $(cat "${FINAL_ISO}.sha256")"
    echo "============================================================"
else
    echo "[!] Build failed or ISO was not generated."
    exit 1
fi
