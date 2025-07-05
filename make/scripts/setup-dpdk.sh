#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---
DPDK_VERSION="23.11"
DPDK_TARBALL="dpdk-${DPDK_VERSION}.tar.gz"
DPDK_URL="https://fast.dpdk.org/rel/${DPDK_TARBALL}"
DPDK_SRC_DIR="dpdk-${DPDK_VERSION}"
INSTALL_PREFIX="/usr/local"

# --- Helper Functions ---
info() {
    echo "[INFO] $1"
}

error_exit() {
    echo "[ERROR] $1" >&2
    exit 1
}

# --- Main Execution ---
info "--- DPDK Setup Script Starting ---"

# 0. Download prerequisites
if ! command -v meson &> /dev/null || ! command -v ninja &> /dev/null; then
    info "Installing Meson and Ninja build tools ..."
    sudo apt-get update
    sudo apt install -y build-essential git gcc clang make meson ninja-build python3 python3-pip libnuma-dev pkg-config libelf-dev pciutils net-tools linux-headers-$(uname -r)    
    sudo apt install python3-pyelftools
    sudo apt-get install libssl-dev
else
    info "Meson and Ninja are already installed."
fi

# 1. Download DPDK tarball if not present
if [ ! -f "$DPDK_TARBALL" ]; then
    info "Downloading DPDK $DPDK_VERSION from $DPDK_URL ..."
    wget "$DPDK_URL" || error_exit "Failed to download DPDK tarball."
else
    info "DPDK tarball $DPDK_TARBALL already exists. Skipping download."
fi

echo
# 2. Extract DPDK tarball
if [ ! -d "$DPDK_SRC_DIR" ]; then
    info "Extracting $DPDK_TARBALL ..."
    tar -xzf "$DPDK_TARBALL" || error_exit "Failed to extract DPDK tarball."
else
    info "DPDK source directory $DPDK_SRC_DIR already exists. Skipping extraction."
fi

echo
# 3. Build DPDK with Meson/Ninja
cd "$DPDK_SRC_DIR"
if [ ! -d build ]; then
    info "Setting up Meson build directory ..."
    meson setup build --prefix="$INSTALL_PREFIX" || error_exit "Meson setup failed."
else
    info "Meson build directory already exists. Skipping setup."
fi

echo
info "Building DPDK with Ninja ..."
ninja -C build || error_exit "Ninja build failed."

echo
info "Installing DPDK to $INSTALL_PREFIX ..."
sudo ninja -C build install || error_exit "Ninja install failed."

# 4. Update linker cache
info "Updating linker cache with ldconfig ..."
sudo ldconfig

echo
# 5. Print environment variable suggestions
info "--- DPDK Setup Complete! ---"
echo
info "If you installed to a non-standard prefix, set PKG_CONFIG_PATH for Meson/CMake builds:"
echo "  export PKG_CONFIG_PATH=$INSTALL_PREFIX/lib/x86_64-linux-gnu/pkgconfig:\$PKG_CONFIG_PATH"
echo
info "DPDK headers are in: $INSTALL_PREFIX/include/dpdk"
info "DPDK libraries are in: $INSTALL_PREFIX/lib/x86_64-linux-gnu"
echo
info "You can now build your DPDK application with Meson or CMake."
echo
info "To clean up build files:"
echo "  cd $DPDK_SRC_DIR && ninja -C build clean"
echo
info "You may now safely remove the following to free disk space:"
echo "  rm -rf $DPDK_SRC_DIR $DPDK_TARBALL"
echo
info "--- Script Finished ---"