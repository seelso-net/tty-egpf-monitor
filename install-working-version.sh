#!/bin/bash

# Quick installation script for the working v0.7.19 version
# This bypasses the APT repository and installs the working version directly

set -e

echo "=== Installing working tty-egpf-monitor v0.7.19 ==="
echo "This script will build and install the CO-RE-aware version that fixes"
echo "the kernel 6.8 compatibility issues."

# Check if we're in the right directory
if [ ! -f "src/daemon.c" ] || [ ! -f "src/sniffer.bpf.c" ]; then
    echo "ERROR: Please run this script from the tty-egpf-monitor source directory"
    exit 1
fi

# Check if we have the right version
if ! grep -q "Version: 0.7.19-1" src/daemon.c; then
    echo "ERROR: This doesn't appear to be the v0.7.19 source code"
    echo "Please make sure you have the latest version with the CO-RE fixes"
    exit 1
fi

echo "✅ Found v0.7.19 source code with CO-RE fixes"

# Install build dependencies
echo "Installing build dependencies..."
sudo apt-get update
sudo apt-get install -y \
    git \
    clang \
    make \
    flex \
    bison \
    libreadline-dev \
    libcap-dev \
    libelf-dev \
    zlib1g-dev \
    pkg-config \
    build-essential \
    linux-headers-$(uname -r) \
    libbpf-dev \
    libsystemd-dev \
    linux-tools-$(uname -r) \
    gnupg \
    apt-utils \
    dpkg-dev \
    debhelper \
    devscripts \
    dh-make

# Install libbpf 1.6.2 for compatibility
echo "Installing libbpf 1.6.2 for kernel 6.8 compatibility..."
cd /tmp
git clone --depth 1 --branch v1.6.2 https://github.com/libbpf/libbpf.git
cd libbpf/src
make
sudo make install PREFIX=/usr/local
sudo ldconfig
cd - > /dev/null
rm -rf /tmp/libbpf

# Build bpftool if needed
if ! command -v bpftool >/dev/null 2>&1; then
    echo "Building bpftool..."
    cd /tmp
    git clone --depth 1 --recurse-submodules https://github.com/libbpf/bpftool.git
    cd bpftool/src
    make
    sudo install -m 0755 bpftool /usr/local/bin/bpftool
    cd - > /dev/null
    rm -rf /tmp/bpftool
fi

# Build the application
echo "Building tty-egpf-monitor v0.7.19..."
make clean
make

# Stop existing daemon
echo "Stopping existing daemon..."
sudo systemctl stop tty-egpf-monitord 2>/dev/null || true
sudo pkill -f tty-egpf-monitord 2>/dev/null || true

# Install the new version
echo "Installing new version..."
sudo cp build/tty-egpf-monitord /usr/bin/
sudo cp build/tty-egpf-monitor /usr/bin/

# Set permissions
sudo chmod +x /usr/bin/tty-egpf-monitord
sudo chmod +x /usr/bin/tty-egpf-monitor

# Start the daemon
echo "Starting daemon..."
sudo systemctl start tty-egpf-monitord

# Wait a moment for startup
sleep 2

# Check if it's running
if systemctl is-active --quiet tty-egpf-monitord; then
    echo "✅ Daemon started successfully!"
    echo "✅ Version: $(journalctl -u tty-egpf-monitord --since '1 minute ago' | grep 'Version:' | tail -1)"
else
    echo "❌ Daemon failed to start. Check logs:"
    journalctl -u tty-egpf-monitord --since '1 minute ago' | tail -20
    exit 1
fi

echo ""
echo "🎉 Installation complete!"
echo ""
echo "The working v0.7.19 version is now installed with CO-RE-aware eBPF programming"
echo "that fixes the kernel 6.8 compatibility issues."
echo ""
echo "Test it by running:"
echo "  sudo tty-egpf-monitor add /dev/ttyUSB0 115200"
echo "  sudo picocom /dev/ttyUSB0 -b 115200 -q"
echo ""
echo "You should now see OPEN events from picocom in the daemon logs!"
