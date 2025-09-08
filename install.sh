#!/bin/bash

# TTY eBPF Monitor Installation Script
# This script installs the tty-egpf-monitor package from the official APT repository

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root. Please run as a regular user with sudo privileges."
   exit 1
fi

# Check if sudo is available
if ! command -v sudo &> /dev/null; then
    print_error "sudo is required but not installed. Please install sudo first."
    exit 1
fi

# Detect Ubuntu version
if ! command -v lsb_release &> /dev/null; then
    print_error "lsb_release not found. Please install lsb-release: sudo apt-get install lsb-release"
    exit 1
fi

DISTRO=$(lsb_release -si)
CODENAME=$(lsb_release -cs)

if [[ "$DISTRO" != "Ubuntu" ]]; then
    print_error "This script is designed for Ubuntu. Detected: $DISTRO"
    exit 1
fi

if [[ "$CODENAME" != "jammy" && "$CODENAME" != "noble" ]]; then
    print_warning "This package is tested on Ubuntu 22.04 (jammy) and 24.04 (noble). Detected: $CODENAME"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

print_status "Installing TTY eBPF Monitor for Ubuntu $CODENAME..."

# Repository configuration
REPO_URL="https://seelso-net.github.io/tty-egpf-monitor"
KEY_URL="${REPO_URL}/public-apt-key.asc"
REPO_FILE="/etc/apt/sources.list.d/tty-egpf-monitor.list"
KEY_FILE="/usr/share/keyrings/tty-egpf-monitor.gpg"

# Ensure gnupg is available and dearmor ASCII key into keyrings path
print_status "Adding repository key..."
if ! command -v gpg &> /dev/null; then
    print_status "Installing gnupg for key handling..."
    if ! sudo apt-get update; then
        print_error "Failed to update package list before installing gnupg"
        exit 1
    fi
    if ! sudo apt-get install -y gnupg; then
        print_error "Failed to install gnupg"
        exit 1
    fi
fi

if ! curl -fsSL "$KEY_URL" | sudo gpg --dearmor -o "$KEY_FILE"; then
    print_error "Failed to download or dearmor repository key from $KEY_URL"
    exit 1
fi
sudo chmod 644 "$KEY_FILE"

# Add the repository
print_status "Adding APT repository..."
if ! echo "deb [signed-by=$KEY_FILE] $REPO_URL $CODENAME main" | sudo tee "$REPO_FILE" > /dev/null; then
    print_error "Failed to add repository"
    exit 1
fi

# Update package list
print_status "Updating package list..."
if ! sudo apt-get update; then
    print_error "Failed to update package list"
    exit 1
fi

# Install packages
print_status "Installing packages..."
if ! sudo apt-get install -y tty-egpf-monitord tty-egpf-monitor-cli; then
    print_error "Failed to install packages"
    exit 1
fi

# Enable and start the service
print_status "Enabling and starting service..."
if ! sudo systemctl enable --now tty-egpf-monitord; then
    print_error "Failed to enable/start service"
    exit 1
fi

# Verify installation
print_status "Verifying installation..."

# Check if service is running
if sudo systemctl is-active --quiet tty-egpf-monitord; then
    print_success "Service is running"
else
    print_warning "Service is not running. Check status with: sudo systemctl status tty-egpf-monitord"
fi

# Check if socket exists
if [[ -S /run/tty-egpf-monitord.sock ]]; then
    print_success "Unix socket created"
else
    print_warning "Unix socket not found. Check service logs"
fi

# Test CLI
if command -v tty-egpf-monitor &> /dev/null; then
    if tty-egpf-monitor list &> /dev/null; then
        print_success "CLI is working"
    else
        print_warning "CLI installed but connection test failed"
    fi
else
    print_error "CLI not found"
fi

print_success "Installation completed!"
echo
echo "Next steps:"
echo "1. Add a port to monitor: sudo tty-egpf-monitor add /dev/ttyUSB0"
echo "2. List configured ports: tty-egpf-monitor list"
echo "3. View live stream: tty-egpf-monitor stream 0"
echo "4. Check service status: sudo systemctl status tty-egpf-monitord"
echo
echo "For detailed documentation, see: https://github.com/seelso-net/tty-egpf-monitor"
echo "For troubleshooting, see: INSTALLATION.md"
