#!/bin/bash

# TTY EGPF Monitor Installation Script
# This script automatically detects OS version and installs from APT repository or GitHub releases

set -e

PACKAGE_VERSION=${1:-latest}
REPO="seelso-net/tty-egpf-monitor"
PACKAGE_NAME="tty-egpf-monitor"
APT_METHOD=${APT_METHOD:-true}  # Default to APT method, set to false to use direct download

echo "🔍 Installing TTY EGPF Monitor..."

# Detect OS and version
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_NAME="$NAME"
    OS_VERSION="$VERSION_ID"
    OS_CODENAME="$VERSION_CODENAME"
    echo "🖥️  Operating System: $OS_NAME $OS_VERSION ($OS_CODENAME)"
else
    echo "⚠️  Warning: Cannot detect OS version"
    OS_VERSION="unknown"
    OS_CODENAME="unknown"
fi

# Detect architecture
ARCH=$(dpkg --print-architecture)
echo "📦 Architecture: $ARCH"

# Function to install via APT repository
install_via_apt() {
    echo "📥 Installing via APT repository..."
    
    # Check if repository is already configured
    if [ -f /etc/apt/sources.list.d/tty-egpf-monitor.list ]; then
        echo "✅ Repository already configured"
    else
        echo "🔑 Adding GPG key..."
        wget -qO - https://seelso-net.github.io/tty-egpf-monitor/public-apt-key.asc | 
            gpg --dearmor | 
            sudo tee /usr/share/keyrings/tty-egpf-monitor-archive-keyring.gpg > /dev/null
        
        echo "📋 Adding repository..."
        echo "deb [signed-by=/usr/share/keyrings/tty-egpf-monitor-archive-keyring.gpg] https://seelso-net.github.io/tty-egpf-monitor $OS_CODENAME main" | 
            sudo tee /etc/apt/sources.list.d/tty-egpf-monitor.list > /dev/null
    fi
    
    echo "🔄 Updating package list..."
    sudo apt-get update
    
    echo "📦 Installing packages..."
    sudo apt-get install -y tty-egpf-monitord tty-egpf-monitor-cli
}

# Function to install via direct download
install_via_download() {
    echo "📥 Installing via direct download..."
    
    # Create temporary directory
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    
    # Download the latest release
    if [ "$PACKAGE_VERSION" = "latest" ]; then
        echo "📥 Downloading latest release..."
        RELEASE_URL=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep "browser_download_url.*monitord.*deb" | cut -d '"' -f 4)
    else
        echo "📥 Downloading version $PACKAGE_VERSION..."
        RELEASE_URL=$(curl -s "https://api.github.com/repos/$REPO/releases/tags/v$PACKAGE_VERSION" | grep "browser_download_url.*monitord.*deb" | cut -d '"' -f 4)
    fi
    
    if [ -z "$RELEASE_URL" ]; then
        echo "❌ Error: Could not find Debian package for version $PACKAGE_VERSION"
        exit 1
    fi
    
    echo "📦 Downloading: $RELEASE_URL"
    wget "$RELEASE_URL"
    
    # Install the package
    DEB_FILE=$(basename "$RELEASE_URL")
    echo "🔧 Installing $DEB_FILE..."
    sudo dpkg -i "$DEB_FILE"
    
    # Fix any dependency issues
    sudo apt-get install -f -y
    
    # Clean up
    cd /
    rm -rf "$TEMP_DIR"
}

# Main installation logic
if [ "$APT_METHOD" = "true" ] && [ "$OS_CODENAME" != "unknown" ] && ([ "$OS_CODENAME" = "jammy" ] || [ "$OS_CODENAME" = "noble" ]); then
    install_via_apt
else
    if [ "$APT_METHOD" = "true" ]; then
        echo "⚠️  APT method not available for $OS_NAME $OS_VERSION"
        echo "   Falling back to direct download method..."
    fi
    install_via_download
fi

echo "✅ TTY EGPF Monitor installed successfully!"
echo ""
echo "📚 Quick Start:"
echo "   - CLI: tty-egpf-monitor --help"
echo "   - Service status: sudo systemctl status tty-egpf-monitord"
echo "   - Logs: sudo journalctl -u tty-egpf-monitord -f"
echo ""
echo "🔍 The daemon should be running automatically."

# Check service status
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet tty-egpf-monitord; then
        echo "✅ Service is running"
    else
        echo "⚠️  Service is not running. Start it with: sudo systemctl start tty-egpf-monitord"
    fi
fi
