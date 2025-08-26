#!/bin/bash

# TTY EGPF Monitor Version-Specific Installation
# This script downloads and installs a specific version from GitHub releases

set -e

VERSION=${1:-latest}
REPO="seelso-net/tty-egpf-monitor"

if [ "$VERSION" = "latest" ]; then
    echo "🔍 Installing latest version of TTY EGPF Monitor..."
    
    # Get latest version
    LATEST_TAG=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
    VERSION=${LATEST_TAG#v}
    echo "📦 Latest version: $VERSION"
else
    echo "🔍 Installing version $VERSION of TTY EGPF Monitor..."
fi

# Detect architecture
ARCH=$(dpkg --print-architecture)
echo "📦 Architecture: $ARCH"

# Create temporary directory
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

# Download the specific version
echo "📥 Downloading version $VERSION..."
RELEASE_URL=$(curl -s "https://api.github.com/repos/$REPO/releases/tags/v$VERSION" | grep "browser_download_url.*deb" | cut -d '"' -f 4)

if [ -z "$RELEASE_URL" ]; then
    echo "❌ Error: Could not find Debian package for version $VERSION"
    echo "📋 Available versions:"
    curl -s "https://api.github.com/repos/$REPO/releases" | grep '"tag_name"' | cut -d'"' -f4 | head -10
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

echo "✅ TTY EGPF Monitor version $VERSION installed successfully!"
echo "🚀 Run 'tty-egpf-monitor --help' to get started"
echo ""
echo "📋 To see installed version:"
echo "   dpkg -l | grep tty-egpf-monitor"
