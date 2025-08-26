#!/bin/bash

# TTY EGPF Monitor Installation Script
# This script downloads and installs the latest release

set -e

VERSION=${1:-latest}
REPO="seelso-net/tty-egpf-monitor"
PACKAGE_NAME="tty-egpf-monitor"

echo "🔍 Installing TTY EGPF Monitor..."

# Detect architecture
ARCH=$(dpkg --print-architecture)
echo "📦 Architecture: $ARCH"

# Create temporary directory
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

# Download the latest release
if [ "$VERSION" = "latest" ]; then
    echo "📥 Downloading latest release..."
    RELEASE_URL=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep "browser_download_url.*deb" | cut -d '"' -f 4)
else
    echo "📥 Downloading version $VERSION..."
    RELEASE_URL=$(curl -s "https://api.github.com/repos/$REPO/releases/tags/v$VERSION" | grep "browser_download_url.*deb" | cut -d '"' -f 4)
fi

if [ -z "$RELEASE_URL" ]; then
    echo "❌ Error: Could not find Debian package for version $VERSION"
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

echo "✅ TTY EGPF Monitor installed successfully!"
echo "🚀 Run 'tty-egpf-monitor --help' to get started"
