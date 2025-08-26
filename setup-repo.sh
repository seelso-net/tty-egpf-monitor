#!/bin/bash

# TTY EGPF Monitor APT Repository Setup
# This script adds the official APT repository and installs the package

set -e

REPO_URL="https://seelso-net.github.io/tty-egpf-monitor"
VERSION=${1:-latest}

echo "🔍 Setting up TTY EGPF Monitor APT repository..."

# Detect distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
else
    echo "❌ Error: Could not detect operating system"
    exit 1
fi

echo "📦 Detected: $OS $VER"

# Check if running on Ubuntu/Debian
if [[ "$OS" != *"Ubuntu"* ]] && [[ "$OS" != *"Debian"* ]]; then
    echo "❌ Error: This repository is only supported on Ubuntu and Debian"
    exit 1
fi

# Add repository
echo "📥 Adding APT repository..."
echo "deb [trusted=yes] $REPO_URL stable main" | sudo tee /etc/apt/sources.list.d/tty-egpf-monitor.list

# Update package list
echo "🔄 Updating package list..."
sudo apt-get update

# Install the package
if [ "$VERSION" = "latest" ]; then
    echo "🔧 Installing latest version of TTY EGPF Monitor..."
    sudo apt-get install -y tty-egpf-monitor
else
    echo "🔧 Installing version $VERSION of TTY EGPF Monitor..."
    sudo apt-get install -y tty-egpf-monitor=$VERSION-1
fi

echo "✅ TTY EGPF Monitor installed successfully!"
echo "🚀 Run 'tty-egpf-monitor --help' to get started"
echo ""
echo "📝 To update in the future, run:"
echo "   sudo apt update && sudo apt upgrade tty-egpf-monitor"
echo ""
echo "📋 To see available versions:"
echo "   apt list -a tty-egpf-monitor"
