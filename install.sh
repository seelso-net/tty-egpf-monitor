#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🔍 TTY EGPF Monitor Installation Script${NC}"
echo "=============================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
    exit 1
fi

# Detect Ubuntu version
if [ ! -f /etc/os-release ]; then
    echo -e "${RED}Error: Cannot detect OS version${NC}"
    exit 1
fi

source /etc/os-release

if [ "$ID" != "ubuntu" ]; then
    echo -e "${RED}Error: This script is designed for Ubuntu only${NC}"
    exit 1
fi

echo -e "${GREEN}Detected Ubuntu version: $VERSION_CODENAME${NC}"

# Set repository URL and codename
REPO_URL="https://seelso-net.github.io/tty-egpf-monitor"
CODENAME="$VERSION_CODENAME"

# Check if codename is supported
if [[ "$CODENAME" != "jammy" && "$CODENAME" != "noble" ]]; then
    echo -e "${YELLOW}Warning: Ubuntu $CODENAME is not officially supported${NC}"
    echo -e "${YELLOW}Attempting to use jammy repository...${NC}"
    CODENAME="jammy"
fi

echo -e "${GREEN}Using repository: $REPO_URL for $CODENAME${NC}"

# Install repository key
echo -e "${GREEN}Installing repository key...${NC}"
curl -fsSL "${REPO_URL}/public-apt-key.gpg" | gpg --dearmor -o /usr/share/keyrings/tty-egpf-monitor.gpg

# Add repository
echo -e "${GREEN}Adding repository...${NC}"
echo "deb [signed-by=/usr/share/keyrings/tty-egpf-monitor.gpg] ${REPO_URL} ${CODENAME} main" > /etc/apt/sources.list.d/tty-egpf-monitor.list

# Update package list
echo -e "${GREEN}Updating package list...${NC}"
apt-get update

# Install packages
echo -e "${GREEN}Installing tty-egpf-monitor packages...${NC}"
apt-get install -y tty-egpf-monitord tty-egpf-monitor-cli

# Enable and start service
echo -e "${GREEN}Enabling and starting tty-egpf-monitord service...${NC}"
systemctl enable --now tty-egpf-monitord

# Check service status
echo -e "${GREEN}Checking service status...${NC}"
if systemctl is-active --quiet tty-egpf-monitord; then
    echo -e "${GREEN}✅ tty-egpf-monitord is running successfully${NC}"
else
    echo -e "${RED}❌ tty-egpf-monitord failed to start${NC}"
    echo -e "${YELLOW}Check the service status with: systemctl status tty-egpf-monitord${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}🎉 Installation completed successfully!${NC}"
echo ""
echo -e "${GREEN}Quick start:${NC}"
echo "  # Add a port to monitor"
echo "  tty-egpf-monitor add /dev/ttyUSB0"
echo ""
echo "  # List configured ports"
echo "  tty-egpf-monitor list"
echo ""
echo "  # Stream live events"
echo "  tty-egpf-monitor stream 0"
echo ""
echo -e "${GREEN}Documentation:${NC}"
echo "  - README: https://github.com/seelso-net/tty-egpf-monitor"
echo "  - Socket: /run/tty-egpf-monitord.sock"
echo "  - Logs: /var/log/tty-egpf-monitor/"
echo ""
