#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🧪 TTY EGPF Monitor Installation Test${NC}"
echo "=========================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
    exit 1
fi

# Test 1: Check if packages are installed
echo -e "${GREEN}Test 1: Checking package installation...${NC}"
if dpkg -l | grep -q "tty-egpf-monitord"; then
    echo -e "${GREEN}✅ tty-egpf-monitord package is installed${NC}"
else
    echo -e "${RED}❌ tty-egpf-monitord package is not installed${NC}"
    exit 1
fi

if dpkg -l | grep -q "tty-egpf-monitor-cli"; then
    echo -e "${GREEN}✅ tty-egpf-monitor-cli package is installed${NC}"
else
    echo -e "${RED}❌ tty-egpf-monitor-cli package is not installed${NC}"
    exit 1
fi

# Test 2: Check if service is running
echo -e "${GREEN}Test 2: Checking service status...${NC}"
if systemctl is-active --quiet tty-egpf-monitord; then
    echo -e "${GREEN}✅ tty-egpf-monitord service is running${NC}"
else
    echo -e "${RED}❌ tty-egpf-monitord service is not running${NC}"
    echo -e "${YELLOW}Attempting to start service...${NC}"
    systemctl start tty-egpf-monitord
    sleep 2
    if systemctl is-active --quiet tty-egpf-monitord; then
        echo -e "${GREEN}✅ Service started successfully${NC}"
    else
        echo -e "${RED}❌ Failed to start service${NC}"
        systemctl status tty-egpf-monitord
        exit 1
    fi
fi

# Test 3: Check if socket exists
echo -e "${GREEN}Test 3: Checking socket file...${NC}"
if [ -S /run/tty-egpf-monitord.sock ]; then
    echo -e "${GREEN}✅ Socket file exists${NC}"
else
    echo -e "${RED}❌ Socket file does not exist${NC}"
    exit 1
fi

# Test 4: Check if CLI can connect
echo -e "${GREEN}Test 4: Testing CLI connection...${NC}"
if timeout 5 tty-egpf-monitor list > /dev/null 2>&1; then
    echo -e "${GREEN}✅ CLI can connect to daemon${NC}"
else
    echo -e "${RED}❌ CLI cannot connect to daemon${NC}"
    exit 1
fi

# Test 5: Check if log directory exists
echo -e "${GREEN}Test 5: Checking log directory...${NC}"
if [ -d /var/log/tty-egpf-monitor ]; then
    echo -e "${GREEN}✅ Log directory exists${NC}"
else
    echo -e "${RED}❌ Log directory does not exist${NC}"
    exit 1
fi

# Test 6: Check libbpf compatibility (Ubuntu 22.04 specific)
echo -e "${GREEN}Test 6: Checking libbpf compatibility...${NC}"
if [ -f /etc/os-release ] && grep -q "jammy" /etc/os-release; then
    echo -e "${YELLOW}Ubuntu 22.04 detected, checking libbpf...${NC}"
    if ldconfig -p | grep -q "libbpf.so.1"; then
        echo -e "${GREEN}✅ libbpf.so.1 is available${NC}"
    else
        echo -e "${YELLOW}⚠️  libbpf.so.1 not found, but this might be normal for Ubuntu 22.04${NC}"
    fi
else
    echo -e "${GREEN}Not Ubuntu 22.04, skipping libbpf check${NC}"
fi

# Test 7: Check if daemon can load BPF programs
echo -e "${GREEN}Test 7: Checking BPF program loading...${NC}"
if pgrep -f "tty-egpf-monitord" > /dev/null; then
    echo -e "${GREEN}✅ Daemon process is running${NC}"
    
    # Check if BPF programs are loaded
    if bpftool prog list | grep -q "tty"; then
        echo -e "${GREEN}✅ BPF programs are loaded${NC}"
    else
        echo -e "${YELLOW}⚠️  No BPF programs found (this might be normal if no devices are added)${NC}"
    fi
else
    echo -e "${RED}❌ Daemon process is not running${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}🎉 All tests passed! Installation is working correctly.${NC}"
echo ""
echo -e "${GREEN}Next steps:${NC}"
echo "  1. Add a device to monitor: tty-egpf-monitor add /dev/ttyUSB0"
echo "  2. List configured devices: tty-egpf-monitor list"
echo "  3. Stream live events: tty-egpf-monitor stream 0"
echo ""
echo -e "${GREEN}For more information, see the README.md file.${NC}"
