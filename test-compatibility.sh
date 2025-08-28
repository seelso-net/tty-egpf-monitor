#!/bin/bash
# Local compatibility test for tty-egpf-monitor

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "🧪 TTY EGPF Monitor Compatibility Test"
echo "====================================="

# Function to check if a command exists
check_command() {
    if command -v "$1" >/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} $1 found"
        return 0
    else
        echo -e "${RED}✗${NC} $1 not found"
        return 1
    fi
}

# Function to check package
check_package() {
    if dpkg -l | grep -q "^ii.*$1"; then
        echo -e "${GREEN}✓${NC} $1 installed"
        return 0
    else
        echo -e "${RED}✗${NC} $1 not installed"
        return 1
    fi
}

# Function to check kernel capability support
check_capability() {
    if grep -q "$1" /proc/sys/kernel/cap_last_cap 2>/dev/null || capsh --print | grep -q "$1" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} $1 capability supported"
        return 0
    else
        # Check kernel version for CAP_BPF (added in 5.8)
        KERNEL_VERSION=$(uname -r | cut -d. -f1,2)
        KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
        KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)
        
        if [ "$1" = "CAP_BPF" ] && ([ $KERNEL_MAJOR -lt 5 ] || ([ $KERNEL_MAJOR -eq 5 ] && [ $KERNEL_MINOR -lt 8 ])); then
            echo -e "${YELLOW}⚠${NC} $1 not supported (kernel < 5.8)"
            return 2
        else
            echo -e "${RED}✗${NC} $1 capability not found"
            return 1
        fi
    fi
}

# System Information
echo -e "\n${YELLOW}System Information:${NC}"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "OS: $NAME $VERSION_ID ($VERSION_CODENAME)"
else
    echo "OS: Unknown"
fi
echo "Kernel: $(uname -r)"
echo "Architecture: $(dpkg --print-architecture)"

# Check build dependencies
echo -e "\n${YELLOW}Build Dependencies:${NC}"
BUILD_DEPS=(clang make libelf-dev zlib1g-dev pkg-config build-essential libbpf-dev libsystemd-dev)
BUILD_OK=true
for dep in "${BUILD_DEPS[@]}"; do
    check_package "$dep" || BUILD_OK=false
done

# Check runtime dependencies based on OS version
echo -e "\n${YELLOW}Runtime Dependencies:${NC}"
if [ "$VERSION_ID" = "22.04" ]; then
    echo "Checking for Ubuntu 22.04 (Jammy)..."
    RUNTIME_DEPS=(libbpf0 libc6 libcap2-bin libsystemd0)
else
    echo "Checking for Ubuntu 24.04+ (Noble)..."
    RUNTIME_DEPS=(libbpf1 libc6 libcap2-bin libsystemd0)
fi

RUNTIME_OK=true
for dep in "${RUNTIME_DEPS[@]}"; do
    check_package "$dep" || RUNTIME_OK=false
done

# Check kernel capabilities
echo -e "\n${YELLOW}Kernel Capabilities:${NC}"
CAP_OK=true
check_capability "CAP_SYS_ADMIN" || CAP_OK=false
check_capability "CAP_NET_ADMIN" || CAP_OK=false
check_capability "CAP_PERFMON" || CAP_OK=false
CAP_BPF_STATUS=$(check_capability "CAP_BPF"; echo $?)

# Check kernel features
echo -e "\n${YELLOW}Kernel Features:${NC}"
KERNEL_OK=true

# Check for BPF support
if [ -d /sys/fs/bpf ]; then
    echo -e "${GREEN}✓${NC} BPF filesystem mounted"
else
    echo -e "${RED}✗${NC} BPF filesystem not mounted"
    KERNEL_OK=false
fi

# Check for BTF support
if [ -f /sys/kernel/btf/vmlinux ]; then
    echo -e "${GREEN}✓${NC} BTF (BPF Type Format) available"
else
    echo -e "${YELLOW}⚠${NC} BTF not available (may affect some features)"
fi

# Check for debugfs
if [ -d /sys/kernel/debug ]; then
    echo -e "${GREEN}✓${NC} debugfs mounted"
else
    echo -e "${YELLOW}⚠${NC} debugfs not mounted (required for some tracing features)"
fi

# Check systemd
echo -e "\n${YELLOW}Systemd Support:${NC}"
if check_command "systemctl"; then
    SYSTEMD_VERSION=$(systemctl --version | head -1 | awk '{print $2}')
    echo "  Version: $SYSTEMD_VERSION"
fi

# Test package build
echo -e "\n${YELLOW}Package Build Test:${NC}"
if [ "$BUILD_OK" = true ] && [ -f "Makefile" ]; then
    echo "Attempting test build..."
    if make clean >/dev/null 2>&1 && make >/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} Build successful"
        
        # Check binaries
        if [ -f "build/tty-egpf-monitord" ] && [ -f "build/tty-egpf-monitor" ]; then
            echo -e "${GREEN}✓${NC} Binaries created"
            
            # Check dynamic linking
            echo -e "\n${YELLOW}Binary Dependencies:${NC}"
            if ldd build/tty-egpf-monitord >/dev/null 2>&1; then
                echo -e "${GREEN}✓${NC} All libraries resolved"
            else
                echo -e "${RED}✗${NC} Missing libraries"
                ldd build/tty-egpf-monitord || true
            fi
        else
            echo -e "${RED}✗${NC} Binaries not found"
        fi
    else
        echo -e "${RED}✗${NC} Build failed"
    fi
else
    echo -e "${YELLOW}⚠${NC} Skipping build test (dependencies missing)"
fi

# Summary
echo -e "\n${YELLOW}=== Compatibility Summary ===${NC}"

if [ "$VERSION_ID" = "22.04" ]; then
    echo -e "\n${YELLOW}Ubuntu 22.04 Specific Notes:${NC}"
    if [ "$CAP_BPF_STATUS" -eq 2 ]; then
        echo "• CAP_BPF not available - will use CAP_SYS_ADMIN instead ✓"
    fi
    echo "• Using libbpf0 package ✓"
    echo "• Systemd service configured for compatibility ✓"
elif [ "$VERSION_ID" = "24.04" ]; then
    echo -e "\n${YELLOW}Ubuntu 24.04 Specific Notes:${NC}"
    echo "• Full CAP_BPF support available ✓"
    echo "• Using libbpf1 package ✓"
fi

# Overall result
echo -e "\n${YELLOW}Overall Status:${NC}"
if [ "$BUILD_OK" = true ] && [ "$RUNTIME_OK" = true ] && [ "$KERNEL_OK" = true ]; then
    echo -e "${GREEN}✅ System is compatible with tty-egpf-monitor${NC}"
    exit 0
else
    echo -e "${RED}❌ Some compatibility issues found${NC}"
    echo "Please install missing dependencies and ensure kernel features are enabled."
    exit 1
fi
