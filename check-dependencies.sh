#!/bin/bash

# TTY-EGPF-MONITOR Dependency Checker
# Run this script on the target system to verify all requirements

echo "=== TTY-EGPF-MONITOR Dependency Checker ==="
echo "Checking system requirements for tty-egpf-monitor v0.7.9"
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check and report
check_dependency() {
    local name="$1"
    local command="$2"
    local expected="$3"
    
    echo -n "Checking $name... "
    
    if eval "$command" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ OK${NC}"
        if [ -n "$expected" ]; then
            local result=$(eval "$command")
            if [[ "$result" == *"$expected"* ]]; then
                echo -e "  ${GREEN}  Version: $result${NC}"
            else
                echo -e "  ${YELLOW}  Version: $result (expected: $expected)${NC}"
            fi
        fi
        return 0
    else
        echo -e "${RED}✗ MISSING${NC}"
        return 1
    fi
}

# Function to check file existence
check_file() {
    local file="$1"
    local description="$2"
    
    echo -n "Checking $description... "
    
    if [ -f "$file" ]; then
        echo -e "${GREEN}✓ OK${NC}"
        ls -la "$file"
        return 0
    else
        echo -e "${RED}✗ MISSING${NC}"
        return 1
    fi
}

# Function to check directory existence
check_directory() {
    local dir="$1"
    local description="$2"
    
    echo -n "Checking $description... "
    
    if [ -d "$dir" ]; then
        echo -e "${GREEN}✓ OK${NC}"
        return 0
    else
        echo -e "${RED}✗ MISSING${NC}"
        return 1
    fi
}

# System Information
echo "=== System Information ==="
echo "OS: $(lsb_release -d 2>/dev/null | cut -f2 || echo "Unknown")"
echo "Kernel: $(uname -r)"
echo "Architecture: $(uname -m)"
echo

# Build Tools
echo "=== Build Tools ==="
check_dependency "gcc" "gcc --version | head -1" "gcc"
check_dependency "clang" "clang --version | head -1" "clang"
check_dependency "make" "make --version | head -1" "GNU Make"
echo

# Libraries
echo "=== Libraries ==="
check_dependency "libbpf" "pkg-config --exists libbpf && echo 'libbpf found'" ""
check_dependency "libelf" "pkg-config --exists libelf && echo 'libelf found'" ""
check_dependency "zlib" "pkg-config --exists zlib && echo 'zlib found'" ""
echo

# Runtime Libraries
echo "=== Runtime Libraries ==="
check_dependency "libbpf.so.1" "ldconfig -p | grep libbpf.so.1" ""
check_dependency "libelf.so.1" "ldconfig -p | grep libelf.so.1" ""
check_dependency "libz.so.1" "ldconfig -p | grep libz.so.1" ""
echo

# Tools
echo "=== Tools ==="
check_dependency "bpftool" "bpftool version" "bpftool"
echo

# Kernel Features
echo "=== Kernel Features ==="
check_file "/sys/kernel/btf/vmlinux" "BTF (BPF Type Format)"
check_directory "/sys/kernel/debug/tracing" "Kernel tracing support"
echo

# Tracepoints
echo "=== Tracepoints ==="
if [ -d "/sys/kernel/debug/tracing/events" ]; then
    echo "Checking tracepoint availability..."
    
    # Check if we can access tracepoints (requires root)
    if [ "$EUID" -eq 0 ]; then
        check_file "/sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/enable" "openat tracepoint"
        check_file "/sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/enable" "raw syscall tracepoint"
        
        echo "Tracepoint status:"
        if [ -f "/sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/enable" ]; then
            echo "  openat: $(cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/enable)"
        fi
        if [ -f "/sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/enable" ]; then
            echo "  raw_syscalls: $(cat /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/enable)"
        fi
    else
        echo -e "${YELLOW}  Note: Run as root to check tracepoint status${NC}"
    fi
else
    echo -e "${RED}✗ Kernel tracing not available${NC}"
fi
echo

# Permissions
echo "=== Permissions ==="
if [ "$EUID" -eq 0 ]; then
    echo -e "${GREEN}✓ Running as root${NC}"
else
    echo -e "${YELLOW}⚠ Not running as root (required for eBPF)${NC}"
fi
echo

# Summary
echo "=== Summary ==="
echo "This script checks the basic requirements for tty-egpf-monitor."
echo "For a complete deployment, also ensure:"
echo "1. TTY devices are available (e.g., /dev/ttyUSB0)"
echo "2. Proper permissions for TTY access"
echo "3. Network access for git clone (if building from source)"
echo

# Recommendations
echo "=== Recommendations ==="
if ! check_dependency "libbpf" "pkg-config --exists libbpf" "" >/dev/null 2>&1; then
    echo -e "${YELLOW}⚠ Install libbpf: sudo apt install libbpf-dev${NC}"
fi

if ! check_dependency "bpftool" "bpftool version" "" >/dev/null 2>&1; then
    echo -e "${YELLOW}⚠ Install bpftool: sudo apt install linux-tools-\$(uname -r)${NC}"
fi

if [ ! -f "/sys/kernel/btf/vmlinux" ]; then
    echo -e "${RED}✗ BTF not available - kernel may not support eBPF properly${NC}"
fi

echo
echo "For detailed deployment instructions, see DEPLOYMENT.md"
