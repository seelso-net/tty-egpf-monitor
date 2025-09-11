# TTY-EGPF-MONITOR Deployment Guide

## System Requirements

### Operating System
- **Ubuntu 22.04 LTS (jammy)** - Supported
- **Ubuntu 24.04 LTS (noble)** - Tested and working
- **Kernel**: 5.8+ (eBPF support required)
- **Architecture**: x86_64, aarch64, arm64

### Required Dependencies

#### 1. Build Tools (from debian/control)
```bash
sudo apt update
sudo apt install -y build-essential clang gcc make debhelper pkg-config
```

#### 2. eBPF Development Libraries
```bash
# Install system libbpf (Ubuntu 24.04)
sudo apt install -y libbpf-dev libelf-dev zlib1g-dev

# For Ubuntu 22.04, install custom libbpf from source:
wget https://github.com/libbpf/libbpf/archive/refs/tags/v1.6.2.tar.gz
tar -xzf v1.6.2.tar.gz
cd libbpf-1.6.2/src
make
sudo make install
```

#### 3. Kernel Headers and BTF
```bash
# Install kernel headers
sudo apt install -y linux-headers-$(uname -r) linux-headers-generic

# Verify BTF is available
ls -la /sys/kernel/btf/vmlinux
# Should show: -r--r--r-- 1 root root [size] [date] /sys/kernel/btf/vmlinux
```

#### 4. bpftool
```bash
# Install bpftool (required for eBPF program loading)
sudo apt install -y linux-tools-common linux-tools-$(uname -r)

# OR install from source (recommended for latest features)
# bpftool is included with libbpf source build above
```

#### 5. System Dependencies
```bash
# Required for systemd service
sudo apt install -y libsystemd-dev

# Runtime libraries
sudo apt install -y libelf1 zlib1g libzstd1
```

## Build Process

### 1. Clone Repository
```bash
git clone https://github.com/seelso-net/tty-egpf-monitor.git
cd tty-egpf-monitor
git checkout v0.7.9  # Use the working version
```

### 2. Build Options

#### Option A: Development Build (Dynamic Linking)
```bash
make clean
make
```

#### Option B: Static Build (Recommended for Deployment)
```bash
make clean
STATIC_BPF=1 make
```

#### Option C: Debian Package Build
```bash
# Build Debian packages
dpkg-buildpackage -b

# This creates:
# - tty-egpf-monitord_*.deb (daemon package)
# - tty-egpf-monitor-cli_*.deb (CLI package)
```

### 3. Verify Build
```bash
# Check binary dependencies
ldd build/tty-egpf-monitord

# For static build, should show minimal dependencies:
# linux-vdso.so.1
# libc.so.6
# libelf.so.1
# libz.so.1
# /lib64/ld-linux-x86-64.so.2

# For dynamic build, should also show:
# libbpf.so.1 => /usr/local/lib64/libbpf.so.1
```

## Installation

### Option A: Use Official APT Repository (Recommended)
```bash
# Use the provided installation script
curl -fsSL https://raw.githubusercontent.com/seelso-net/tty-egpf-monitor/main/install.sh | bash
```

### Option B: Install Debian Packages
```bash
# Install the built packages
sudo dpkg -i tty-egpf-monitord_*.deb tty-egpf-monitor-cli_*.deb

# Fix any missing dependencies
sudo apt-get install -f
```

### Option C: Manual Installation
```bash
# Install binaries
sudo cp build/tty-egpf-monitord /usr/local/bin/
sudo cp build/tty-egpf-monitor /usr/local/bin/
sudo chmod +x /usr/local/bin/tty-egpf-monitord
sudo chmod +x /usr/local/bin/tty-egpf-monitor

# Install systemd service
sudo cp packaging/tty-egpf-monitord.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable tty-egpf-monitord

# Create log directory
sudo mkdir -p /var/log/tty-egpf-monitor
sudo chown root:root /var/log/tty-egpf-monitor
sudo chmod 755 /var/log/tty-egpf-monitor
```

## Runtime Requirements

### 1. Kernel Features
The following kernel features must be enabled:
- **eBPF support**: Built into modern kernels
- **BTF (BPF Type Format)**: Available in `/sys/kernel/btf/vmlinux`
- **Tracepoints**: Available in `/sys/kernel/debug/tracing/events/`

### 2. Permissions
The daemon requires:
- **Root privileges** for eBPF program loading
- **Access to tracepoints** in `/sys/kernel/debug/tracing/`
- **Write access** to log directory

### 3. Tracepoint Access
```bash
# Verify tracepoints are accessible
sudo ls -la /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/enable
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/enable
# Should show: 1 (enabled)
```

## Ubuntu Version Differences

### Ubuntu 22.04 (jammy)
- **libbpf**: System libbpf is older, use custom libbpf 1.6.2 from source
- **Build**: Use static linking to avoid runtime dependency issues
- **Kernel**: 5.15+ has good eBPF support
- **BTF**: Available in most kernels

### Ubuntu 24.04 (noble)
- **libbpf**: System libbpf 1.6.2 is available
- **Build**: Can use either static or dynamic linking
- **Kernel**: 6.8+ has excellent eBPF support
- **BTF**: Always available

## Troubleshooting

### 1. Build Issues

#### Missing libbpf
```bash
# Error: libbpf.h: No such file or directory
# Solution: Install libbpf-dev or build from source


# For Ubuntu 22.04, build from source:
wget https://github.com/libbpf/libbpf/archive/refs/tags/v1.6.2.tar.gz
tar -xzf v1.6.2.tar.gz
cd libbpf-1.6.2/src
make
sudo make install
```

#### Missing bpftool
```bash
# Error: bpftool: command not found
# Solution: Install bpftool
sudo apt install -y linux-tools-$(uname -r)

# Or build from libbpf source (includes bpftool)
```

#### Missing BTF
```bash
# Error: BTF not available
# Solution: Ensure kernel has BTF support
ls -la /sys/kernel/btf/vmlinux
# If missing, kernel may not have BTF support
# The build will use fallback vmlinux.h
```

#### Library Version Mismatch
```bash
# Error: libbpf.so.1: version mismatch
# Solution: Use static build
make clean
STATIC_BPF=1 make
```

### 2. Runtime Issues

#### Permission Denied
```bash
# Error: Permission denied accessing tracepoints
# Solution: Run as root
sudo tty-egpf-monitord
```

#### eBPF Program Loading Failed
```bash
# Error: eBPF program loading failed
# Solution: Check kernel version and eBPF support
uname -r
# Should be 5.8+ for full eBPF support
```

#### No Events Detected
```bash
# Issue: No TTY events being detected
# Solution: Check tracepoint status
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/enable
sudo cat /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/enable
# Both should show: 1
```

### 3. Library Issues

#### Missing libbpf.so.1
```bash
# Error: libbpf.so.1: cannot open shared object file
# Solution: Install libbpf runtime library
sudo apt install -y libbpf1
# OR if built from source:
sudo ldconfig
```

#### Wrong Library Version
```bash
# Error: version mismatch
# Solution: Check library versions
ldd /usr/local/bin/tty-egpf-monitord
# Ensure all libraries are compatible
```

## Testing

### 1. Basic Functionality Test
```bash
# Start daemon
sudo tty-egpf-monitord --socket /tmp/test.sock --log-dir /tmp/test-logs &

# Add port monitoring
tty-egpf-monitor --socket /tmp/test.sock add /dev/ttyUSB0

# Test with stty
sudo stty -F /dev/ttyUSB0 115200

# Check logs
cat /tmp/test-logs/ttyUSB0.jsonl
# Should show OPEN/CLOSE events
```

### 2. Real Application Test
```bash
# Test with minicom
sudo timeout 5s minicom -D /dev/ttyUSB0 -b 115200

# Check for events in logs
tail -f /tmp/test-logs/ttyUSB0.jsonl
```

## Version Information

- **Working Version**: v0.7.9
- **Commit**: ddf6505
- **Status**: Production Ready
- **Tested On**: Ubuntu 24.04.3 LTS, Kernel 6.14.0-28-generic

## Support

For issues or questions:
1. Check this deployment guide
2. Verify all dependencies are installed
3. Check kernel compatibility
4. Review troubleshooting section
5. Open an issue on GitHub with system information
