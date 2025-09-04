# Ubuntu 22.04 Compatibility Improvements

## Overview

This document outlines the comprehensive improvements made to ensure `tty-egpf-monitor` works seamlessly on Ubuntu 22.04 (Jammy Jellyfish) without manual intervention.

## Problem Statement

Ubuntu 22.04 ships with **libbpf 0.5.0**, which has different BPF skeleton attachment APIs compared to the newer **libbpf 1.7.0** that the project was originally designed for (Ubuntu 24.04). This caused:

1. BPF programs to load but not attach to tracepoints
2. No events being captured despite successful compilation
3. Silent failures that were difficult to diagnose

## Solution Architecture

### 1. CI/CD Pipeline Updates (context)

**File: `.github/workflows/release.yml`**

- **Ubuntu 22.04 Job**: Enhanced to build and install newer libbpf from source
- **Automatic Detection**: CI detects Ubuntu 22.04 and automatically upgrades libbpf
- **Dual Package Support**: Separate packages for Ubuntu 22.04 and 24.04

```yaml
# For jammy, build and install newer libbpf to fix compatibility issues
echo "Ubuntu 22.04 (jammy) detected, building newer libbpf for compatibility"

# Install build dependencies for libbpf
apt-get install -y libelf-dev zlib1g-dev

# Build and install newer libbpf
cd /tmp
git clone --depth 1 https://github.com/libbpf/libbpf.git
cd libbpf/src
make && make install
ldconfig
```

### 2. Package Configuration Updates

**Files: `debian/control.jammy`, `debian/control.noble`**

- **Ubuntu 22.04**: Updated to depend on `libbpf1 (>= 1:0.5.0)` instead of `libbpf0`
- **Ubuntu 24.04**: Continues to use native `libbpf1`
- **Separate Control Files**: Ensures proper dependencies for each Ubuntu version

### 3. Automatic Runtime Installation (postinst)

**File: `debian/tty-egpf-monitord.postinst`**

- **Detection**: Automatically detects Ubuntu 22.04 during package installation
- **Conditional Installation**: Only installs newer libbpf if not already present
- **Clean Installation**: Builds from source and cleans up afterward

```bash
# Handle libbpf compatibility for Ubuntu 22.04
if [ -f /etc/os-release ] && grep -q "jammy" /etc/os-release; then
    echo "Ubuntu 22.04 detected, checking libbpf compatibility..."
    
    # Check if we need to install newer libbpf
    if ! ldconfig -p | grep -q "libbpf.so.1"; then
        echo "Installing newer libbpf for Ubuntu 22.04 compatibility..."
        
        # Install build dependencies
        apt-get update -qq
        apt-get install -y --no-install-recommends git build-essential libelf-dev zlib1g-dev
        
        # Build and install newer libbpf
        cd /tmp
        git clone --depth 1 https://github.com/libbpf/libbpf.git
        cd libbpf/src
        make -j$(nproc) && make install
        ldconfig
        
        # Clean up
        cd /
        rm -rf /tmp/libbpf
        
        echo "Newer libbpf installed successfully"
    else
        echo "libbpf.so.1 already available"
    fi
fi
```

### 4. Build System Updates (linking)

**File: `Makefile`**

- **Runtime Path**: Added `-Wl,-rpath,/usr/local/lib` to ensure the binary finds the newer libbpf
- **Linking**: Updated to use standard `-lbpf` linking instead of hardcoded paths

### 5. Documentation Updates

**File: `README.md`**

- **Compatibility Section**: Added clear explanation of Ubuntu version support
- **Troubleshooting**: Comprehensive troubleshooting guide for Ubuntu 22.04
- **Installation Instructions**: Updated with version-specific information

### 6. Installation Scripts

**Files: `install.sh`, `test-installation.sh`**

- **Automated Installation**: One-command installation for both Ubuntu versions
- **Comprehensive Testing**: Automated test suite to verify installation
- **Error Handling**: Robust error detection and reporting

## Technical Details

### libbpf Version Compatibility

| Ubuntu Version | Native libbpf | Package Dependency | Runtime Action |
|----------------|---------------|-------------------|----------------|
| 22.04 (Jammy)  | 0.5.0         | libbpf1 (>= 1:0.5.0) | Auto-upgrade to 1.7.0+ |
| 24.04 (Noble)  | 1.7.0+        | libbpf1 (>= 1:0.5.0) | Use native version |

### BPF Skeleton Attachment

The key difference between libbpf versions:

- **libbpf 0.5.0**: BPF skeleton attachment may fail silently
- **libbpf 1.7.0+**: Proper skeleton attachment with error reporting

### Installation Flow on Jammy

1. **Package Installation**: Standard `apt install` process
2. **Post-installation Script**: Detects Ubuntu 22.04 and upgrades libbpf if needed
3. **Service Start**: Daemon starts with proper libbpf version
4. **Verification**: Test script confirms all components work correctly

## Benefits

### For Users

- **Zero Manual Intervention**: Works out-of-the-box on Ubuntu 22.04
- **Backward Compatibility**: Continues to work on Ubuntu 24.04
- **Automatic Updates**: Future libbpf updates handled automatically
- **Clear Documentation**: Comprehensive troubleshooting guides

### For Developers

- **CI/CD Integration**: Automated testing on both Ubuntu versions
- **Separate Packages**: Clean separation of dependencies
- **Maintainable Code**: Clear version detection and handling
- **Comprehensive Testing**: Automated test suite for verification

## Testing

### Automated Tests

The `test-installation.sh` script verifies:

1. ✅ Package installation
2. ✅ Service status
3. ✅ Socket file creation
4. ✅ CLI connectivity
5. ✅ Log directory setup
6. ✅ libbpf compatibility (Ubuntu 22.04 specific)
7. ✅ BPF program loading

### Manual Testing

```bash
# Install on Ubuntu 22.04
sudo ./install.sh

# Test functionality
sudo ./test-installation.sh

# Add a device and verify monitoring
tty-egpf-monitor add /dev/ttyUSB0
tty-egpf-monitor stream 0
```

## Future Considerations

- **Kernel Compatibility**: Monitor for kernel changes that might affect eBPF
- **libbpf Updates**: Track upstream libbpf releases for potential improvements
- **Distribution Support**: Extend support to other distributions as needed
- **Performance Monitoring**: Track performance impact of libbpf upgrades

## Conclusion

These improvements ensure that `tty-egpf-monitor` provides a seamless experience on Ubuntu 22.04 while maintaining full compatibility with Ubuntu 24.04. The automatic libbpf upgrade process is transparent to users and ensures reliable eBPF functionality across both Ubuntu versions.
