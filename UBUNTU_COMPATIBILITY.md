# Ubuntu Compatibility Guide

This guide details the compatibility requirements and solutions for running tty-egpf-monitor on different Ubuntu versions.

## Supported Ubuntu Versions

- **Ubuntu 22.04 LTS (Jammy Jellyfish)** ✅
- **Ubuntu 24.04 LTS (Noble Numbat)** ✅

## Key Differences Between Ubuntu Versions

### Ubuntu 22.04 (Jammy)
- **Kernel**: 5.15 (default)
- **libbpf**: Uses `libbpf0` package
- **Capabilities**: No `CAP_BPF` support (kernel < 5.8)
- **Solution**: Uses `CAP_SYS_ADMIN` instead of `CAP_BPF`

### Ubuntu 24.04 (Noble)
- **Kernel**: 6.8+ (default)
- **libbpf**: Uses `libbpf1` package
- **Capabilities**: Full `CAP_BPF` support
- **Solution**: Uses modern capability set including `CAP_BPF`

## Installation Methods

### Method 1: APT Repository (Recommended)

The APT repository automatically selects the correct package for your Ubuntu version:

```bash
# Quick install script
curl -sSL https://seelso-net.github.io/tty-egpf-monitor/install.sh | bash

# Or manual APT setup
wget -qO - https://seelso-net.github.io/tty-egpf-monitor/public-apt-key.asc | \
  gpg --dearmor | \
  sudo tee /usr/share/keyrings/tty-egpf-monitor-archive-keyring.gpg > /dev/null

echo "deb [signed-by=/usr/share/keyrings/tty-egpf-monitor-archive-keyring.gpg] \
  https://seelso-net.github.io/tty-egpf-monitor $(lsb_release -cs) main" | \
  sudo tee /etc/apt/sources.list.d/tty-egpf-monitor.list

sudo apt-get update
sudo apt-get install tty-egpf-monitord tty-egpf-monitor-cli
```

### Method 2: Direct Download

If APT repository is not available for your version:

```bash
# Download latest release
wget https://github.com/seelso-net/tty-egpf-monitor/releases/latest/download/tty-egpf-monitord_*_amd64.deb

# Install with dependency resolution
sudo apt install ./tty-egpf-monitord_*_amd64.deb
```

## Building from Source

When building from source, the build system automatically detects your Ubuntu version:

```bash
# Clone repository
git clone https://github.com/seelso-net/tty-egpf-monitor.git
cd tty-egpf-monitor

# Build with OS-specific configuration
./build-package.sh

# Install the generated package
sudo dpkg -i ../tty-egpf-monitord_*.deb
sudo apt-get install -f
```

## Testing Compatibility

### Quick Compatibility Check

Run the compatibility test script to verify your system:

```bash
./test-compatibility.sh
```

This will check:
- OS version and kernel
- Required dependencies
- Kernel capabilities
- BPF filesystem support
- Build environment

### Multi-Version Testing

Test on multiple Ubuntu versions using Docker:

```bash
./test-multi-ubuntu.sh
```

This will:
- Build packages for each Ubuntu version
- Test installation and functionality
- Generate detailed test reports

## Troubleshooting

### Exit Status 127

If you encounter exit status 127 on Ubuntu 22.04:

1. **Check capabilities**: The service might be trying to use `CAP_BPF` which doesn't exist
   ```bash
   getcap /usr/bin/tty-egpf-monitord
   ```

2. **Verify dependencies**: Ensure all required libraries are installed
   ```bash
   ldd /usr/bin/tty-egpf-monitord
   sudo apt-get install -f
   ```

3. **Check service configuration**: The systemd service should use appropriate capabilities
   ```bash
   systemctl cat tty-egpf-monitord.service | grep Cap
   ```

### Library Version Conflicts

If you see libbpf version errors:

- **Ubuntu 22.04**: Requires `libbpf0`
  ```bash
  sudo apt-get install libbpf0
  ```

- **Ubuntu 24.04**: Requires `libbpf1`
  ```bash
  sudo apt-get install libbpf1
  ```

### Kernel Requirements

Minimum kernel requirements:
- **4.18+**: Basic eBPF support
- **5.8+**: CAP_BPF capability support
- **5.15+**: Full BTF (BPF Type Format) support

Check your kernel version:
```bash
uname -r
```

## Technical Implementation Details

### Package Control Files

The project maintains separate control files for each Ubuntu version:
- `debian/control.jammy` - Ubuntu 22.04 specific dependencies
- `debian/control.noble` - Ubuntu 24.04 specific dependencies

### Systemd Service Files

OS-specific systemd configurations:
- `packaging/tty-egpf-monitord.service.jammy` - Uses CAP_SYS_ADMIN
- `packaging/tty-egpf-monitord.service.noble` - Uses CAP_BPF

### Post-Installation Script

The `debian/tty-egpf-monitord.postinst` script automatically:
- Detects Ubuntu version
- Sets appropriate capabilities
- Configures kernel parameters
- Enables required tracepoints

## Contributing

When adding support for new Ubuntu versions:

1. Create version-specific control file: `debian/control.CODENAME`
2. Create version-specific service file: `packaging/tty-egpf-monitord.service.CODENAME`
3. Update `build-package.sh` to handle the new version
4. Add the codename to `setup-apt-repo.sh` CODENAMES array
5. Update `install.sh` to recognize the new version
6. Add test cases to `test-multi-ubuntu.sh`
7. Update this documentation

## Support Matrix

| Ubuntu Version | Kernel | libbpf | CAP_BPF | Status |
|----------------|--------|---------|---------|---------|
| 22.04 LTS | 5.15 | libbpf0 | ❌ | ✅ Supported |
| 24.04 LTS | 6.8+ | libbpf1 | ✅ | ✅ Supported |
| 20.04 LTS | 5.4 | libbpf0 | ❌ | ⚠️ Untested |
| Future | TBD | TBD | ✅ | 🔄 Planned |
