# 📦 Installation Guide

## 🚀 Quick Installation

### Ubuntu 22.04 (Jammy) and Ubuntu 24.04 (Noble)

1. **Add the APT repository**:
```bash
# Detect your Ubuntu version
CODENAME=$(lsb_release -cs)
REPO_URL=https://seelso-net.github.io/tty-egpf-monitor

# Add the repository key and source
curl -fsSL ${REPO_URL}/public-apt-key.asc | sudo gpg --dearmor -o /usr/share/keyrings/tty-egpf-monitor.gpg
echo "deb [signed-by=/usr/share/keyrings/tty-egpf-monitor.gpg] ${REPO_URL} ${CODENAME} main" | sudo tee /etc/apt/sources.list.d/tty-egpf-monitor.list
sudo apt-get update
```

2. **Install the packages** (post-install handles Jammy libbpf automatically):
```bash
sudo apt-get install -y tty-egpf-monitord tty-egpf-monitor-cli
```

3. **Enable and start the service**:
```bash
sudo systemctl enable --now tty-egpf-monitord
```

More details: see [UBUNTU_22_04_COMPATIBILITY.md](UBUNTU_22_04_COMPATIBILITY.md) for the Jammy postinst flow and linking considerations.

4. **Verify installation**:
```bash
# Check service status
sudo systemctl status tty-egpf-monitord

# Test CLI
tty-egpf-monitor list
```

## 🔧 Manual Installation

If you prefer to install manually or need to build from source:

### Prerequisites

```bash
# Install build dependencies
sudo apt-get install -y build-essential clang make libelf-dev zlib1g-dev pkg-config \
    linux-headers-generic libbpf-dev bpftool libsystemd-dev git
```

### Build from Source (developers)

```bash
# Clone the repository
git clone https://github.com/seelso-net/tty-egpf-monitor.git
cd tty-egpf-monitor

# Build
make

# Install
sudo make install
```

## 🐍 Python Client Installation

Install the Python client library for programmatic access and automation:

```bash
# Install from PyPI
pip install tty-egpf-monitor

# Verify installation
tty-egpf-monitor-py --help
python -c "import tty_egpf_monitor; print(tty_egpf_monitor.__version__)"
```

### Python Usage Examples

**Basic library usage:**
```python
from tty_egpf_monitor import TTYMonitorClient

client = TTYMonitorClient()
idx = client.add_port("/dev/ttyUSB0", baudrate=115200)

# Stream live events
for entry in client.stream_parsed_logs("/dev/ttyUSB0"):
    print(f"{entry.timestamp}: {entry.event_type} by {entry.process}")
    if entry.data:
        print(f"  Data: {entry.data}")
```

**CLI usage (compatible with C version):**
```bash
tty-egpf-monitor-py add /dev/ttyUSB0 115200
tty-egpf-monitor-py list
tty-egpf-monitor-py stream /dev/ttyUSB0
tty-egpf-monitor-py logs 0 > captured.jsonl
tty-egpf-monitor-py remove /dev/ttyUSB0
```

**Note:** The daemon (`tty-egpf-monitord`) must still be installed and running. The Python client is just an alternative interface to the same daemon.

## 🐳 Docker Installation

For containerized environments:

```bash
# Mount the host socket and log directory
docker run --rm -it \
  -v /run/tty-egpf-monitord.sock:/run/tty-egpf-monitord.sock \
  -v /var/log/tty-egpf-monitor:/var/log/tty-egpf-monitor \
  --device=/dev/ttyUSB0:/dev/ttyUSB0 \
  ubuntu:22.04 bash

# Inside container, install CLI
apt-get update && apt-get install -y curl
curl -fsSL https://seelso-net.github.io/tty-egpf-monitor/public-apt-key.asc | gpg --dearmor -o /usr/share/keyrings/tty-egpf-monitor.gpg
echo "deb [signed-by=/usr/share/keyrings/tty-egpf-monitor.gpg] https://seelso-net.github.io/tty-egpf-monitor jammy main" | tee /etc/apt/sources.list.d/tty-egpf-monitor.list
apt-get update && apt-get install -y tty-egpf-monitor-cli
```

## 🔍 Verification

After installation, verify everything is working:

```bash
# 1. Check service status
sudo systemctl status tty-egpf-monitord

# 2. Check socket exists (service creates it when running)
ls -la /run/tty-egpf-monitord.sock || true

# 3. Test CLI connection
tty-egpf-monitor list

# 4. Add a test port (if you have a TTY device)
sudo tty-egpf-monitor add /dev/ttyUSB0

# 5. Check logs directory
ls -la /var/log/tty-egpf-monitor/
```

## 🚦 Quick Start

```bash
# Add a serial port to monitor
sudo tty-egpf-monitor add /dev/ttyUSB0

# List configured ports
tty-egpf-monitor list

# View live stream of captured data
tty-egpf-monitor stream 0

# Download captured logs
tty-egpf-monitor logs 0 > captured_data.jsonl

# Remove monitoring
sudo tty-egpf-monitor remove 0
```

## 🔧 Configuration

### Default Settings

- **Socket**: `/run/tty-egpf-monitord.sock`
- **Logs**: `/var/log/tty-egpf-monitor/`
- **Configuration**: `/var/log/tty-egpf-monitor/daemon.conf`

### Runtime Configuration

Configuration persistence is intentionally disabled; add ports via the CLI at runtime or use systemd to run post-start commands. Example:

```ini
[Service]
ExecStartPost=/usr/bin/tty-egpf-monitor add /dev/ttyUSB0 115200
ExecStartPost=/usr/bin/tty-egpf-monitor add /dev/ttyUSB1 115200
```

### Service Configuration

Edit the systemd service:

```bash
sudo systemctl edit tty-egpf-monitord.service
```

Add custom parameters:

```ini
[Service]
ExecStart=
ExecStart=/usr/bin/tty-egpf-monitord --socket /custom/path.sock --log-dir /custom/logs
```

## 🔒 Security Considerations

### Permissions

The daemon requires root privileges for eBPF operations. For CLI access:

```bash
# Create a dedicated group
sudo groupadd tty-monitor

# Add users to the group
sudo usermod -a -G tty-monitor $USER

# Set socket permissions
sudo chown root:tty-monitor /run/tty-egpf-monitord.sock
sudo chmod 660 /run/tty-egpf-monitord.sock
```

### Capabilities

The daemon needs specific capabilities:

```bash
# Check current capabilities
sudo capsh --print

# Required capabilities: cap_bpf, cap_perfmon, cap_net_admin
```

## 🐛 Troubleshooting

### Common Issues

1. **Service won't start**:
```bash
# Check logs
sudo journalctl -u tty-egpf-monitord -f

# Check kernel support
cat /proc/sys/kernel/unprivileged_bpf_disabled
```

2. **Permission denied**:
```bash
# Ensure user is in the correct group
groups $USER

# Check socket permissions
ls -la /run/tty-egpf-monitord.sock
```

3. **No events captured**:
```bash
# Verify BPF program is loaded
sudo bpftool prog list | grep tty

# Check if target device exists
ls -la /dev/ttyUSB*
```

4. **libbpf version issues** (Ubuntu 22.04):
```bash
# Check current version
pkg-config --modversion libbpf

# If needed, install newer version
sudo apt-get install -y git build-essential libelf-dev zlib1g-dev
cd /tmp
git clone --depth 1 --branch v1.6.2 https://github.com/libbpf/libbpf.git
cd libbpf/src
sudo make install
sudo ldconfig
```

### Debug Tips

- Run foreground with custom paths:
  ```bash
  sudo tty-egpf-monitord --socket /tmp/debug.sock --log-dir /tmp/debug-logs
  ```
- Tail service logs: `sudo journalctl -u tty-egpf-monitord -f`

### Log Locations

- **System logs**: `sudo journalctl -u tty-egpf-monitord`
- **Application logs**: `/var/log/tty-egpf-monitor/`
- **BPF logs**: `sudo dmesg | grep bpf`

## 📋 System Requirements

### Minimum Requirements

- **OS**: Ubuntu 22.04 LTS or Ubuntu 24.04 LTS
- **Kernel**: Linux 5.4+ (eBPF support required)
- **Architecture**: x86_64 (amd64)
- **Memory**: 64MB RAM
- **Storage**: 100MB free space

### Recommended

- **Kernel**: Linux 5.15+ (better eBPF features)
- **Memory**: 256MB RAM
- **Storage**: 1GB free space for logs

### Kernel Configuration

Ensure these kernel options are enabled:

```bash
# Check kernel config
zcat /proc/config.gz | grep -E "(BPF|EBPF)"

# Required options:
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_HAVE_EBPF_JIT=y
```

## 🔄 Updates

To update to the latest version:

```bash
sudo apt-get update
sudo apt-get upgrade tty-egpf-monitord tty-egpf-monitor-cli
sudo systemctl restart tty-egpf-monitord
```

## 🗑️ Uninstallation

To completely remove the package:

```bash
# Stop and disable service
sudo systemctl stop tty-egpf-monitord
sudo systemctl disable tty-egpf-monitord

# Remove packages
sudo apt-get remove --purge tty-egpf-monitord tty-egpf-monitor-cli

# Remove repository
sudo rm /etc/apt/sources.list.d/tty-egpf-monitor.list
sudo rm /usr/share/keyrings/tty-egpf-monitor.gpg

# Clean up logs (optional)
sudo rm -rf /var/log/tty-egpf-monitor

# Update package list
sudo apt-get update
```

## 📞 Support

For issues and support:

1. **GitHub Issues**: [Create an issue](https://github.com/seelso-net/tty-egpf-monitor/issues)
2. **Documentation**: Check this guide and the main README.md
3. **Logs**: Use the troubleshooting section above

## 📄 License

This software is licensed under GPL-3.0. See the LICENSE file for details.
