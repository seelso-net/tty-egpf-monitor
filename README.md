# 🔍 TTY EGPF Monitor

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL%203.0-green.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![eBPF](https://img.shields.io/badge/eBPF-CO--RE-blue.svg)](https://ebpf.io/)
[![Linux](https://img.shields.io/badge/Linux-Kernel-orange.svg)](https://www.kernel.org/)

> **Advanced Serial Port Monitoring with eBPF Technology**

A sophisticated real-time serial port monitoring tool that combines the power of eBPF (extended Berkeley Packet Filter) with intelligent state management to provide comprehensive visibility into TTY device activity. Perfect for debugging, reverse engineering, and monitoring serial communications.

## ✨ Features

### 🚀 **Daemon + CLI Model**
- **Daemon (tty-egpf-monitord)**: Runs on the host, loads/attaches the eBPF program and manages multiple TTY targets. Exposes a local Unix domain socket API at `/run/tty-egpf-monitord.sock`.
- **CLI (tty-egpf-monitor)**: Talks to the daemon via the Unix socket to add/list/remove ports and to fetch logs (bulk or live stream). Ideal for containers – just mount the socket.

### 🚦 **Multi-port Monitoring**
- Configure multiple devices; each port has its own log
- eBPF events include a `port_idx` to attribute data to the correct log

### 🔧 **eBPF-Powered Monitoring**
- CO-RE, tracepoints for `open/close/read/write/ioctl`, real-time data capture

### 📊 **Per-port Logs**
- Stored as NDJSON under `/var/log/tty-egpf-monitor/<tty>.jsonl` by default
- Overridable per-port log path at add time
- Human-readable mode with millisecond timestamps; data is quoted and non-printable bytes are escaped as `\\xNN`

### 🧹 Noise-free, attribute-based filtering
- OPEN is emitted immediately only for writable opens
- READ/WRITE are logged only for FDs opened writable and after OPEN was emitted
- IOCTLs are limited to important TTY-related ones
- Effectively eliminates systemd/udisks/housekeeping scanners and container runtime noise

## 🏗️ Architecture

```
┌───────────────┐   UDS   ┌───────────┐    ┌─────────────────┐    ┌───────────────┐
│   CLI (UDS)   │◄───────►│  Daemon   │◄──►│   eBPF Program  │◄──►│ Kernel Trace  │
│ tty-egpf-...  │         │ monitord  │    │ (sniffer.bpf)   │    │ (syscalls)    │
└───────────────┘         └───────────┘    └─────────────────┘    └───────────────┘
```

## 📦 Installation

### 🚀 Quick Install (Recommended)

**Option 1: One-command installation script**
```bash
curl -fsSL https://raw.githubusercontent.com/seelso-net/tty-egpf-monitor/main/install.sh | bash
```

**Option 2: Manual installation**
```bash
# Add repository and install
CODENAME=$(lsb_release -cs)
REPO_URL=https://seelso-net.github.io/tty-egpf-monitor
curl -fsSL ${REPO_URL}/public-apt-key.asc | sudo gpg --dearmor -o /usr/share/keyrings/tty-egpf-monitor.gpg
echo "deb [signed-by=/usr/share/keyrings/tty-egpf-monitor.gpg] ${REPO_URL} ${CODENAME} main" | sudo tee /etc/apt/sources.list.d/tty-egpf-monitor.list
sudo apt-get update
sudo apt-get install -y tty-egpf-monitord tty-egpf-monitor-cli
sudo systemctl enable --now tty-egpf-monitord
```

### 📋 Detailed Installation Guide

For complete installation instructions, troubleshooting, and advanced configuration, see **[INSTALLATION.md](INSTALLATION.md)**.

### 🔧 Manual Build

If you prefer to build from source:

```bash
# Install dependencies
sudo apt-get install -y build-essential clang make libelf-dev zlib1g-dev pkg-config \
    linux-headers-generic libbpf-dev bpftool libsystemd-dev git

# Build and install
git clone https://github.com/seelso-net/tty-egpf-monitor.git
cd tty-egpf-monitor
make
sudo make install
```

### 🐳 Docker Support

For containerized environments, see the [Docker section in INSTALLATION.md](INSTALLATION.md#docker-installation).

### 📦 Package Information

- **Repository**: GitHub Pages-hosted APT repository
- **Signing**: GPG-signed packages for security
- **Supported**: Ubuntu 22.04 (Jammy) and Ubuntu 24.04 (Noble)

## 🚀 Ubuntu 22.04 (Jammy) Compatibility

- The APT package performs a post-install check on Jammy. If a modern libbpf is not available, it automatically builds and installs a newer libbpf from source, then runs ldconfig.
- On Ubuntu 24.04 (Noble), the native libbpf is sufficient and no action is taken.
- This happens transparently during `apt install tty-egpf-monitord`—no manual steps are required.

See also: [UBUNTU_22_04_COMPATIBILITY.md](UBUNTU_22_04_COMPATIBILITY.md) for deep-dive details (libbpf versions, linking, CI, and postinst flow).

**Defaults**:
- Socket: `/run/tty-egpf-monitord.sock`
- Logs dir: `/var/log/tty-egpf-monitor`

## 🚀 Quick Start

```bash
# Add a port (default log path is derived from tty name)
tty-egpf-monitor add /dev/ttyUSB0

# List configured ports
tty-egpf-monitor list

# Bulk download NDJSON log for port (by index or device)
tty-egpf-monitor logs 0 > ttyUSB0.jsonl
tty-egpf-monitor logs /dev/ttyUSB0 > ttyUSB0.jsonl

# Live stream (by index or device)
tty-egpf-monitor stream 0
tty-egpf-monitor stream /dev/ttyUSB0

# Remove by index
tty-egpf-monitor remove 0

# Or remove by device path
tty-egpf-monitor remove /dev/ttyUSB0
```

## 🐳 Container Usage
Mount the host socket and log directory into the container:
```bash
docker run --rm -it \
  -v /run/tty-egpf-monitord.sock:/run/tty-egpf-monitord.sock \
  -v /var/log/tty-egpf-monitor:/var/log/tty-egpf-monitor \
  ghcr.io/yourorg/tty-egpf-monitor-cli:latest \
  tty-egpf-monitor list
```

## 🔌 Daemon Configuration
```bash
sudo tty-egpf-monitord \
  --socket /run/tty-egpf-monitord.sock \
  --log-dir /var/log/tty-egpf-monitor
```

Note: configuration persistence is intentionally disabled. Add ports at runtime via the CLI. If you need ports configured on boot, use a systemd drop-in with ExecStartPost to call the CLI.

## API (for reference)
- `GET /ports` → list: `[ {"idx":0, "dev":"/dev/ttyUSB0"}, ... ]`
- `POST /ports` with body `{ "dev":"/dev/ttyUSB0", "log":"/custom/path.jsonl", "baudrate":115200 }` → `{ "idx":0 }`
- `DELETE /ports/{idx}` → `{ "ok": true }`
- `DELETE /ports` with body `{ "dev":"/dev/ttyUSB0" }` → `{ "ok": true }`
- `GET /logs/{idx}` → NDJSON body
- `GET /stream/{idx}` → chunked NDJSON stream

## Requirements & Security
- Root privileges needed for eBPF attach.
- Socket permissions: You can move the socket under a restricted directory and chown it to a dedicated group, then run the CLI as a member of that group.
- Systemd unit: `tty-egpf-monitord.service` starts the daemon at boot and places the socket at `/run/tty-egpf-monitord.sock` by default.

## 🔧 Troubleshooting

### Common Issues

- **Permission Denied**: Ensure the daemon has the necessary capabilities (`cap_bpf`, `cap_perfmon`, `cap_net_admin`)
- **eBPF Not Supported**: Check if your kernel supports eBPF and if `unprivileged_bpf_disabled` is set to 1
- **No Events Captured**: Verify that the target devices are being accessed and that the BPF programs are properly attached

### Detailed Daemon–CLI model
- The daemon loads and attaches the eBPF program once, and multiplexes events for multiple ports.
- You instruct the daemon via the Unix socket to add/remove ports; each port writes to its own NDJSON log.
- The CLI is a thin client over HTTP/1.1 requests to the Unix socket; it supports bulk log download and live streaming without touching the kernel.

## License
GPL-3.0. See LICENSE.
