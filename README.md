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

## 🏗️ Architecture

```
┌───────────────┐   UDS   ┌───────────┐    ┌─────────────────┐    ┌───────────────┐
│   CLI (UDS)   │◄───────►│  Daemon   │◄──►│   eBPF Program  │◄──►│ Kernel Trace  │
│ tty-egpf-...  │         │ monitord  │    │ (sniffer.bpf)   │    │ (syscalls)    │
└───────────────┘         └───────────┘    └─────────────────┘    └───────────────┘
```

## 📦 Installation

### Install via apt (GitHub-backed repo)
We publish .deb packages and an apt repository on the `gh-pages` branch. After a tagged release (e.g., `v1.2.3`), CI builds and updates the repo automatically.

1) Add the apt source:
```bash
CODENAME=stable
REPO_URL=https://seelso-net.github.io/tty-egpf-monitor
echo "deb [trusted=yes] ${REPO_URL} ${CODENAME} main" | sudo tee /etc/apt/sources.list.d/tty-egpf-monitor.list
sudo apt-get update
```

Optionally, verify signatures: import our GPG pubkey and replace `trusted=yes` with `signed-by=/usr/share/keyrings/tty-egpf-monitor.gpg`.

2) Install packages:
```bash
sudo apt-get install -y tty-egpf-monitord tty-egpf-monitor-cli
sudo systemctl enable --now tty-egpf-monitord
```

Defaults:
- Socket: `/run/tty-egpf-monitord.sock`
- Logs dir: `/var/log/tty-egpf-monitor`

## 🚀 Quick Start

```bash
# Add a port (default log path is derived from tty name)
tty-egpf-monitor add /dev/ttyUSB0

# List configured ports
tty-egpf-monitor list

# Bulk download NDJSON log for port index 0
tty-egpf-monitor logs 0 > ttyUSB0.jsonl

# Live stream
tty-egpf-monitor stream 0

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

## API (for reference)
- `GET /ports` → list: `[ {"idx":0, "dev":"/dev/ttyUSB0"}, ... ]`
- `POST /ports` with body `{ "dev":"/dev/ttyUSB0", "log":"/custom/path.jsonl" }` → `{ "idx":0 }`
- `DELETE /ports/{idx}` → `{ "ok": true }`
- `DELETE /ports` with body `{ "dev":"/dev/ttyUSB0" }` → `{ "ok": true }`
- `GET /logs/{idx}` → NDJSON body
- `GET /stream/{idx}` → chunked NDJSON stream

## Requirements & Security
- Root privileges needed for eBPF attach.
- Socket permissions: You can move the socket under a restricted directory and chown it to a dedicated group, then run the CLI as a member of that group.
- Systemd unit: `tty-egpf-monitord.service` starts the daemon at boot and places the socket at `/run/tty-egpf-monitord.sock` by default.

### Detailed Daemon–CLI model
- The daemon loads and attaches the eBPF program once, and multiplexes events for multiple ports.
- You instruct the daemon via the Unix socket to add/remove ports; each port writes to its own NDJSON log.
- The CLI is a thin client over HTTP/1.1 requests to the Unix socket; it supports bulk log download and live streaming without touching the kernel.

## License
GPL-3.0. See LICENSE.
