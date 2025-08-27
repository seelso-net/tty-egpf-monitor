# 🔍 TTY EGPF Monitor

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL%203.0-green.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![eBPF](https://img.shields.io/badge/eBPF-CO--RE-blue.svg)](https://ebpf.io/)
[![Linux](https://img.shields.io/badge/Linux-Kernel-orange.svg)](https://www.kernel.org/)

> **Advanced Serial Port Monitoring with eBPF Technology**

A sophisticated real-time serial port monitoring tool that combines the power of eBPF (extended Berkeley Packet Filter) with intelligent state management to provide comprehensive visibility into TTY device activity. Perfect for debugging, reverse engineering, and monitoring serial communications.

## ✨ Features

### 🚀 **Dual-Mode Operation**
- **Active Mode**: Directly reads from the serial port when no other applications are using it
- **Passive Mode**: Uses eBPF to monitor all system calls when other applications are actively using the port
- **Automatic State Transitions**: Seamlessly switches between modes based on port availability

### 🔧 **eBPF-Powered Monitoring**
- **CO-RE (Compile Once, Run Everywhere)**: No kernel module compilation required
- **System Call Tracing**: Monitors `open()`, `close()`, `read()`, `write()`, and `ioctl()` operations
- **Real-time Data Capture**: Captures actual data being transmitted/received
- **Process Identification**: Tracks which processes are accessing the serial port

### 📊 **Comprehensive Logging**
- **JSON Lines Format**: Machine-readable output for easy parsing
- **Timestamped Events**: Nanosecond precision timing
- **Hex Data Dumps**: Complete visibility into serial data
- **Process Context**: Command names and process IDs for all operations

### ⚙️ **Flexible Configuration**
- **Baud Rate Support**: 9600 to 921600 baud
- **Data Bits**: 7 or 8 bits
- **Parity**: None, Even, or Odd
- **Stop Bits**: 1 or 2 bits
- **Hardware Flow Control**: Optional RTS/CTS support

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Orchestrator  │    │   eBPF Program  │    │   Kernel Space  │
│   (Userspace)   │◄──►│   (sniffer.bpf) │◄──►│   (Tracepoints) │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Active Mode   │    │  Ring Buffer    │    │  System Calls   │
│  Direct Read    │    │   Events        │    │   Monitoring    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 📋 Requirements

### System Requirements
- **Linux Kernel**: 5.4+ with BTF support
- **Architecture**: x86_64, ARM64, or ARM
- **Permissions**: Root access (for eBPF operations)

### Build Dependencies
```bash
# Ubuntu/Debian
sudo apt-get install clang make bpftool libbpf-dev libelf-dev zlib1g-dev pkg-config

# CentOS/RHEL/Fedora
sudo dnf install clang make bpftool libbpf-devel elfutils-libelf-devel zlib-devel pkg-config
```

## 📦 Installation

### Option 1: GitHub Releases (Recommended)
```bash
# Download and install the latest release
wget https://github.com/seelso-net/tty-egpf-monitor/releases/latest/download/tty-egpf-monitor_*_amd64.deb
sudo dpkg -i tty-egpf-monitor_*_amd64.deb
sudo apt-get install -f -y  # Fix any dependency issues
```

### Option 2: Version-Specific Installation
```bash
# Install specific version from GitHub releases
wget https://github.com/seelso-net/tty-egpf-monitor/releases/download/v1.0.0/tty-egpf-monitor_1.0.0_amd64.deb
sudo dpkg -i tty-egpf-monitor_1.0.0_amd64.deb
sudo apt-get install -f -y  # Fix any dependency issues
```

### Option 3: From Source
```bash
# Clone the repository
git clone https://github.com/seelso-net/tty-egpf-monitor.git
cd tty-egpf-monitor

# Install dependencies
sudo apt-get update
sudo apt-get install -y \
  clang \
  make \
  libelf-dev \
  zlib1g-dev \
  pkg-config \
  build-essential \
  linux-headers-$(uname -r) \
  libbpf-dev

# Install bpftool (if not available in package manager)
sudo apt-get install -y bpftool || {
  # Build from source
  sudo apt-get install -y \
    libcap-dev \
    libpcap-dev \
    libbfd-dev \
    binutils-dev \
    libreadline-dev \
    libssl-dev \
    libnuma-dev \
    cmake \
    ninja-build \
    llvm
  
  git clone --depth 1 --branch v6.6 https://github.com/torvalds/linux.git /tmp/linux
  cd /tmp/linux/tools/bpf/bpftool
  make -j$(nproc)
  sudo make install
  sudo ldconfig
  cd -
}

# Build the application
make clean
make
```

## 🚀 Quick Start

### 1. Build the Application (if installed from source)
```bash
git clone <repository-url>
cd tty-egpf-monitor
make
```

### 2. Run Basic Monitoring
```bash
# Monitor /dev/ttyUSB0 with default settings
sudo tty-egpf-monitor -d /dev/ttyUSB0

# Monitor with custom baud rate
sudo tty-egpf-monitor -d /dev/ttyUSB0 --baud 115200

# Save output to custom log file
sudo tty-egpf-monitor -d /dev/ttyUSB0 -l my_serial_log.jsonl
```

### 3. Advanced Configuration
```bash
# Full serial configuration
sudo tty-egpf-monitor \
  -d /dev/ttyUSB0 \
  --baud 9600 \
  --databits 8 \
  --parity N \
  --stopbits 1 \
  --crtscts \
  -l detailed_log.jsonl
```

## 📖 Usage Examples

### Basic Serial Port Monitoring
```bash
# Start monitoring
sudo tty-egpf-monitor -d /dev/ttyUSB0

# In another terminal, use the serial port
echo "Hello World" > /dev/ttyUSB0
cat /dev/ttyUSB0
```

### Monitoring Industrial Equipment
```bash
# Monitor Modbus RTU communication
sudo tty-egpf-monitor \
  -d /dev/ttyUSB0 \
  --baud 9600 \
  --databits 8 \
  --parity E \
  --stopbits 1 \
  -l modbus_traffic.jsonl
```

### Debugging Embedded Systems
```bash
# Monitor UART communication with embedded device
sudo tty-egpf-monitor \
  -d /dev/ttyACM0 \
  --baud 115200 \
  -l embedded_debug.jsonl
```

## 📊 Output Format

The application generates JSON Lines format output with the following event types:

### Active Read Events
```json
{
  "ts": 1703123456.123456789,
  "event": "active_read",
  "n": 10,
  "data": "48656c6c6f20576f726c64"
}
```

### System Call Events
```json
{
  "ts": 1703123456.123456789,
  "type": "write",
  "pid": 1234,
  "tgid": 1234,
  "comm": "myapp",
  "dir": "app2dev",
  "len": 5,
  "trunc": 0,
  "data": "48656c6c6f"
}
```

### IOCTL Events
```json
{
  "ts": 1703123456.123456789,
  "type": "ioctl",
  "pid": 1234,
  "tgid": 1234,
  "comm": "myapp",
  "ioctl": "TCGETS",
  "cmd": 21505
}
```

## 🔧 Configuration Options

| Option | Description | Default | Values |
|--------|-------------|---------|--------|
| `-d` | Device path | Required | `/dev/tty*` |
| `-l` | Log file path | `serial-sniff.jsonl` | Any writable path |
| `--baud` | Baud rate | 115200 | 9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600 |
| `--databits` | Data bits | 8 | 7, 8 |
| `--parity` | Parity | N | N (None), E (Even), O (Odd) |
| `--stopbits` | Stop bits | 1 | 1, 2 |
| `--crtscts` | Hardware flow control | Disabled | Flag (enables RTS/CTS) |

## 🛠️ Development

### Project Structure
```
tty-egpf-monitor/
├── src/
│   ├── orchestrator.c      # Main userspace application
│   └── sniffer.bpf.c       # eBPF program for system call monitoring
├── build/                  # Build artifacts (generated)
├── Makefile               # Build configuration
└── README.md              # This file
```

### Building from Source
```bash
# Clean build
make clean

# Build with debug symbols
make CFLAGS="-O0 -g -DDEBUG"

# Cross-compile for ARM
make CC=arm-linux-gnueabihf-gcc BPF_CLANG=clang
```

### Debugging
```bash
# Run with verbose output
sudo ./build/sermon -d /dev/ttyUSB0 2>&1 | tee debug.log

# Monitor eBPF program loading
sudo bpftool prog list | grep sniffer

# Check ring buffer statistics
sudo bpftool map dump name events
```

## 🔒 Security Considerations

- **Root Access Required**: eBPF programs require elevated privileges
- **Kernel Interface**: Direct interaction with kernel tracepoints
- **Data Capture**: Captures all serial data - ensure sensitive data is handled appropriately
- **Process Visibility**: Monitors all processes accessing the target device

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Development Setup
```bash
# Install development dependencies
sudo apt-get install clang-tools valgrind

# Run static analysis
clang-tidy src/*.c

# Memory leak detection
valgrind --leak-check=full ./build/sermon -d /dev/ttyUSB0
```

## 📄 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **eBPF Community**: For the amazing eBPF technology
- **libbpf**: For the excellent eBPF library
- **Linux Kernel**: For CO-RE and BTF support

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/your-repo/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-repo/discussions)
- **Documentation**: [Wiki](https://github.com/your-repo/wiki)

---

**Made with ❤️ and eBPF magic**
