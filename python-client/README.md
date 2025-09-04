# TTY eBPF Monitor Python Client

[![PyPI version](https://badge.fury.io/py/tty-egpf-monitor.svg)](https://badge.fury.io/py/tty-egpf-monitor)
[![Python](https://img.shields.io/pypi/pyversions/tty-egpf-monitor.svg)](https://pypi.org/project/tty-egpf-monitor/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

A Python client library for [TTY eBPF Monitor](https://github.com/seelso-net/tty-egpf-monitor), providing a clean, Pythonic interface to monitor serial port activity using eBPF technology.

## Features

- 🐍 **Pure Python** - No C dependencies, works with any Python 3.8+
- 🔌 **Unix Socket API** - Communicates with daemon via Unix domain socket
- 📊 **Parsed Log Entries** - Automatic parsing of log format with timestamps
- 🔄 **Live Streaming** - Real-time event streaming with iterator interface  
- 🛠️ **CLI Wrapper** - Drop-in replacement for the C CLI tool
- 📚 **Rich Examples** - Comprehensive examples for common use cases
- 🔍 **Data Analysis** - Built-in support for protocol analysis and debugging

## Installation

### Install from PyPI

```bash
pip install tty-egpf-monitor
```

### Install the Daemon

The Python client requires the `tty-egpf-monitord` daemon to be running:

```bash
# Install daemon via APT repository
curl -fsSL https://raw.githubusercontent.com/seelso-net/tty-egpf-monitor/main/install.sh | bash

# Or install manually
CODENAME=$(lsb_release -cs)
REPO_URL=https://seelso-net.github.io/tty-egpf-monitor
curl -fsSL ${REPO_URL}/public-apt-key.asc | sudo gpg --dearmor -o /usr/share/keyrings/tty-egpf-monitor.gpg
echo "deb [signed-by=/usr/share/keyrings/tty-egpf-monitor.gpg] ${REPO_URL} ${CODENAME} main" | sudo tee /etc/apt/sources.list.d/tty-egpf-monitor.list
sudo apt-get update && sudo apt-get install -y tty-egpf-monitord
sudo systemctl enable --now tty-egpf-monitord
```

## Quick Start

### Library Usage

```python
from tty_egpf_monitor import TTYMonitorClient

# Create client
client = TTYMonitorClient()

# Add a port to monitor
idx = client.add_port("/dev/ttyUSB0", baudrate=115200)
print(f"Monitoring port {idx}")

# List all ports
ports = client.list_ports()
for port in ports:
    print(f"Port {port.idx}: {port.device}")

# Stream live events
for entry in client.stream_parsed_logs("/dev/ttyUSB0"):
    print(f"[{entry.timestamp}] {entry.event_type}: {entry.process}")
    if entry.data:
        print(f"  Data: {entry.data}")

# Remove port when done
client.remove_port("/dev/ttyUSB0")
```

### CLI Usage

The package includes a CLI tool compatible with the C version:

```bash
# Add a port
tty-egpf-monitor-py add /dev/ttyUSB0 115200

# List ports
tty-egpf-monitor-py list

# Stream logs (by index or device path)
tty-egpf-monitor-py stream 0
tty-egpf-monitor-py stream /dev/ttyUSB0

# Download logs
tty-egpf-monitor-py logs /dev/ttyUSB0 > captured.jsonl

# Remove port
tty-egpf-monitor-py remove /dev/ttyUSB0
```

## API Reference

### TTYMonitorClient

#### Methods

- **`list_ports()`** → `List[Port]`
  
  List all configured ports.

- **`add_port(device, baudrate=115200, log_path=None)`** → `int`
  
  Add a port to monitor. Returns the port index.

- **`remove_port(port_identifier)`** → `bool`
  
  Remove a port by index (int) or device path (str).

- **`get_logs(port_identifier)`** → `str`
  
  Download full log content for a port.

- **`stream_logs(port_identifier)`** → `Iterator[str]`
  
  Stream raw log lines as they arrive.

- **`stream_parsed_logs(port_identifier)`** → `Iterator[LogEntry]`
  
  Stream parsed log entries as they arrive.

- **`wait_for_event(port_identifier, event_type, timeout=30.0)`** → `Optional[LogEntry]`
  
  Wait for a specific event type with timeout.

### LogEntry

Represents a parsed log entry:

```python
@dataclass
class LogEntry:
    timestamp: datetime      # When the event occurred
    event_type: str         # OPEN, CLOSE, READ, WRITE, IOCTL, MODE_CHANGE
    process: str            # Process name that triggered the event
    direction: Optional[str] # APP->DEV or DEV->APP (for READ/write)
    data: Optional[bytes]   # Raw data (for read/write events)
    raw_line: str          # Original log line
```

### Port

Represents a monitored port:

```python
@dataclass  
class Port:
    idx: int                    # Port index
    device: str                # Device path
    baudrate: Optional[int]     # Configured baud rate
    log_path: Optional[str]     # Log file path
```

## Examples

See the [`examples/`](examples/) directory for comprehensive usage examples:

- **`basic_usage.py`** - Core functionality demonstration
- **`monitor_serial_data.py`** - Real-time monitoring with processing
- **`automation_script.py`** - Automated testing and analysis

## Error Handling

```python
from tty_egpf_monitor import TTYMonitorError

try:
    client = TTYMonitorClient()
    client.add_port("/dev/ttyUSB0")
except TTYMonitorError as e:
    print(f"Error: {e}")
```

## Requirements

- **Python**: 3.8 or later
- **Operating System**: Linux (Ubuntu 22.04+ recommended)
- **Daemon**: `tty-egpf-monitord` must be installed and running
- **Permissions**: Access to the daemon's Unix socket (usually `/run/tty-egpf-monitord.sock`)

## Related Projects

- **[TTY eBPF Monitor](https://github.com/seelso-net/tty-egpf-monitor)** - Main project with C daemon and CLI
- **[APT Repository](https://seelso-net.github.io/tty-egpf-monitor)** - Binary packages for Ubuntu

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](https://github.com/seelso-net/tty-egpf-monitor/blob/main/LICENSE) file for details.
