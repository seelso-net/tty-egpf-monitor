# TTY eBPF Monitor Python Examples

This directory contains example scripts demonstrating how to use the TTY eBPF Monitor Python client library.

## Prerequisites

1. **Install the daemon** (if not already installed):
   ```bash
   curl -fsSL https://raw.githubusercontent.com/seelso-net/tty-egpf-monitor/main/install.sh | bash
   ```

2. **Install the Python client**:
   ```bash
   pip install tty-egpf-monitor
   ```

3. **Ensure the daemon is running**:
   ```bash
   sudo systemctl status tty-egpf-monitord
   ```

## Examples

### 1. Basic Usage (`basic_usage.py`)

Demonstrates core functionality of the Python client library:
- Adding and removing ports
- Listing configured ports  
- Getting historical logs
- Streaming live events

```bash
python basic_usage.py
```

### 2. Serial Data Monitoring (`monitor_serial_data.py`)

Advanced example showing real-time monitoring with event processing:
- Event filtering and categorization
- Data pattern detection
- Formatted output with emojis
- Graceful shutdown handling

```bash
python monitor_serial_data.py /dev/ttyUSB0
python monitor_serial_data.py /dev/ttyUSB0 --baudrate 9600
```

### 3. Automation Script (`automation_script.py`)

Example for automated testing and monitoring:
- Waiting for device activity
- Capturing session data
- Protocol analysis
- Summary reporting

```bash
python automation_script.py /dev/ttyUSB0 30
```

## Library Usage

### Quick Start

```python
from tty_egpf_monitor import TTYMonitorClient

# Create client
client = TTYMonitorClient()

# Add a port
idx = client.add_port("/dev/ttyUSB0", baudrate=115200)

# List ports
ports = client.list_ports()
for port in ports:
    print(f"Port {port.idx}: {port.device}")

# Stream live events
for entry in client.stream_parsed_logs("/dev/ttyUSB0"):
    print(f"{entry.timestamp}: {entry.event_type} by {entry.process}")
    if entry.data:
        print(f"  Data: {entry.data}")

# Remove port
client.remove_port("/dev/ttyUSB0")
```

### API Reference

#### TTYMonitorClient

- `list_ports()` → `List[Port]`
- `add_port(device, baudrate=115200, log_path=None)` → `int`
- `remove_port(port_identifier)` → `bool`
- `get_logs(port_identifier)` → `str`
- `stream_logs(port_identifier)` → `Iterator[str]`
- `stream_parsed_logs(port_identifier)` → `Iterator[LogEntry]`
- `wait_for_event(port_identifier, event_type, timeout=30.0)` → `Optional[LogEntry]`

#### LogEntry

- `timestamp: datetime`
- `event_type: str` (OPEN, CLOSE, READ, WRITE, IOCTL, MODE_CHANGE)
- `process: str`
- `direction: Optional[str]` (APP->DEV, DEV->APP)
- `data: Optional[bytes]`
- `raw_line: str`

## Error Handling

All API methods may raise `TTYMonitorError` for:
- Connection failures
- HTTP errors
- Invalid responses
- Device not found

```python
from tty_egpf_monitor import TTYMonitorError

try:
    client.add_port("/dev/ttyUSB0")
except TTYMonitorError as e:
    print(f"Failed to add port: {e}")
```

## Tips

1. **Run with appropriate permissions**: The daemon runs as root, but the Python client can run as any user with access to the socket.

2. **Handle interrupts gracefully**: Use signal handlers for clean shutdown in long-running scripts.

3. **Device path vs index**: Most methods accept either a device path (`"/dev/ttyUSB0"`) or port index (`0`).

4. **Stream processing**: Use `stream_parsed_logs()` for real-time processing, `get_logs()` for historical data.

5. **Data handling**: Serial data is returned as `bytes` objects, allowing proper handling of binary protocols.
