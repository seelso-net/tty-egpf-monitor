"""
TTY eBPF Monitor Python Client

Provides a Python interface to the tty-egpf-monitord daemon via Unix domain socket.
"""

import json
import socket
import time
from typing import List, Optional, Iterator, Dict, Any, Union
from datetime import datetime
from .models import Port, LogEntry


class TTYMonitorError(Exception):
    """Exception raised for TTY Monitor API errors."""
    pass


class TTYMonitorClient:
    """Client for interacting with tty-egpf-monitord daemon."""
    
    def __init__(self, socket_path: str = "/run/tty-egpf-monitord.sock"):
        """
        Initialize the client.
        
        Args:
            socket_path: Path to the daemon's Unix domain socket
        """
        self.socket_path = socket_path
    
    def _send_http_request(self, method: str, path: str, body: Optional[str] = None) -> str:
        """Send HTTP request over Unix domain socket and return response body."""
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(self.socket_path)
            
            # Build HTTP request
            if body:
                request = (
                    f"{method} {path} HTTP/1.1\r\n"
                    f"Host: localhost\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                    f"{body}"
                )
            else:
                request = (
                    f"{method} {path} HTTP/1.1\r\n"
                    f"Host: localhost\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                )
            
            sock.sendall(request.encode())
            
            # Read response
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            
            response_str = response.decode('utf-8')
            
            # Parse HTTP response
            if '\r\n\r\n' not in response_str:
                raise TTYMonitorError("Invalid HTTP response")
            
            headers, body = response_str.split('\r\n\r\n', 1)
            
            # Check status code
            status_line = headers.split('\r\n')[0]
            if not status_line.startswith('HTTP/1.1 2'):
                # Extract error message from body if available
                error_msg = body.strip() if body else "Request failed"
                raise TTYMonitorError(f"HTTP error: {status_line} - {error_msg}")
            
            return body
            
        except socket.error as e:
            raise TTYMonitorError(f"Socket error: {e}")
        finally:
            sock.close()
    
    def list_ports(self) -> List[Port]:
        """
        List all configured ports.
        
        Returns:
            List of Port objects
        """
        body = self._send_http_request("GET", "/ports")
        try:
            ports_data = json.loads(body)
            return [Port.from_dict(port_data) for port_data in ports_data]
        except json.JSONDecodeError as e:
            raise TTYMonitorError(f"Invalid JSON response: {e}")
    
    def add_port(self, device: str, baudrate: int = 115200, log_path: Optional[str] = None) -> int:
        """
        Add a port to monitor.
        
        Args:
            device: Device path (e.g., "/dev/ttyUSB0")
            baudrate: Baud rate (default: 115200)
            log_path: Custom log path (optional)
        
        Returns:
            Port index
        """
        request_data = {
            "dev": device,
            "log": log_path or "",
            "baudrate": baudrate
        }
        
        body = self._send_http_request("POST", "/ports", json.dumps(request_data))
        try:
            response = json.loads(body)
            idx = response["idx"]
            if not isinstance(idx, int):
                raise TTYMonitorError(f"Invalid idx type: {type(idx)}")
            return idx
        except (json.JSONDecodeError, KeyError) as e:
            raise TTYMonitorError(f"Invalid response: {e}")
    
    def remove_port(self, port_identifier: Union[str, int]) -> bool:
        """
        Remove a port from monitoring.
        
        Args:
            port_identifier: Port index (int) or device path (str)
        
        Returns:
            True if successful
        """
        if isinstance(port_identifier, int):
            # Remove by index
            body = self._send_http_request("DELETE", f"/ports/{port_identifier}")
        else:
            # Remove by device path
            request_data = {"dev": str(port_identifier)}
            body = self._send_http_request("DELETE", "/ports", json.dumps(request_data))
        
        try:
            response = json.loads(body)
            ok_value = response.get("ok", False)
            return bool(ok_value)
        except json.JSONDecodeError:
            return False
    
    def get_logs(self, port_identifier: Union[str, int]) -> str:
        """
        Download full log for a port.
        
        Args:
            port_identifier: Port index (int) or device path (str)
        
        Returns:
            Raw log content
        """
        if isinstance(port_identifier, str):
            # Resolve device path to index
            ports = self.list_ports()
            idx = None
            for port in ports:
                if port.device == port_identifier:
                    idx = port.idx
                    break
            if idx is None:
                raise TTYMonitorError(f"Device not found: {port_identifier}")
        else:
            idx = port_identifier
        
        return self._send_http_request("GET", f"/logs/{idx}")
    
    def parse_logs(self, log_content: str) -> List[LogEntry]:
        """
        Parse log content into LogEntry objects.
        
        Args:
            log_content: Raw log content from get_logs()
        
        Returns:
            List of parsed LogEntry objects
        """
        entries = []
        for line in log_content.strip().split('\n'):
            if line.strip():
                try:
                    entry = LogEntry.parse_simple_log(line)
                    entries.append(entry)
                except Exception:
                    # If parsing fails, create a basic entry with raw line
                    entries.append(LogEntry(
                        timestamp=datetime.now(),
                        event_type="UNPARSED",
                        process="",
                        raw_line=line.strip()
                    ))
        return entries
    
    def stream_logs(self, port_identifier: Union[str, int]) -> Iterator[str]:
        """
        Stream live logs for a port.
        
        Args:
            port_identifier: Port index (int) or device path (str)
        
        Yields:
            Log lines as they arrive
        """
        if isinstance(port_identifier, str):
            # Resolve device path to index
            ports = self.list_ports()
            idx = None
            for port in ports:
                if port.device == port_identifier:
                    idx = port.idx
                    break
            if idx is None:
                raise TTYMonitorError(f"Device not found: {port_identifier}")
        else:
            idx = port_identifier
        
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(self.socket_path)
            
            # Send streaming request
            request = (
                f"GET /stream/{idx} HTTP/1.1\r\n"
                f"Host: localhost\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            sock.sendall(request.encode())
            
            # Read response headers
            headers = b""
            while b'\r\n\r\n' not in headers:
                chunk = sock.recv(1)
                if not chunk:
                    raise TTYMonitorError("Connection closed while reading headers")
                headers += chunk
            
            # Check status
            headers_str = headers.decode('utf-8')
            if not headers_str.startswith('HTTP/1.1 200'):
                raise TTYMonitorError(f"Stream failed: {headers_str.split()[1]}")
            
            # Read chunked response
            buffer = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                
                buffer += chunk
                
                # Process complete lines
                while b'\n' in buffer:
                    line, buffer = buffer.split(b'\n', 1)
                    line_str = line.decode('utf-8', errors='replace').strip()
                    
                    # Skip HTTP chunked encoding artifacts
                    if line_str and not line_str.isdigit() and line_str != '0':
                        # Skip chunked encoding hex numbers and empty lines
                        if not all(c in '0123456789abcdefABCDEF' for c in line_str):
                            yield line_str
        
        except socket.error as e:
            raise TTYMonitorError(f"Socket error: {e}")
        finally:
            sock.close()
    
    def stream_parsed_logs(self, port_identifier: Union[str, int]) -> Iterator[LogEntry]:
        """
        Stream live logs for a port, parsed into LogEntry objects.
        
        Args:
            port_identifier: Port index (int) or device path (str)
        
        Yields:
            Parsed LogEntry objects as they arrive
        """
        for line in self.stream_logs(port_identifier):
            try:
                yield LogEntry.parse_simple_log(line)
            except Exception:
                # If parsing fails, yield raw entry
                yield LogEntry(
                    timestamp=datetime.now(),
                    event_type="UNPARSED",
                    process="",
                    raw_line=line
                )
    
    def wait_for_event(self, port_identifier: Union[str, int], event_type: str, timeout: float = 30.0) -> Optional[LogEntry]:
        """
        Wait for a specific event type on a port.
        
        Args:
            port_identifier: Port index (int) or device path (str)
            event_type: Event type to wait for (e.g., "OPEN", "WRITE", "READ")
            timeout: Maximum time to wait in seconds
        
        Returns:
            LogEntry if event found, None if timeout
        """
        start_time = time.time()
        
        for entry in self.stream_parsed_logs(port_identifier):
            if entry.event_type == event_type:
                return entry
            
            if time.time() - start_time > timeout:
                break
        
        return None
