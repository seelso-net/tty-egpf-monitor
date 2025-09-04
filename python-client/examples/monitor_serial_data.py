#!/usr/bin/env python3
"""
Serial data monitoring example.

This example shows how to monitor serial data with filtering and processing.
"""

import time
import signal
import sys
from tty_egpf_monitor import TTYMonitorClient, TTYMonitorError


class SerialDataMonitor:
    """Example class for monitoring and processing serial data."""
    
    def __init__(self, device: str, baudrate: int = 115200):
        self.device = device
        self.baudrate = baudrate
        self.client = TTYMonitorClient()
        self.running = True
        
        # Set up signal handler for clean exit
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        print(f"\nReceived signal {signum}, shutting down...")
        self.running = False
    
    def start_monitoring(self):
        """Start monitoring the serial device."""
        try:
            print(f"Starting monitor for {self.device} at {self.baudrate} baud")
            
            # Add the port
            try:
                idx = self.client.add_port(self.device, self.baudrate)
                print(f"Port added with index: {idx}")
            except TTYMonitorError as e:
                if "already exists" in str(e):
                    print(f"Port {self.device} already being monitored")
                else:
                    raise
            
            # Monitor for events
            print("Monitoring for TTY events (Ctrl+C to stop)...")
            self._monitor_events()
            
        except TTYMonitorError as e:
            print(f"Error: {e}")
            return 1
        finally:
            # Clean up
            try:
                self.client.remove_port(self.device)
                print(f"Removed monitoring for {self.device}")
            except TTYMonitorError:
                pass  # Ignore cleanup errors
        
        return 0
    
    def _monitor_events(self):
        """Monitor and process events."""
        data_buffer = bytearray()
        
        try:
            for entry in self.client.stream_parsed_logs(self.device):
                if not self.running:
                    break
                
                timestamp = entry.timestamp.strftime("%d.%m.%y %H:%M:%S.%f")[:-3]
                
                if entry.event_type == "OPEN":
                    print(f"[{timestamp}] 📂 {entry.process} opened the port")
                
                elif entry.event_type == "CLOSE":
                    print(f"[{timestamp}] 📁 {entry.process} closed the port")
                    if data_buffer:
                        print(f"    Final data buffer: {data_buffer}")
                        data_buffer.clear()
                
                elif entry.event_type == "WRITE":
                    if entry.data:
                        data_buffer.extend(entry.data)
                        print(f"[{timestamp}] ✍️  {entry.process} wrote {len(entry.data)} bytes")
                        print(f"    Data: {entry.data}")
                        
                        # Example: detect specific patterns
                        if b"AT" in entry.data:
                            print("    🔍 Detected AT command!")
                        
                elif entry.event_type == "READ":
                    if entry.data:
                        print(f"[{timestamp}] 📖 {entry.process} read {len(entry.data)} bytes")
                        print(f"    Data: {entry.data}")
                
                elif entry.event_type == "MODE_CHANGE":
                    print(f"[{timestamp}] 🔄 Mode change: {entry.raw_line}")
                
                elif entry.event_type == "IOCTL":
                    print(f"[{timestamp}] ⚙️  {entry.process} ioctl operation")
                
                else:
                    print(f"[{timestamp}] ❓ Unknown event: {entry.raw_line}")
        
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user")


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Monitor serial data with TTY eBPF Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This example demonstrates real-time serial data monitoring with event processing.

Example usage:
  python monitor_serial_data.py /dev/ttyUSB0
  python monitor_serial_data.py /dev/ttyUSB0 --baudrate 9600
"""
    )
    
    parser.add_argument("device", help="Serial device to monitor (e.g., /dev/ttyUSB0)")
    parser.add_argument("--baudrate", type=int, default=115200, help="Baud rate (default: 115200)")
    
    args = parser.parse_args()
    
    # Create and start monitor
    monitor = SerialDataMonitor(args.device, args.baudrate)
    return monitor.start_monitoring()


if __name__ == "__main__":
    sys.exit(main())
