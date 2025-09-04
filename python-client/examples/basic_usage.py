#!/usr/bin/env python3
"""
Basic usage example for TTY eBPF Monitor Python client.

This example demonstrates the core functionality of the Python client library.
"""

import time
from tty_egpf_monitor import TTYMonitorClient, TTYMonitorError


def main():
    """Demonstrate basic usage of the TTY monitor client."""
    # Create client (uses default socket path)
    client = TTYMonitorClient()
    
    try:
        print("=== TTY eBPF Monitor Python Client Demo ===\n")
        
        # List current ports
        print("1. Listing current ports:")
        ports = client.list_ports()
        if ports:
            for port in ports:
                print(f"   Port {port.idx}: {port.device}")
        else:
            print("   No ports configured")
        
        # Add a port (example - adjust device path as needed)
        device = "/dev/ttyUSB0"
        print(f"\n2. Adding port: {device}")
        try:
            idx = client.add_port(device, baudrate=115200)
            print(f"   Port added with index: {idx}")
            
            # List ports again to show the addition
            print("\n3. Updated port list:")
            ports = client.list_ports()
            for port in ports:
                print(f"   Port {port.idx}: {port.device}")
            
            # Get existing logs
            print(f"\n4. Getting existing logs for {device}:")
            logs = client.get_logs(device)
            if logs.strip():
                print("   Recent log entries:")
                for line in logs.strip().split('\n')[-5:]:  # Last 5 lines
                    print(f"   {line}")
            else:
                print("   No existing logs")
            
            # Stream logs for a short time (demo)
            print(f"\n5. Streaming logs for {device} (10 seconds):")
            print("   Waiting for TTY activity...")
            
            start_time = time.time()
            for entry in client.stream_parsed_logs(device):
                print(f"   [{entry.timestamp.strftime('%d.%m.%y %H:%M:%S')}] {entry.event_type}: {entry.process}")
                if entry.data:
                    print(f"      Data: {entry.data}")
                
                # Stop after 10 seconds for demo
                if time.time() - start_time > 10:
                    break
            
            print("   Stream demo completed")
            
            # Remove the port
            print(f"\n6. Removing port: {device}")
            success = client.remove_port(device)
            if success:
                print("   Port removed successfully")
            else:
                print("   Failed to remove port")
                
        except TTYMonitorError as e:
            if "already exists" in str(e):
                print(f"   Port {device} already exists - that's OK for demo")
            else:
                raise
    
    except TTYMonitorError as e:
        print(f"Error: {e}")
        return 1
    except KeyboardInterrupt:
        print("\nDemo interrupted by user")
        return 0
    
    print("\n=== Demo completed ===")
    return 0


if __name__ == "__main__":
    exit(main())
