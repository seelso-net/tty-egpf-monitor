#!/usr/bin/env python3
"""
Automation example using TTY eBPF Monitor.

This example shows how to use the Python client for automated testing and monitoring.
"""

import time
import sys
from tty_egpf_monitor import TTYMonitorClient, TTYMonitorError


def wait_for_device_activity(client: TTYMonitorClient, device: str, timeout: int = 30):
    """Wait for any activity on a device."""
    print(f"Waiting for activity on {device} (timeout: {timeout}s)...")
    
    start_time = time.time()
    for entry in client.stream_parsed_logs(device):
        if entry.event_type in ["WRITE", "READ"]:
            print(f"✅ Activity detected: {entry.event_type} by {entry.process}")
            return True
        
        if time.time() - start_time > timeout:
            print("❌ Timeout waiting for activity")
            return False
    
    return False


def capture_session_data(client: TTYMonitorClient, device: str, duration: int = 60):
    """Capture all data from a session."""
    print(f"Capturing data from {device} for {duration} seconds...")
    
    session_data = {
        "writes": [],
        "reads": [],
        "total_bytes_written": 0,
        "total_bytes_read": 0,
        "processes": set()
    }
    
    start_time = time.time()
    
    try:
        for entry in client.stream_parsed_logs(device):
            elapsed = time.time() - start_time
            
            if entry.event_type == "WRITE" and entry.data:
                session_data["writes"].append({
                    "timestamp": entry.timestamp,
                    "process": entry.process,
                    "data": entry.data,
                    "size": len(entry.data)
                })
                session_data["total_bytes_written"] += len(entry.data)
                session_data["processes"].add(entry.process)
                
            elif entry.event_type == "READ" and entry.data:
                session_data["reads"].append({
                    "timestamp": entry.timestamp, 
                    "process": entry.process,
                    "data": entry.data,
                    "size": len(entry.data)
                })
                session_data["total_bytes_read"] += len(entry.data)
                session_data["processes"].add(entry.process)
            
            if elapsed > duration:
                break
    
    except KeyboardInterrupt:
        print("\nCapture interrupted by user")
    
    return session_data


def analyze_protocol(data_writes):
    """Simple protocol analysis example."""
    print("\n📊 Protocol Analysis:")
    
    if not data_writes:
        print("   No data to analyze")
        return
    
    # Combine all written data
    all_data = b"".join(write["data"] for write in data_writes)
    
    print(f"   Total data: {len(all_data)} bytes")
    print(f"   Data preview: {all_data[:100]}...")
    
    # Look for common patterns
    patterns = {
        b"AT": "AT commands detected",
        b"\r\n": "CRLF line endings detected", 
        b"\n": "LF line endings detected",
        b"\x00": "Null bytes detected (binary data?)",
    }
    
    for pattern, description in patterns.items():
        if pattern in all_data:
            count = all_data.count(pattern)
            print(f"   🔍 {description} ({count} occurrences)")


def main():
    """Main automation example."""
    if len(sys.argv) < 2:
        print("Usage: python automation_script.py <device> [duration]")
        print("Example: python automation_script.py /dev/ttyUSB0 30")
        return 1
    
    device = sys.argv[1]
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    
    client = TTYMonitorClient()
    
    try:
        print(f"🚀 Starting automated monitoring of {device}")
        
        # Add the device
        try:
            idx = client.add_port(device)
            print(f"✅ Added {device} as port {idx}")
        except TTYMonitorError as e:
            if "already exists" in str(e):
                print(f"ℹ️  {device} already being monitored")
            else:
                raise
        
        # Wait for initial activity
        if wait_for_device_activity(client, device, timeout=10):
            # Capture session data
            session_data = capture_session_data(client, device, duration)
            
            # Print summary
            print(f"\n📈 Session Summary:")
            print(f"   Duration: {duration} seconds")
            print(f"   Processes involved: {', '.join(session_data['processes'])}")
            print(f"   Total writes: {len(session_data['writes'])} ({session_data['total_bytes_written']} bytes)")
            print(f"   Total reads: {len(session_data['reads'])} ({session_data['total_bytes_read']} bytes)")
            
            # Analyze the data
            if session_data["writes"]:
                analyze_protocol(session_data["writes"])
        
        else:
            print("⚠️  No activity detected on device")
    
    except TTYMonitorError as e:
        print(f"❌ Error: {e}")
        return 1
    except KeyboardInterrupt:
        print("\n🛑 Automation interrupted")
        return 0
    finally:
        # Cleanup
        try:
            client.remove_port(device)
            print(f"🧹 Cleaned up monitoring for {device}")
        except TTYMonitorError:
            pass
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
