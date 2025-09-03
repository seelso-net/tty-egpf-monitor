#!/usr/bin/env python3
"""
Test script for TTY monitoring - opens port, sends data, closes port
"""

import serial
import time
import sys

def test_tty_write(port_path, baudrate=115200, test_data="Hello from Python!"):
    """Open TTY port, send test data, and close it"""
    try:
        print(f"Opening {port_path} at {baudrate} baud...")
        
        # Open the serial port
        ser = serial.Serial(
            port=port_path,
            baudrate=baudrate,
            timeout=1,
            write_timeout=1
        )
        
        print(f"Port opened successfully: {ser.name}")
        print(f"Sending data: '{test_data}'")
        
        # Send the test data
        bytes_written = ser.write(test_data.encode('utf-8'))
        print(f"Wrote {bytes_written} bytes")
        
        # Flush to ensure data is sent
        ser.flush()
        
        # Small delay to ensure data is processed
        time.sleep(0.1)
        
        print("Closing port...")
        ser.close()
        print("Port closed successfully")
        
        return True
        
    except serial.SerialException as e:
        print(f"Serial error: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 test_tty.py <port_path> [baudrate] [test_data]")
        print("Example: python3 test_tty.py /dev/ttyUSB0 115200 'Test message'")
        sys.exit(1)
    
    port_path = sys.argv[1]
    baudrate = int(sys.argv[2]) if len(sys.argv) > 2 else 115200
    test_data = sys.argv[3] if len(sys.argv) > 3 else "Hello from Python script!"
    
    print(f"Testing TTY write to {port_path}")
    print(f"Baudrate: {baudrate}")
    print(f"Test data: '{test_data}'")
    print("-" * 50)
    
    success = test_tty_write(port_path, baudrate, test_data)
    
    if success:
        print("Test completed successfully!")
    else:
        print("Test failed!")
        sys.exit(1)
