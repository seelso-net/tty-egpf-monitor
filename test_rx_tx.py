#!/usr/bin/env python3
import time
import serial

# Open serial port
ser = serial.Serial('/dev/ttyUSB0', 9600, timeout=1)

print("Testing TX and RX capture...")

# Write some data (TX)
print("Writing 'hello' to device...")
ser.write(b'hello\n')
time.sleep(0.1)

# Read some data (RX)
print("Reading from device...")
try:
    data = ser.read(10)
    print(f"Read: {data}")
except Exception as e:
    print(f"Read error: {e}")

# Write more data
print("Writing 'world' to device...")
ser.write(b'world\n')
time.sleep(0.1)

# Read more data
print("Reading from device again...")
try:
    data = ser.read(10)
    print(f"Read: {data}")
except Exception as e:
    print(f"Read error: {e}")

ser.close()
print("Test completed.")
