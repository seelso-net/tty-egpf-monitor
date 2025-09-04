#!/usr/bin/env python3
"""
TTY eBPF Monitor CLI

Command-line interface for the tty-egpf-monitor daemon using the Python client library.
"""

import argparse
import sys
import json
from typing import Optional
from .client import TTYMonitorClient, TTYMonitorError


def cmd_add(client: TTYMonitorClient, args: argparse.Namespace) -> int:
    """Add a port to monitor."""
    try:
        idx = client.add_port(args.device, args.baudrate, args.logfile)
        print(json.dumps({"idx": idx}))
        return 0
    except TTYMonitorError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_list(client: TTYMonitorClient, args: argparse.Namespace) -> int:
    """List configured ports."""
    try:
        ports = client.list_ports()
        ports_data = [{"idx": p.idx, "dev": p.device} for p in ports]
        print(json.dumps(ports_data))
        return 0
    except TTYMonitorError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_logs(client: TTYMonitorClient, args: argparse.Namespace) -> int:
    """Download full log for a port."""
    try:
        # Parse port identifier (int or string)
        port_id = args.port
        try:
            port_id = int(port_id)
        except ValueError:
            pass  # Keep as string (device path)
        
        logs = client.get_logs(port_id)
        print(logs, end='')  # Don't add extra newline, logs already have them
        return 0
    except TTYMonitorError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_stream(client: TTYMonitorClient, args: argparse.Namespace) -> int:
    """Live stream logs for a port."""
    try:
        # Parse port identifier (int or string)
        port_id = args.port
        try:
            port_id = int(port_id)
        except ValueError:
            pass  # Keep as string (device path)
        
        for line in client.stream_logs(port_id):
            print(line)
            sys.stdout.flush()
        
        return 0
    except KeyboardInterrupt:
        return 0
    except TTYMonitorError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_remove(client: TTYMonitorClient, args: argparse.Namespace) -> int:
    """Remove a port from monitoring."""
    try:
        # Parse port identifier (int or string)
        port_id = args.port
        try:
            port_id = int(port_id)
        except ValueError:
            pass  # Keep as string (device path)
        
        success = client.remove_port(port_id)
        if success:
            print(json.dumps({"ok": True}))
            return 0
        else:
            print("Error: Remove failed", file=sys.stderr)
            return 1
    except TTYMonitorError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="TTY eBPF Monitor Python CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  tty-egpf-monitor-py add /dev/ttyUSB0 115200
  tty-egpf-monitor-py list
  tty-egpf-monitor-py stream /dev/ttyUSB0
  tty-egpf-monitor-py logs 0
  tty-egpf-monitor-py remove /dev/ttyUSB0

For more information, see: https://github.com/seelso-net/tty-egpf-monitor
"""
    )
    
    parser.add_argument(
        "--socket",
        default="/run/tty-egpf-monitord.sock",
        help="Path to daemon socket (default: %(default)s)"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Add command
    add_parser = subparsers.add_parser("add", help="Add a monitored port")
    add_parser.add_argument("device", help="Device path (e.g., /dev/ttyUSB0)")
    add_parser.add_argument("baudrate", nargs="?", type=int, default=115200, help="Baud rate (default: 115200)")
    add_parser.add_argument("logfile", nargs="?", help="Custom log file path (optional)")
    
    # List command
    subparsers.add_parser("list", help="List configured ports")
    
    # Logs command
    logs_parser = subparsers.add_parser("logs", help="Download full log for a port")
    logs_parser.add_argument("port", help="Port index or device path")
    
    # Stream command
    stream_parser = subparsers.add_parser("stream", help="Live stream logs for a port")
    stream_parser.add_argument("port", help="Port index or device path")
    
    # Remove command
    remove_parser = subparsers.add_parser("remove", help="Remove a port from monitoring")
    remove_parser.add_argument("port", help="Port index or device path")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 2
    
    # Create client
    client = TTYMonitorClient(args.socket)
    
    # Execute command
    if args.command == "add":
        return cmd_add(client, args)
    elif args.command == "list":
        return cmd_list(client, args)
    elif args.command == "logs":
        return cmd_logs(client, args)
    elif args.command == "stream":
        return cmd_stream(client, args)
    elif args.command == "remove":
        return cmd_remove(client, args)
    else:
        parser.print_help()
        return 2


if __name__ == "__main__":
    sys.exit(main())
