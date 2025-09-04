"""
TTY eBPF Monitor Python Client Library

A Python client library for interacting with the tty-egpf-monitord daemon.
Provides a clean, Pythonic interface to the HTTP+JSON API over Unix domain sockets.
"""

from .client import TTYMonitorClient, TTYMonitorError
from .models import Port, LogEntry

__version__ = "0.5.22"
__author__ = "TTY eBPF Monitor Team"
__license__ = "GPL-3.0"

__all__ = [
    "TTYMonitorClient",
    "TTYMonitorError", 
    "Port",
    "LogEntry",
]
