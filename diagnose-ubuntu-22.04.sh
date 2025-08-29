#!/bin/bash
# Diagnostic script for Ubuntu 22.04 issues

echo "=== Ubuntu 22.04 Diagnostic Script ==="
echo

# Check OS version
echo "1. OS Version:"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "   OS: $NAME $VERSION_ID ($VERSION_CODENAME)"
else
    echo "   Unable to detect OS version"
fi
echo

# Check kernel version
echo "2. Kernel Version:"
uname -r
echo

# Check if binary exists and is executable
echo "3. Binary Check:"
if [ -f /usr/bin/tty-egpf-monitord ]; then
    echo "   ✓ Binary exists"
    ls -la /usr/bin/tty-egpf-monitord
    
    # Check if it's executable
    if [ -x /usr/bin/tty-egpf-monitord ]; then
        echo "   ✓ Binary is executable"
    else
        echo "   ✗ Binary is NOT executable"
    fi
else
    echo "   ✗ Binary NOT found at /usr/bin/tty-egpf-monitord"
fi
echo

# Check library dependencies
echo "4. Library Dependencies:"
if [ -f /usr/bin/tty-egpf-monitord ]; then
    if ldd /usr/bin/tty-egpf-monitord >/dev/null 2>&1; then
        echo "   ✓ All libraries resolved"
        ldd /usr/bin/tty-egpf-monitord | grep "not found" || echo "   No missing libraries"
    else
        echo "   ✗ Missing libraries:"
        ldd /usr/bin/tty-egpf-monitord 2>&1
    fi
else
    echo "   Cannot check - binary not found"
fi
echo

# Check libbpf version
echo "5. libbpf Version:"
dpkg -l | grep libbpf | grep "^ii" || echo "   No libbpf packages installed"
echo

# Check capabilities on binary
echo "6. Binary Capabilities:"
if [ -f /usr/bin/tty-egpf-monitord ]; then
    getcap /usr/bin/tty-egpf-monitord || echo "   No capabilities set"
else
    echo "   Cannot check - binary not found"
fi
echo

# Check systemd service file
echo "7. Systemd Service File:"
if [ -f /lib/systemd/system/tty-egpf-monitord.service ]; then
    echo "   Service file exists"
    echo "   Capabilities configuration:"
    grep -E "^(Ambient|Capability)" /lib/systemd/system/tty-egpf-monitord.service
else
    echo "   ✗ Service file NOT found"
fi
echo

# Try to run the binary directly
echo "8. Direct Binary Test:"
if [ -f /usr/bin/tty-egpf-monitord ]; then
    echo "   Testing binary with --help:"
    timeout 2 /usr/bin/tty-egpf-monitord --help 2>&1 || echo "   Exit code: $?"
else
    echo "   Cannot test - binary not found"
fi
echo

# Check systemd service status
echo "9. Service Status:"
systemctl status tty-egpf-monitord --no-pager | head -20
echo

# Check recent service logs
echo "10. Recent Service Logs:"
journalctl -u tty-egpf-monitord -n 20 --no-pager | grep -E "(error|fail|127|not found)"
echo

# Check kernel capabilities support
echo "11. Kernel Capabilities Support:"
if [ -f /proc/sys/kernel/cap_last_cap ]; then
    LAST_CAP=$(cat /proc/sys/kernel/cap_last_cap)
    echo "   Last capability: $LAST_CAP"
    if [ $LAST_CAP -ge 39 ]; then
        echo "   ✓ CAP_BPF (39) should be supported"
    else
        echo "   ✗ CAP_BPF (39) NOT supported (kernel too old)"
    fi
else
    echo "   Cannot determine capability support"
fi

echo
echo "=== End of Diagnostic ==="
