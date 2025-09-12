#!/bin/bash

# Comprehensive debugging script for picocom detection issues
# This will help us identify exactly why picocom events aren't being detected

set -e

echo "=== TTY-EGPF-MONITOR DEBUGGING SCRIPT ==="
echo "This script will help diagnose why picocom events aren't being detected"
echo ""

# Check daemon status
echo "1. Checking daemon status..."
if systemctl is-active --quiet tty-egpf-monitord; then
    echo "✅ Daemon is running"
    echo "   Version: $(journalctl -u tty-egpf-monitord --since '1 minute ago' | grep 'Version:' | tail -1)"
else
    echo "❌ Daemon is not running"
    echo "   Starting daemon..."
    sudo systemctl start tty-egpf-monitord
    sleep 2
fi

# Check if port is added
echo ""
echo "2. Checking if port is added..."
if tty-egpf-monitor list 2>/dev/null | grep -q "ttyUSB0"; then
    echo "✅ Port /dev/ttyUSB0 is added"
else
    echo "❌ Port not added, adding it now..."
    sudo tty-egpf-monitor add /dev/ttyUSB0 115200
    sleep 1
fi

# Check eBPF programs
echo ""
echo "3. Checking eBPF programs..."
echo "   Attached eBPF programs:"
sudo bpftool prog list | grep -E "(openat|close|ioctl)" || echo "   No openat/close/ioctl programs found"

echo ""
echo "   Tracepoints:"
sudo bpftool prog list | grep -E "tracepoint" || echo "   No tracepoint programs found"

# Check if picocom is available
echo ""
echo "4. Checking picocom availability..."
if command -v picocom >/dev/null 2>&1; then
    echo "✅ picocom is available: $(which picocom)"
else
    echo "❌ picocom not found, installing..."
    sudo apt-get install -y picocom
fi

# Monitor daemon logs in real-time
echo ""
echo "5. Starting real-time log monitoring..."
echo "   (This will run for 30 seconds - open another terminal to run picocom)"
echo "   Run this command in another terminal:"
echo "   sudo timeout 10s picocom /dev/ttyUSB0 -b 115200 -q"
echo ""

# Start monitoring logs
timeout 30s journalctl -u tty-egpf-monitord -f --since 'now' | while read line; do
    echo "DAEMON: $line"
    if echo "$line" | grep -q "picocom\|OPEN\|state.*PASSIVE\|foreign open"; then
        echo "🎯 FOUND PICOCOM EVENT: $line"
    fi
done &

MONITOR_PID=$!

# Wait for user to run picocom
echo ""
echo "   Now run picocom in another terminal:"
echo "   sudo timeout 10s picocom /dev/ttyUSB0 -b 115200 -q"
echo ""
echo "   Press Enter when you've run picocom, or wait 30 seconds..."
read -t 30

# Stop monitoring
kill $MONITOR_PID 2>/dev/null || true

# Check what syscalls picocom actually makes
echo ""
echo "6. Analyzing what syscalls picocom makes..."
echo "   Running strace on picocom to see what it actually does:"

# Create a test script that runs picocom with strace
cat > /tmp/test_picocom.sh << 'EOF'
#!/bin/bash
echo "Starting picocom with strace..."
sudo strace -e openat,openat2,close,ioctl,read,write -o /tmp/picocom_strace.log timeout 5s picocom /dev/ttyUSB0 -b 115200 -q 2>/dev/null
echo "Strace log saved to /tmp/picocom_strace.log"
echo ""
echo "Key syscalls made by picocom:"
grep -E "(openat|openat2|close|ioctl)" /tmp/picocom_strace.log | head -10
EOF

chmod +x /tmp/test_picocom.sh
/tmp/test_picocom.sh

# Check if our eBPF programs are actually being triggered
echo ""
echo "7. Checking if eBPF programs are being triggered..."
echo "   Looking for any eBPF program activity:"

# Check trace_pipe for eBPF debug output
echo "   Checking kernel trace (this may show eBPF debug output):"
timeout 5s sudo cat /sys/kernel/debug/tracing/trace_pipe 2>/dev/null | grep -E "(openat|picocom|tty-egpf)" | head -5 || echo "   No eBPF debug output found"

# Check if the issue is with our filtering
echo ""
echo "8. Checking daemon filtering logic..."
echo "   Recent daemon events (last 2 minutes):"
journalctl -u tty-egpf-monitord --since '2 minutes ago' | grep -E "(Event|DEBUG|state)" | tail -10

# Check if picocom process is being detected at all
echo ""
echo "9. Checking if picocom process is detected..."
echo "   Looking for any picocom-related events:"
journalctl -u tty-egpf-monitord --since '5 minutes ago' | grep -i picocom || echo "   No picocom events found in logs"

# Summary and recommendations
echo ""
echo "=== DEBUGGING SUMMARY ==="
echo ""
echo "If you're still not seeing picocom events, the issue might be:"
echo "1. eBPF programs not attaching to the right tracepoints"
echo "2. Picocom using different syscalls than expected"
echo "3. Kernel version specific compatibility issues"
echo "4. Events being filtered out by our logic"
echo ""
echo "Next steps:"
echo "1. Check the strace output above to see what syscalls picocom actually makes"
echo "2. Verify eBPF programs are attached to the right tracepoints"
echo "3. Check if there are any kernel trace messages"
echo ""
echo "If the issue persists, we may need to:"
echo "- Add more debug output to the eBPF programs"
echo "- Check if picocom uses different syscalls on your system"
echo "- Verify the tracepoint names are correct for your kernel version"
