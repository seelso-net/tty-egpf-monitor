#!/bin/bash
set -e

# Enable necessary tracepoints
enable_tracepoints() {
    if [ -d /sys/kernel/debug/tracing ]; then
        echo 1 > /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/enable 2>/dev/null || true
        echo 1 > /sys/kernel/debug/tracing/events/syscalls/sys_exit_openat/enable 2>/dev/null || true
        echo 1 > /sys/kernel/debug/tracing/events/syscalls/sys_enter_close/enable 2>/dev/null || true
        echo 1 > /sys/kernel/debug/tracing/events/syscalls/sys_exit_close/enable 2>/dev/null || true
        echo 1 > /sys/kernel/debug/tracing/events/syscalls/sys_enter_write/enable 2>/dev/null || true
        echo 1 > /sys/kernel/debug/tracing/events/syscalls/sys_enter_read/enable 2>/dev/null || true
        echo 1 > /sys/kernel/debug/tracing/events/syscalls/sys_enter_ioctl/enable 2>/dev/null || true
    fi
}

# Enable unprivileged BPF if needed
if [ "$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null)" = "2" ]; then
    echo 1 > /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || true
fi

# Enable tracepoints
enable_tracepoints

# Start the daemon
exec /usr/bin/tty-egpf-monitord "$@"
