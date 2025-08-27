#!/usr/bin/env bash
set -euo pipefail

out="$1"
mkdir -p "$(dirname "$out")"

if [ "${FORCE_VMLINUX_FALLBACK:-}" != "1" ] && command -v bpftool >/dev/null 2>&1 && [ -r /sys/kernel/btf/vmlinux ]; then
    if bpftool btf dump file /sys/kernel/btf/vmlinux format c >"$out" 2>/dev/null; then
        echo "Generated vmlinux.h from kernel BTF"
        exit 0
    fi
fi

echo "BTF not available, using bundled fallback header"
script_dir="$(cd "$(dirname "$0")" && pwd)"
cp "$script_dir/vmlinux-fallback.h" "$out"
echo "Wrote fallback vmlinux.h"

