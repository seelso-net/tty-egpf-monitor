# Simple build for CO-RE eBPF + userspace loader
# Modified for Ubuntu 22.04 with available kernel headers

BPF_CLANG ?= clang
CC ?= gcc
# Find working bpftool - prefer specific paths over the wrapper script
BPFTOOL ?= $(shell \
	for bpf in $(shell find /usr/lib/linux-tools-* -name bpftool 2>/dev/null | head -1) /usr/local/sbin/bpftool /usr/local/bin/bpftool bpftool; do \
		if $$bpf version >/dev/null 2>&1; then \
			echo $$bpf; \
			break; \
		fi; \
	done)

UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
  BPF_ARCH := x86
else ifeq ($(UNAME_M),aarch64)
  BPF_ARCH := arm64
else ifeq ($(UNAME_M),arm64)
  BPF_ARCH := arm64
else ifeq ($(UNAME_M),armv7l)
  BPF_ARCH := arm
else
  $(warning Unknown arch $(UNAME_M), defaulting __TARGET_ARCH_x86)
  BPF_ARCH := x86
endif

CFLAGS := -O2 -g
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(BPF_ARCH)

# Detect available kernel headers dynamically
# Try to find the best available kernel headers
KERNEL_VERSION := $(shell uname -r)
KERNEL_HEADERS := $(shell \
	if [ -d "/usr/src/linux-headers-$(KERNEL_VERSION)" ]; then \
		echo "/usr/src/linux-headers-$(KERNEL_VERSION)"; \
	elif [ -d "/usr/src/linux-headers-generic" ]; then \
		echo "/usr/src/linux-headers-generic"; \
	else \
		ls -d /usr/src/linux-headers-*-generic 2>/dev/null | sort -V | tail -1 || echo "/usr/include"; \
	fi)

# Use custom libbpf if available, otherwise fall back to system
CUSTOM_LIBBPF_INCLUDE := /usr/local/include
SYSTEM_LIBBPF_INCLUDE := /usr/include

# Check if custom libbpf headers exist
ifeq ($(wildcard $(CUSTOM_LIBBPF_INCLUDE)/bpf/libbpf.h),)
  LIBBPF_INCLUDE := $(SYSTEM_LIBBPF_INCLUDE)
else
  LIBBPF_INCLUDE := $(CUSTOM_LIBBPF_INCLUDE)
endif

INCLUDES := -Ibuild -Isrc -I$(LIBBPF_INCLUDE)
BPF_INCLUDES := -Ibuild -Isrc -I$(LIBBPF_INCLUDE)

all: build/tty-egpf-monitord build/tty-egpf-monitor

build:
	mkdir -p build

# Generate vmlinux.h (CO-RE) from kernel BTF once (script with fallback)
build/vmlinux.h: | build
	@echo "Generating vmlinux.h..."
	@/usr/bin/env bash tools/gen-vmlinux-h.sh $@

# Build BPF object
build/sniffer.bpf.o: src/sniffer.bpf.c build/vmlinux.h | build
	$(BPF_CLANG) $(BPF_CFLAGS) $(BPF_INCLUDES) -c $< -o $@

# Generate libbpf skeleton header
build/sniffer.skel.h: build/sniffer.bpf.o | build
	$(BPFTOOL) gen skeleton $< > $@

# Userspace daemon and CLI
# Decide how to link libbpf
# 1. If STATIC_BPF=1 is set, link libbpf **statically** (preferred for Debian packages
#    when shipping a custom libbpf that isn't available as a distro package).
# 2. Else, if we are inside a Debian package build (DEB_BUILD_ARCH is set), rely on
#    system libbpf shared library so that dpkg-shlibdeps can discover the dependency.
# 3. Otherwise (local dev build) use whatever is in /usr/local/lib and keep rpath
#    so the binary finds the custom libbpf shared object at runtime.

# Always statically link libbpf for package builds to ensure compatibility
# This embeds libbpf 1.6.2 into the binary, avoiding runtime dependency issues
ifdef DEB_BUILD_ARCH
  # For Debian builds, always use static linking with custom libbpf
  # This ensures the binary works on both Ubuntu 22.04 and 24.04
  LIBBPF_LIBS := -L/usr/local/lib64 -L/usr/local/lib -Wl,-Bstatic -lbpf -Wl,-Bdynamic -lelf -lz -lpthread
  LIBBPF_CFLAGS := -I$(LIBBPF_INCLUDE)
  LIBBPF_LDFLAGS := -L/usr/local/lib64 -L/usr/local/lib
else ifeq ($(STATIC_BPF),1)
  # Manual static build
  LIBBPF_LIBS := -L/usr/local/lib64 -L/usr/local/lib -Wl,-Bstatic -lbpf -Wl,-Bdynamic -lelf -lz -lpthread
else
  # Development build - use dynamic linking with rpath
  LIBBPF_LIBS := -L/usr/local/lib64 -L/usr/local/lib -lbpf -lelf -lz -lpthread -Wl,-rpath,/usr/local/lib64 -Wl,-rpath,/usr/local/lib -Wl,-rpath,/usr/lib/x86_64-linux-gnu
endif

build/tty-egpf-monitord: src/daemon.c build/sniffer.skel.h | build
	$(CC) $(CFLAGS) $(INCLUDES) src/daemon.c -o $@ $(LIBBPF_LIBS)

build/tty-egpf-monitor: src/cli.c | build
	$(CC) $(CFLAGS) $(INCLUDES) src/cli.c -o $@ -lpthread

clean:
	rm -rf build

install: all
	install -d $(DESTDIR)/usr/bin
	install -d $(DESTDIR)/usr/lib/systemd/system
	install -d $(DESTDIR)/var/log/tty-egpf-monitor
	install -m 755 build/tty-egpf-monitord $(DESTDIR)/usr/bin/
	install -m 755 build/tty-egpf-monitor $(DESTDIR)/usr/bin/
	install -m 644 packaging/tty-egpf-monitord.service $(DESTDIR)/usr/lib/systemd/system/
