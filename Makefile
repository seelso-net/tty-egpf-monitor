# Simple build for CO-RE eBPF + userspace loader
# Requires: clang, make, bpftool, libbpf-dev, libelf-dev, zlib1g-dev, pkg-config

BPF_CLANG ?= clang
CC ?= cc
BPFTOOL ?= bpftool

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

INCLUDES := -Ibuild -Isrc

all: build/tty-egpf-monitord build/tty-egpf-monitor

build:
	mkdir -p build

# Generate vmlinux.h (CO-RE) from kernel BTF once (script with fallback)
build/vmlinux.h: | build
	@echo "Generating vmlinux.h..."
	@/usr/bin/env bash tools/gen-vmlinux-h.sh $@

# Build BPF object
build/sniffer.bpf.o: src/sniffer.bpf.c build/vmlinux.h | build
	$(BPF_CLANG) $(BPF_CFLAGS) -Ibuild -Isrc -c $< -o $@

# Generate libbpf skeleton header
build/sniffer.skel.h: build/sniffer.bpf.o | build
	$(BPFTOOL) gen skeleton $< > $@

# Userspace daemon and CLI
build/tty-egpf-monitord: src/daemon.c build/sniffer.skel.h | build
	$(CC) $(CFLAGS) $(INCLUDES) src/daemon.c -o $@ $(shell pkg-config --libs --cflags libbpf) -lelf -lz -lpthread

build/tty-egpf-monitor: src/cli.c | build
	$(CC) $(CFLAGS) $(INCLUDES) src/cli.c -o $@ -lpthread

clean:
	rm -rf build
