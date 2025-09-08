// SPDX-License-Identifier: GPL-2.0
// Simplified eBPF program for Ubuntu 24.04 compatibility
// This version avoids bpf_probe_read_user_str which fails on kernel 6.14+

#include "vmlinux.h"

/* Minimal fixed-width types + __user, no libc/UAPI includes */
#ifndef __u8
typedef unsigned char      __u8;
typedef unsigned short     __u16;
typedef unsigned int       __u32;
typedef unsigned long long __u64;
typedef signed char        __s8;
typedef short              __s16;
typedef int                __s32;
typedef long long          __s64;
#endif
#ifndef __user
#define __user
#endif

/* Syscall numbers */
#define __NR_openat 257
#define __NR_openat2 437
#define __NR_close 3
#define __NR_read 0
#define __NR_write 1
#define __NR_ioctl 16

/* File open flags */
#define O_RDONLY 00000000
#define O_WRONLY 00000001
#define O_RDWR   00000002

/* Event types */
#define EV_OPEN 1
#define EV_CLOSE 2
#define EV_READ 3
#define EV_WRITE 4
#define EV_IOCTL 5

/* Maximum data to capture */
#define MAX_DATA 64

/* Event structure */
struct event {
    __u32 type;
    __u32 port_idx;
    __u32 tgid;
    __u8 comm[16];
    __u8 comm_len;
    __s64 ret;
    __u32 cmd;
    __u8 dir;  // 0=read, 1=write
    __u32 data_len;
    __u32 data_trunc;
    __u8 data[MAX_DATA];
};

/* File descriptor key */
struct fdkey {
    __u32 tgid;
    __s32 fd;
};

/* Close context */
struct close_ctx {
    __s32 fd;
};

/* Maps */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct fdkey);
    __type(value, __u32);
    __uint(max_entries, 1024);
} fd_portidx SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct close_ctx);
    __uint(max_entries, 1024);
} cl_ctx SEC(".maps");

/* Raw syscall enter - capture file descriptors for close */
SEC("tracepoint/raw_syscalls/sys_enter")
int tp_raw_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    long id = 0;
    bpf_probe_read_kernel(&id, sizeof(id), &ctx->id);
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    if (id == __NR_close) {
        __s32 fd;
        bpf_probe_read_kernel(&fd, sizeof(fd), &ctx->args[0]);
        /* Store fd for close exit handler */
        struct close_ctx cc = { .fd = fd };
        bpf_map_update_elem(&cl_ctx, &tgid, &cc, BPF_ANY);
        return 0;
    }

    return 0;
}

/* Raw syscall exit - handle open/close events */
SEC("tracepoint/raw_syscalls/sys_exit")
int tp_raw_sys_exit(struct trace_event_raw_sys_exit *ctx)
{
    long id = 0; __s64 ret = 0;
    bpf_probe_read_kernel(&id, sizeof(id), &ctx->id);
    bpf_probe_read_kernel(&ret, sizeof(ret), &ctx->ret);
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    if (id == __NR_openat || id == __NR_openat2) {
        if (ret >= 0) {  // openat/openat2 was successful
            __s32 fd = (__s32)ret;
            struct fdkey k = { .tgid = tgid, .fd = fd };
            
            // Check if this fd is already mapped to a port
            __u32 *idxp = bpf_map_lookup_elem(&fd_portidx, &k);
            if (idxp) {
                // Already mapped, emit OPEN event
                struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
                if (e) {
                    e->type = EV_OPEN; e->port_idx = *idxp; e->tgid = tgid;
                    e->comm_len = bpf_get_current_comm(e->comm, sizeof(e->comm));
                    bpf_ringbuf_submit(e, 0);
                }
            }
        }
        return 0;
    }

    if (id == __NR_close) {
        struct close_ctx *cc = bpf_map_lookup_elem(&cl_ctx, &tgid);
        if (!cc) return 0;
        __s32 fd = cc->fd;
        if (ret == 0) {  // close was successful
            struct fdkey k = { .tgid = tgid, .fd = fd };
            __u32 *idxp = bpf_map_lookup_elem(&fd_portidx, &k);
            if (idxp) {
                // Emit CLOSE event
                struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
                if (e) {
                    e->type = EV_CLOSE; e->port_idx = *idxp; e->tgid = tgid;
                    e->comm_len = bpf_get_current_comm(e->comm, sizeof(e->comm));
                    bpf_ringbuf_submit(e, 0);
                }
                // Clean up mappings
                bpf_map_delete_elem(&fd_portidx, &k);
            }
            bpf_map_delete_elem(&cl_ctx, &tgid);
        }
        return 0;
    }

    return 0;
}

/* Write syscall - capture data */
SEC("tracepoint/syscalls/sys_enter_write")
int tp_enter_write(struct trace_event_raw_sys_enter *ctx)
{
    __s32 fd;
    const void __user *buf;
    size_t count;
    bpf_probe_read_kernel(&fd, sizeof(fd), &ctx->args[0]);
    bpf_probe_read_kernel(&buf, sizeof(buf), &ctx->args[1]);
    bpf_probe_read_kernel(&count, sizeof(count), &ctx->args[2]);
    
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct fdkey k = { .tgid = tgid, .fd = fd };
    __u32 *idxp = bpf_map_lookup_elem(&fd_portidx, &k);
    if (!idxp) return 0;

    size_t cap = count > MAX_DATA ? MAX_DATA : count;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->type = EV_WRITE; e->port_idx = *idxp; e->tgid = tgid;
    e->comm_len = bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->dir = 1; e->ret = 0; e->cmd = 0;
    e->data_len = cap; e->data_trunc = count > MAX_DATA ? (count - MAX_DATA) : 0;
    
    // Copy data from userspace buffer
    if (cap && buf) {
        bpf_probe_read_user(e->data, cap, buf);
    }
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Read syscall - capture data */
SEC("tracepoint/syscalls/sys_enter_read")
int tp_enter_read(struct trace_event_raw_sys_enter *ctx)
{
    __s32 fd;
    const void __user *buf;
    size_t count;
    bpf_probe_read_kernel(&fd, sizeof(fd), &ctx->args[0]);
    bpf_probe_read_kernel(&buf, sizeof(buf), &ctx->args[1]);
    bpf_probe_read_kernel(&count, sizeof(count), &ctx->args[2]);
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    struct fdkey k = { .tgid = tgid, .fd = fd };
    __u32 *idxp = bpf_map_lookup_elem(&fd_portidx, &k);
    if (!idxp) return 0;

    size_t cap = count > MAX_DATA ? MAX_DATA : count;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->type = EV_READ; e->port_idx = *idxp; e->tgid = tgid;
    e->comm_len = bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->dir = 0; e->ret = 0; e->cmd = 0;
    e->data_len = cap; e->data_trunc = count > MAX_DATA ? (count - MAX_DATA) : 0;
    
    // Copy data from userspace buffer
    if (cap && buf) {
        bpf_probe_read_user(e->data, cap, buf);
    }
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* IOCTL syscall */
SEC("tracepoint/syscalls/sys_enter_ioctl")
int tp_enter_ioctl(struct trace_event_raw_sys_enter *ctx)
{
    __s32 fd;
    __u32 cmd;
    bpf_probe_read_kernel(&fd, sizeof(fd), &ctx->args[0]);
    bpf_probe_read_kernel(&cmd, sizeof(cmd), &ctx->args[1]);
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    struct fdkey k = { .tgid = tgid, .fd = fd };
    __u32 *idxp = bpf_map_lookup_elem(&fd_portidx, &k);
    if (!idxp) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->type = EV_IOCTL; e->port_idx = *idxp; e->tgid = tgid;
    e->comm_len = bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->dir = 0; e->ret = 0; e->cmd = cmd;
    e->data_len = 0; e->data_trunc = 0;
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}
