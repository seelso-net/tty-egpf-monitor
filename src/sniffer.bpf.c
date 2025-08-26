// SPDX-License-Identifier: GPL-2.0
// eBPF CO-RE serial sniffer (syscall-tracepoint backend) with per-CPU scratch buffers.

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

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_DATA 256
#define MAX_PATH 256

enum evtype { EV_OPEN=1, EV_CLOSE=2, EV_READ=3, EV_WRITE=4, EV_IOCTL=5 };

struct event {
    __u64 ts, dev;     /* dev unused here; kept for ABI compatibility (set 0) */
    __u32 pid, tgid;
    char  comm[16];
    __u32 type;        /* evtype */
    __s32 ret;         /* read/ioctl/close return */
    __u32 cmd;         /* ioctl cmd */
    __u32 dir;         /* 1=write, 0=read */
    __u32 data_len, data_trunc;
    __u8  data[MAX_DATA];
};

/* Ringbuf for user-space */
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1<<24); } events SEC(".maps");

/* FDs of interest: key = (tgid, fd) */
struct fdkey { __u32 tgid; __s32 fd; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __type(key, struct fdkey); __type(value, __u8); __uint(max_entries, 65536); } fd_interest SEC(".maps");

/* read() entry ctx: capture userspace buffer pointer by (tgid, fd) */
struct read_ctx { const void *buf; size_t count; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __type(key, struct fdkey); __type(value, struct read_ctx); __uint(max_entries, 65536); } rd_ctx SEC(".maps");

/* openat() entry ctx: save filename pointer by tgid */
struct open_ctx { const char *filename; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __type(key, __u32); __type(value, struct open_ctx); __uint(max_entries, 32768); } op_ctx SEC(".maps");

/* close() entry ctx: save fd by tgid to check result on exit */
struct close_ctx { __s32 fd; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __type(key, __u32); __type(value, struct close_ctx); __uint(max_entries, 32768); } cl_ctx SEC(".maps");

/* Target device path, set by userspace (index 0) */
struct pathval { char path[MAX_PATH]; };
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, struct pathval); __uint(max_entries, 1); } target_path SEC(".maps");

/* Per-CPU scratch buffers (avoid stack usage) */
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __type(key, __u32); __type(value, struct pathval); __uint(max_entries, 1); } scratch1 SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __type(key, __u32); __type(value, struct pathval); __uint(max_entries, 1); } scratch2 SEC(".maps");

/* Optional: orchestrator tgid (for parity with earlier version) */
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, __u32); __uint(max_entries, 1); } orchestrator_tgid SEC(".maps");

static __always_inline void fill_common(struct event *e, __u32 type) {
    __u64 id = bpf_get_current_pid_tgid();
    e->ts = bpf_ktime_get_ns();
    e->type = type;
    e->pid = (__u32)id;
    e->tgid = id >> 32;
    e->dev = 0;
    bpf_get_current_comm(&e->comm, sizeof e->comm);
}

/* bounded byte-wise compare */
static __always_inline int str_eq_n(const char *a, const char *b, int n)
{
#pragma unroll
    for (int i = 0; i < MAX_PATH; i++) {
        if (i >= n) break;
        char ca = 0, cb = 0;
        bpf_core_read(&ca, sizeof(ca), a + i);
        bpf_core_read(&cb, sizeof(cb), b + i);
        if (ca != cb) return 0;
        if (!ca) return 1;
    }
    return 1;
}

/* ---------- sys_enter_openat ---------- */
SEC("tracepoint/syscalls/sys_enter_openat")
int tp_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    const char *filename = (const char *)(__u64)ctx->args[1];
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct open_ctx oc = { .filename = filename };
    bpf_map_update_elem(&op_ctx, &tgid, &oc, BPF_ANY);
    return 0;
}

/* ---------- sys_exit_openat ---------- */
SEC("tracepoint/syscalls/sys_exit_openat")
int tp_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
    __s64 ret = ctx->ret; /* new fd if >=0 */
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    struct open_ctx *oc = bpf_map_lookup_elem(&op_ctx, &tgid);
    if (!oc) return 0;

    __u32 k0 = 0;

    /* scratch1 := wanted path (from kernel map memory) */
    struct pathval *sw = bpf_map_lookup_elem(&scratch1, &k0);
    if (!sw) { bpf_map_delete_elem(&op_ctx, &tgid); return 0; }
    struct pathval *tp = bpf_map_lookup_elem(&target_path, &k0);
    if (!tp) { bpf_map_delete_elem(&op_ctx, &tgid); return 0; }
    /* copy kernel memory (ok) */
    bpf_probe_read_kernel(sw->path, sizeof(sw->path), tp->path);

    /* scratch2 := user path (from userspace pointer) */
    struct pathval *sg = bpf_map_lookup_elem(&scratch2, &k0);
    if (!sg) { bpf_map_delete_elem(&op_ctx, &tgid); return 0; }
    int glen = bpf_probe_read_user_str(sg->path, sizeof(sg->path), oc->filename);
    bpf_map_delete_elem(&op_ctx, &tgid);
    if (glen <= 0) return 0;

    if (ret >= 0 && str_eq_n(sw->path, sg->path, MAX_PATH)) {
        struct fdkey k = { .tgid = tgid, .fd = (__s32)ret };
        __u8 one = 1;
        bpf_map_update_elem(&fd_interest, &k, &one, BPF_ANY);

        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e) return 0;
        fill_common(e, EV_OPEN);
        e->cmd = 0; e->ret = ret; e->dir = 0; e->data_len = 0; e->data_trunc = 0;
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

/* ---------- sys_enter_close ---------- */
SEC("tracepoint/syscalls/sys_enter_close")
int tp_enter_close(struct trace_event_raw_sys_enter *ctx)
{
    __s32 fd = (__s32)ctx->args[0];
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    struct fdkey k = { .tgid = tgid, .fd = fd };
    __u8 *hit = bpf_map_lookup_elem(&fd_interest, &k);
    if (!hit) return 0;

    struct close_ctx cc = { .fd = fd };
    bpf_map_update_elem(&cl_ctx, &tgid, &cc, BPF_ANY);
    return 0;
}

/* ---------- sys_exit_close ---------- */
SEC("tracepoint/syscalls/sys_exit_close")
int tp_exit_close(struct trace_event_raw_sys_exit *ctx)
{
    __s64 ret = ctx->ret;
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    struct close_ctx *cc = bpf_map_lookup_elem(&cl_ctx, &tgid);
    if (!cc) return 0;

    struct fdkey k = { .tgid = tgid, .fd = cc->fd };
    bpf_map_delete_elem(&cl_ctx, &tgid);

    if (ret == 0) {
        bpf_map_delete_elem(&rd_ctx, &k);      /* drop any pending read ctx */
        bpf_map_delete_elem(&fd_interest, &k); /* unmark fd */

        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            fill_common(e, EV_CLOSE);
            e->cmd = 0; e->ret = 0; e->dir = 0; e->data_len = 0; e->data_trunc = 0;
            bpf_ringbuf_submit(e, 0);
        }
    }
    return 0;
}

/* ---------- sys_enter_write: app -> device ---------- */
SEC("tracepoint/syscalls/sys_enter_write")
int tp_enter_write(struct trace_event_raw_sys_enter *ctx)
{
    __s32 fd = (__s32)ctx->args[0];
    const void __user *buf = (const void *)(__u64)ctx->args[1];
    size_t count = (size_t)ctx->args[2];
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    struct fdkey k = { .tgid = tgid, .fd = fd };
    __u8 *hit = bpf_map_lookup_elem(&fd_interest, &k);
    if (!hit) return 0;

    size_t cap = count > MAX_DATA ? MAX_DATA : count;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(e, EV_WRITE);
    e->dir = 1; e->ret = 0; e->cmd = 0;
    e->data_len = cap; e->data_trunc = count > MAX_DATA ? (count - MAX_DATA) : 0;
    if (cap && buf) bpf_probe_read_user(e->data, cap, buf);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------- sys_enter_read: device -> app (capture on enter only, optional) ---------- */
SEC("tracepoint/syscalls/sys_enter_read")
int tp_enter_read(struct trace_event_raw_sys_enter *ctx)
{
    __s32 fd = (__s32)ctx->args[0];
    const void __user *buf = (const void *)(__u64)ctx->args[1];
    size_t count = (size_t)ctx->args[2];
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    struct fdkey k = { .tgid = tgid, .fd = fd };
    __u8 *hit = bpf_map_lookup_elem(&fd_interest, &k);
    if (!hit) return 0;

    struct read_ctx rc = { .buf = buf, .count = count };
    bpf_map_update_elem(&rd_ctx, &k, &rc, BPF_ANY);
    return 0;
}

/* (Optional) sys_exit_read could copy dev->app bytes using the recorded buf+ret
   If you want that too, I’ll extend this with a small per-task slot for the fd. */

/* ---------- sys_enter_ioctl ---------- */
SEC("tracepoint/syscalls/sys_enter_ioctl")
int tp_enter_ioctl(struct trace_event_raw_sys_enter *ctx)
{
    __s32 fd = (__s32)ctx->args[0];
    __u32 cmd = (__u32)ctx->args[1];
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    struct fdkey k = { .tgid = tgid, .fd = fd };
    __u8 *hit = bpf_map_lookup_elem(&fd_interest, &k);
    if (!hit) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(e, EV_IOCTL);
    e->cmd = cmd; e->ret = 0; e->dir = 0;
    e->data_len = 0; e->data_trunc = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

