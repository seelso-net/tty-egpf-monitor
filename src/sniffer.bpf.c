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
/* Avoid kernel asm includes in BPF C; hard-define x86_64 syscall numbers */
#ifndef __NR_read
#define __NR_read   0
#endif
#ifndef __NR_write
#define __NR_write  1
#endif
#ifndef __NR_openat
#define __NR_openat 257
#endif
#ifndef __NR_ioctl
#define __NR_ioctl  16
#endif
#ifndef __NR_openat2
#define __NR_openat2 437
#endif
#ifndef __NR_readv
#define __NR_readv  19
#endif
#ifndef __NR_writev
#define __NR_writev 20
#endif

/* Minimal O_* flags used to detect writable opens */
#ifndef O_RDONLY
#define O_RDONLY 0
#endif
#ifndef O_WRONLY
#define O_WRONLY 1
#endif
#ifndef O_RDWR
#define O_RDWR 2
#endif

char LICENSE[] SEC("license") = "GPL";

#define MAX_DATA 256
#define MAX_PATH 256
/* Limit bytes compared in verifier-safe loop */
#define COMPARE_MAX 128
/* Maximum number of concurrently monitored target paths */
#define MAX_TARGETS 32

/* Minimal stat mode bits for character device check */
#ifndef S_IFMT
#define S_IFMT  00170000
#endif
#ifndef S_IFCHR
#define S_IFCHR 0020000
#endif

enum evtype { EV_OPEN=1, EV_CLOSE=2, EV_READ=3, EV_WRITE=4, EV_IOCTL=5 };

struct event {
    __u64 ts, dev;     /* dev unused here; kept for ABI compatibility (set 0) */
    __u32 pid, tgid;
    char  comm[16];
    __u32 type;        /* evtype */
    __s32 ret;         /* read/ioctl/close return */
    __u32 cmd;         /* ioctl cmd */
    __u32 dir;         /* 1=write, 0=read */
    __u32 port_idx;    /* target index matched in userspace-managed list */
    __u32 data_len, data_trunc;
    __u8  data[MAX_DATA];
};

/* Minimal iovec for readv/writev handling */
struct __iovec { void *iov_base; size_t iov_len; };

/* Ringbuf for user-space */
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1<<24); } events SEC(".maps");

/* FDs of interest: key = (tgid, fd) */
struct fdkey { __u32 tgid; __s32 fd; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __type(key, struct fdkey); __type(value, __u8); __uint(max_entries, 65536); } fd_interest SEC(".maps");

/* read() entry ctx: capture userspace buffer pointer by tgid */
struct read_ctx { __s32 fd; const void *buf; size_t count; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __type(key, __u32); __type(value, struct read_ctx); __uint(max_entries, 32768); } rd_ctx SEC(".maps");

/* openat() entry ctx: save filename pointer by tgid */
struct open_ctx { const char *filename; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __type(key, __u32); __type(value, struct open_ctx); __uint(max_entries, 32768); } op_ctx SEC(".maps");

/* close() entry ctx: save fd by tgid to check result on exit */
struct close_ctx { __s32 fd; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __type(key, __u32); __type(value, struct close_ctx); __uint(max_entries, 32768); } cl_ctx SEC(".maps");

/* Target device paths, set by userspace (index 0..MAX_TARGETS-1). Empty string marks unused slot */
struct pathval { char path[MAX_PATH]; };
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, struct pathval); __uint(max_entries, MAX_TARGETS); } target_path SEC(".maps");

/* Target device dev_t (major:minor) from stat(2), populated by userspace */
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, __u64); __uint(max_entries, MAX_TARGETS); } target_dev SEC(".maps");

/* Number of configured targets (0..MAX_TARGETS). Optional optimization hint. */
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, __u32); __uint(max_entries, 1); } target_count SEC(".maps");

/* Per-CPU scratch buffers (avoid stack usage) */
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, struct pathval); __uint(max_entries, 1); } scratch1 SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, struct pathval); __uint(max_entries, 1); } scratch2 SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, struct read_ctx); __uint(max_entries, 1); } scratch3 SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, struct open_ctx); __uint(max_entries, 1); } scratch4 SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, struct close_ctx); __uint(max_entries, 1); } scratch5 SEC(".maps");

/* Optional: orchestrator tgid (for parity with earlier version) */
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, __u32); __uint(max_entries, 1); } orchestrator_tgid SEC(".maps");

/* Map fd -> target index for quick attribution */
struct { __uint(type, BPF_MAP_TYPE_HASH); __type(key, struct fdkey); __type(value, __u32); __uint(max_entries, 65536); } fd_portidx SEC(".maps");

/* Carry matched target index from openat enter to exit (per-tgid) */
struct { __uint(type, BPF_MAP_TYPE_HASH); __type(key, __u32); __type(value, __u32); __uint(max_entries, 32768); } pending_open_idx SEC(".maps");

/* Track whether we've emitted OPEN event for a (tgid,fd) */
struct { __uint(type, BPF_MAP_TYPE_HASH); __type(key, struct fdkey); __type(value, __u8); __uint(max_entries, 65536); } fd_open_emitted SEC(".maps");

/* Track whether a given (tgid,fd) was opened writable */
struct { __uint(type, BPF_MAP_TYPE_HASH); __type(key, struct fdkey); __type(value, __u8); __uint(max_entries, 65536); } fd_is_writable SEC(".maps");

/* Track if the pending open is writable (per-tgid) */
struct { __uint(type, BPF_MAP_TYPE_HASH); __type(key, __u32); __type(value, __u8); __uint(max_entries, 32768); } pending_open_writable SEC(".maps");

/* Track whether a TTY ioctl was seen on the fd (e.g., TCGETS) */
struct { __uint(type, BPF_MAP_TYPE_HASH); __type(key, struct fdkey); __type(value, __u8); __uint(max_entries, 65536); } fd_has_tty_ioctl SEC(".maps");

/* Debug counters for open mapping */
struct dbg_open_vals {
    __u64 enter_seen_raw;
    __u64 enter_seen_tp;
    __u64 read_fail;
    __u64 enter_matches;
    __u64 no_match;
    __u64 exit_seen_raw;
    __u64 exit_seen_tp;
    __u64 exit_mapped;
    __u32 last_tgid;
    __s32 last_fd;
    __u32 last_idx;
};
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, struct dbg_open_vals); __uint(max_entries, 1); } dbg_open SEC(".maps");

/* (removed device-id maps; using path matching only) */

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
    for (int i = 0; i < COMPARE_MAX; i++) {
        if (i >= n) break;
        /* a and b point to map value memory (scratch buffers). Direct loads are allowed. */
        char ca = ((const volatile char *)a)[i];
        char cb = ((const volatile char *)b)[i];
        if (ca != cb) return 0;
        if (!ca) return 1;
    }
    return 1;
}

/* basename comparison removed (verifier-safe exact match is used) */

/* (removed basename_offset function - using exact path matching only) */

/* ---------- raw_syscalls-based attach for reliable args access ---------- */
SEC("tracepoint/raw_syscalls/sys_enter")
int tp_raw_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    long id = 0;
    bpf_probe_read_kernel(&id, sizeof(id), &ctx->id);
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    
    // Debug: Log all syscalls to see what we're getting
    bpf_printk("RAW_SYS_ENTER: id=%ld tgid=%u (openat=%d openat2=%d)", id, tgid, __NR_openat, __NR_openat2);

    if (id == __NR_openat || id == __NR_openat2) {
        /* Capture filename and try to match now; store matched index for exit */
        __u32 dkey = 0; struct dbg_open_vals *dv_enter = bpf_map_lookup_elem(&dbg_open, &dkey);
        if (dv_enter) dv_enter->enter_seen_raw += 1;
        const char *filename = NULL;
    bpf_probe_read_kernel(&filename, sizeof(filename), &ctx->args[1]);
        __u32 k0 = 0;
        struct pathval *sg = bpf_map_lookup_elem(&scratch2, &k0);
        if (!sg)
            return 0;
        int glen = bpf_probe_read_user_str(sg->path, sizeof(sg->path), filename);
        if (glen <= 0) {
            if (dv_enter) dv_enter->read_fail += 1;
            return 0;
        }

        __s32 matched_idx = -1;
#pragma unroll
        for (int i = 0; i < MAX_TARGETS; i++) {
            __u32 ki = i;
            struct pathval *tpv = bpf_map_lookup_elem(&target_path, &ki);
            if (!tpv) continue;
            if (tpv->path[0] == '\0') continue;
            if (str_eq_n(tpv->path, sg->path, COMPARE_MAX)) { matched_idx = i; break; }
        }
        if (matched_idx >= 0) {
            __u32 midx = (unsigned)matched_idx;
            // If this is an alias match (index >= MAX_TARGETS/2), map back to real port index
            if (midx >= MAX_TARGETS/2) {
                midx = midx - MAX_TARGETS/2;
            }
            bpf_printk("open-enter raw: tgid=%u match idx=%u\n", tgid, midx);
            bpf_map_update_elem(&pending_open_idx, &tgid, &midx, BPF_ANY);
            if (dv_enter) { dv_enter->enter_matches += 1; dv_enter->last_tgid = tgid; dv_enter->last_idx = midx; }
        }
        else if (dv_enter) { dv_enter->no_match += 1; }
        /* Also capture flags to determine writability */
        if (id == __NR_openat) {
            int flags = 0; bpf_probe_read_kernel(&flags, sizeof(flags), &ctx->args[2]);
            __u8 wr = ((flags & O_WRONLY) || (flags & O_RDWR)) ? 1 : 0;
            bpf_map_update_elem(&pending_open_writable, &tgid, &wr, BPF_ANY);
        } else {
            /* openat2: struct open_how* at arg2 -> read .flags
               For simplicity on older kernels, assume read-only if we cannot parse */
            __u8 wr0 = 0; bpf_map_update_elem(&pending_open_writable, &tgid, &wr0, BPF_ANY);
        }
        return 0;
    }

    if (id == __NR_write) {
        __s32 fd; const void __user *buf; size_t count;
        bpf_probe_read_kernel(&fd, sizeof(fd), &ctx->args[0]);
        bpf_probe_read_kernel(&buf, sizeof(buf), &ctx->args[1]);
        bpf_probe_read_kernel(&count, sizeof(count), &ctx->args[2]);
        struct fdkey k = { .tgid = tgid, .fd = fd };
        __u32 *idxp = bpf_map_lookup_elem(&fd_portidx, &k);
        if (!idxp) return 0;
        /* Harden: only emit WRITE if fd was opened writable and OPEN was emitted */
        __u8 *was_wr = bpf_map_lookup_elem(&fd_is_writable, &k);
        if (!was_wr) return 0;
        __u8 *em = bpf_map_lookup_elem(&fd_open_emitted, &k);
        if (!em) return 0;
        size_t cap = count > MAX_DATA ? MAX_DATA : count;
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e) return 0;
        fill_common(e, EV_WRITE);
        e->dir = 1; e->ret = 0; e->cmd = 0; e->port_idx = *idxp;
        e->data_len = cap; e->data_trunc = count > MAX_DATA ? (count - MAX_DATA) : 0;
        if (cap && buf) bpf_probe_read_user(e->data, cap, buf);
        bpf_ringbuf_submit(e, 0);
        return 0;
    }

    if (id == __NR_writev) {
        __s32 fd; const struct __iovec *iov; unsigned long vcnt;
        bpf_probe_read_kernel(&fd, sizeof(fd), &ctx->args[0]);
        bpf_probe_read_kernel(&iov, sizeof(iov), &ctx->args[1]);
        bpf_probe_read_kernel(&vcnt, sizeof(vcnt), &ctx->args[2]);
        struct fdkey k = { .tgid = tgid, .fd = fd };
        __u32 *idxp = bpf_map_lookup_elem(&fd_portidx, &k);
        if (!idxp || !iov || vcnt == 0) return 0;
        /* Harden: only emit WRITE if fd was opened writable and OPEN was emitted */
        __u8 *was_wr = bpf_map_lookup_elem(&fd_is_writable, &k);
        if (!was_wr) return 0;
        __u8 *em = bpf_map_lookup_elem(&fd_open_emitted, &k);
        if (!em) return 0;
        struct __iovec first = {};
        bpf_probe_read_user(&first, sizeof(first), iov);
        size_t cap = first.iov_len > MAX_DATA ? MAX_DATA : first.iov_len;
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e) return 0;
        fill_common(e, EV_WRITE);
        e->dir = 1; e->ret = 0; e->cmd = 0; e->port_idx = *idxp;
        e->data_len = cap; e->data_trunc = first.iov_len > MAX_DATA ? (first.iov_len - MAX_DATA) : 0;
        if (cap && first.iov_base) bpf_probe_read_user(e->data, cap, first.iov_base);
        bpf_ringbuf_submit(e, 0);
        return 0;
    }

    if (id == __NR_read) {
        __s32 fd; const void __user *buf; size_t count;
        bpf_probe_read_kernel(&fd, sizeof(fd), &ctx->args[0]);
        bpf_probe_read_kernel(&buf, sizeof(buf), &ctx->args[1]);
        bpf_probe_read_kernel(&count, sizeof(count), &ctx->args[2]);
    __u32 k0 = 0;
        struct read_ctx *rc = bpf_map_lookup_elem(&scratch3, &k0);
        if (!rc) return 0;
        rc->fd = fd; rc->buf = buf; rc->count = count;
        bpf_map_update_elem(&rd_ctx, &tgid, rc, BPF_ANY);
    return 0;
}

    if (id == __NR_readv) {
        __s32 fd; const struct __iovec *iov; unsigned long vcnt;
        bpf_probe_read_kernel(&fd, sizeof(fd), &ctx->args[0]);
        bpf_probe_read_kernel(&iov, sizeof(iov), &ctx->args[1]);
        bpf_probe_read_kernel(&vcnt, sizeof(vcnt), &ctx->args[2]);
        __u32 k0 = 0;
        struct read_ctx *rc = bpf_map_lookup_elem(&scratch3, &k0);
        if (!rc || !iov || vcnt == 0) return 0;
        struct __iovec first = {};
        bpf_probe_read_user(&first, sizeof(first), iov);
        rc->fd = fd; rc->buf = first.iov_base; rc->count = first.iov_len;
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
        bpf_map_update_elem(&rd_ctx, &tgid, rc, BPF_ANY);
        return 0;
    }

    if (id == __NR_ioctl) {
        __s32 fd; __u32 cmd;
        bpf_probe_read_kernel(&fd, sizeof(fd), &ctx->args[0]);
        bpf_probe_read_kernel(&cmd, sizeof(cmd), &ctx->args[1]);
        struct fdkey k = { .tgid = tgid, .fd = fd };
        __u32 *idxp = bpf_map_lookup_elem(&fd_portidx, &k);
        if (!idxp) return 0;
        /* Do NOT emit OPEN on ioctl; ioctl-only scans shouldn't flip modes */
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e) return 0;
        fill_common(e, EV_IOCTL);
        e->cmd = cmd; e->ret = 0; e->dir = 0; e->port_idx = *idxp;
        e->data_len = 0; e->data_trunc = 0;
        bpf_ringbuf_submit(e, 0);
        return 0;
    }

    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int tp_raw_sys_exit(struct trace_event_raw_sys_exit *ctx)
{
    long id = 0; __s64 ret = 0;
    bpf_probe_read_kernel(&id, sizeof(id), &ctx->id);
    bpf_probe_read_kernel(&ret, sizeof(ret), &ctx->ret);
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    if (id == __NR_openat || id == __NR_openat2) {
        if (ret >= 0) {
            __u32 dkey2 = 0; struct dbg_open_vals *dv2 = bpf_map_lookup_elem(&dbg_open, &dkey2);
            if (dv2) dv2->exit_seen_raw += 1;

            /* If path match was recorded, only map fd; do NOT emit OPEN here */
            __u32 *idxp = bpf_map_lookup_elem(&pending_open_idx, &tgid);
            if (idxp) {
                __u32 midx = *idxp;
                struct fdkey k; k.tgid = tgid; k.fd = (__s32)ret; __u8 one = 1;
                bpf_map_update_elem(&fd_interest, &k, &one, BPF_ANY);
                bpf_map_update_elem(&fd_portidx, &k, &midx, BPF_ANY);
                if (dv2) { dv2->exit_mapped += 1; dv2->last_fd = (__s32)ret; dv2->last_idx = midx; }
                bpf_map_delete_elem(&pending_open_idx, &tgid);
            }
        }
        return 0;
    }

    if (id == __NR_read) {
        struct read_ctx *rc = bpf_map_lookup_elem(&rd_ctx, &tgid);
        if (!rc) return 0;
        struct fdkey k; k.tgid = tgid; k.fd = rc->fd;
        __u32 *idxp = bpf_map_lookup_elem(&fd_portidx, &k);
        if (!idxp) { bpf_map_delete_elem(&rd_ctx, &tgid); return 0; }
        /* Only emit READ if we've already emitted OPEN (from write/ioctl) */
        __u8 *emitted = bpf_map_lookup_elem(&fd_open_emitted, &k);
        if (!emitted) { bpf_map_delete_elem(&rd_ctx, &tgid); return 0; }
        if (ret <= 0) { bpf_map_delete_elem(&rd_ctx, &tgid); return 0; }
        /* Clamp ret to unsigned bounded size for copy */
        __u64 uret = ( __u64)ret;
        __u32 cap = uret > MAX_DATA ? MAX_DATA : ( __u32)uret;
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e) { bpf_map_delete_elem(&rd_ctx, &tgid); return 0; }
        fill_common(e, EV_READ);
        e->dir = 0; e->ret = ret; e->cmd = 0; e->port_idx = *idxp;
        e->data_len = cap; e->data_trunc = ret > MAX_DATA ? (ret - MAX_DATA) : 0;
        if (cap && rc->buf) bpf_probe_read_user(e->data, cap, rc->buf);
        bpf_ringbuf_submit(e, 0);
        bpf_map_delete_elem(&rd_ctx, &tgid);
        return 0;
    }

    if (id == __NR_readv) {
        struct read_ctx *rc = bpf_map_lookup_elem(&rd_ctx, &tgid);
        if (!rc) return 0;
        struct fdkey k; k.tgid = tgid; k.fd = rc->fd;
        __u32 *idxp = bpf_map_lookup_elem(&fd_portidx, &k);
        if (!idxp) { bpf_map_delete_elem(&rd_ctx, &tgid); return 0; }
        /* Only emit READ if we've already emitted OPEN (from write/ioctl) */
        __u8 *emitted = bpf_map_lookup_elem(&fd_open_emitted, &k);
        if (!emitted) { bpf_map_delete_elem(&rd_ctx, &tgid); return 0; }
        if (ret <= 0) { bpf_map_delete_elem(&rd_ctx, &tgid); return 0; }
        __u64 uret2 = ( __u64)ret;
        __u32 cap = uret2 > MAX_DATA ? MAX_DATA : ( __u32)uret2;
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e) { bpf_map_delete_elem(&rd_ctx, &tgid); return 0; }
        fill_common(e, EV_READ);
        e->dir = 0; e->ret = ret; e->cmd = 0; e->port_idx = *idxp;
        e->data_len = cap; e->data_trunc = ret > MAX_DATA ? (ret - MAX_DATA) : 0;
        if (cap && rc->buf) bpf_probe_read_user(e->data, cap, rc->buf);
        bpf_ringbuf_submit(e, 0);
        bpf_map_delete_elem(&rd_ctx, &tgid);
        return 0;
    }

    return 0;
}

/* ---------- Fallback: syscall-specific openat hooks (jammy-friendly) ---------- */
SEC("tracepoint/syscalls/sys_enter_openat")
int tp_enter_openat_tp(struct trace_event_raw_sys_enter *ctx)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    const char *filename = NULL;
    bpf_probe_read_kernel(&filename, sizeof(filename), &ctx->args[1]);
    __u32 k0 = 0;
    struct pathval *sg = bpf_map_lookup_elem(&scratch2, &k0);
    if (!sg)
        return 0;
    int glen = bpf_probe_read_user_str(sg->path, sizeof(sg->path), filename);
    if (glen <= 0)
        return 0;
    
    bpf_printk("openat-enter: tgid=%u filename='%s'", tgid, sg->path);

        __s32 matched_idx = -1;
#pragma unroll
            for (int i = 0; i < MAX_TARGETS; i++) {
                __u32 ki = i;
                struct pathval *tpv = bpf_map_lookup_elem(&target_path, &ki);
                if (!tpv) continue;
                if (tpv->path[0] == '\0') continue;
                if (str_eq_n(tpv->path, sg->path, COMPARE_MAX)) { matched_idx = i; break; }
            }
        if (matched_idx >= 0) {
            __u32 midx = (unsigned)matched_idx;
            // If this is an alias match (index >= MAX_TARGETS/2), map back to real port index
            if (midx >= MAX_TARGETS/2) {
                midx = midx - MAX_TARGETS/2;
            }
        bpf_printk("openat-enter MATCH: tgid=%u filename='%s' idx=%u", tgid, sg->path, midx);
        bpf_map_update_elem(&pending_open_idx, &tgid, &midx, BPF_ANY);
        __u32 dkey = 0; struct dbg_open_vals *dv = bpf_map_lookup_elem(&dbg_open, &dkey);
        if (dv) { dv->enter_matches += 1; dv->last_tgid = tgid; dv->last_idx = midx; }
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int tp_enter_openat2_tp(struct trace_event_raw_sys_enter *ctx)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    const char *filename = NULL;
    bpf_probe_read_kernel(&filename, sizeof(filename), &ctx->args[1]);
    __u32 k0 = 0;
    struct pathval *sg = bpf_map_lookup_elem(&scratch2, &k0);
    if (!sg)
        return 0;
    int glen = bpf_probe_read_user_str(sg->path, sizeof(sg->path), filename);
    if (glen <= 0)
        return 0;

        __s32 matched_idx = -1;
#pragma unroll
        for (int i = 0; i < MAX_TARGETS; i++) {
            __u32 ki = i;
            struct pathval *tpv = bpf_map_lookup_elem(&target_path, &ki);
            if (!tpv) continue;
            if (tpv->path[0] == '\0') continue;
            if (str_eq_n(tpv->path, sg->path, COMPARE_MAX)) { matched_idx = i; break; }
        }
        if (matched_idx >= 0) {
            __u32 midx = (unsigned)matched_idx;
            // If this is an alias match (index >= MAX_TARGETS/2), map back to real port index
            if (midx >= MAX_TARGETS/2) {
                midx = midx - MAX_TARGETS/2;
            }
        bpf_map_update_elem(&pending_open_idx, &tgid, &midx, BPF_ANY);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tp_exit_openat_tp(struct trace_event_raw_sys_exit *ctx)
{
    __s64 ret = 0; 
    bpf_probe_read_kernel(&ret, sizeof(ret), &ctx->ret);
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    
    bpf_printk("openat-exit: tgid=%u ret=%ld", tgid, ret);
    
    if (ret < 0) {
        bpf_printk("openat-exit: FAILED tgid=%u ret=%ld", tgid, ret);
        bpf_map_delete_elem(&pending_open_idx, &tgid);
        return 0;
    }
    __u32 *idxp = bpf_map_lookup_elem(&pending_open_idx, &tgid);
    if (!idxp) return 0;
    struct fdkey k; k.tgid = tgid; k.fd = (__s32)ret; __u8 val = 1; __u32 midx = *idxp;
    bpf_map_update_elem(&fd_interest, &k, &val, BPF_ANY);
    bpf_map_update_elem(&fd_portidx, &k, &midx, BPF_ANY);
    /* Record writability per fd and emit OPEN for all opens (not just writable) */
    __u8 *wr = bpf_map_lookup_elem(&pending_open_writable, &tgid);
    if (wr && *wr) {
        __u8 yes = 1; bpf_map_update_elem(&fd_is_writable, &k, &yes, BPF_ANY);
    }
    
    /* Always emit OPEN event for all monitored TTY opens */
    struct event *o = bpf_ringbuf_reserve(&events, sizeof(*o), 0);
    if (o) { fill_common(o, EV_OPEN); o->cmd=0; o->ret=ret; o->dir=0; o->port_idx=midx; o->data_len=0; o->data_trunc=0; bpf_ringbuf_submit(o, 0); }
    /* Mark emitted to allow read/write logging */
    __u8 emitted = 1;
    bpf_map_update_elem(&fd_open_emitted, &k, &emitted, BPF_ANY);
    bpf_map_delete_elem(&pending_open_writable, &tgid);
    bpf_map_delete_elem(&pending_open_idx, &tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int tp_exit_openat2_tp(struct trace_event_raw_sys_exit *ctx)
{
    __s64 ret = 0; 
    bpf_probe_read_kernel(&ret, sizeof(ret), &ctx->ret);
    if (ret < 0) {
        __u32 tgid_fail = bpf_get_current_pid_tgid() >> 32;
        bpf_map_delete_elem(&pending_open_idx, &tgid_fail);
        return 0;
    }
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    __u32 *idxp = bpf_map_lookup_elem(&pending_open_idx, &tgid);
    if (!idxp) return 0;
    struct fdkey k; k.tgid = tgid; k.fd = (__s32)ret; __u8 val2 = 1; __u32 midx = *idxp;
    bpf_map_update_elem(&fd_interest, &k, &val2, BPF_ANY);
    bpf_map_update_elem(&fd_portidx, &k, &midx, BPF_ANY);
    __u8 *wr2 = bpf_map_lookup_elem(&pending_open_writable, &tgid);
    if (wr2 && *wr2) {
        __u8 yes = 1; bpf_map_update_elem(&fd_is_writable, &k, &yes, BPF_ANY);
    }
    
    /* Always emit OPEN event for all monitored TTY opens */
    struct event *o2 = bpf_ringbuf_reserve(&events, sizeof(*o2), 0);
    if (o2) { fill_common(o2, EV_OPEN); o2->cmd=0; o2->ret=ret; o2->dir=0; o2->port_idx=midx; o2->data_len=0; o2->data_trunc=0; bpf_ringbuf_submit(o2, 0); }
    /* Mark emitted to allow read/write logging */
    __u8 emitted2 = 1;
    bpf_map_update_elem(&fd_open_emitted, &k, &emitted2, BPF_ANY);
    bpf_map_delete_elem(&pending_open_writable, &tgid);
    bpf_map_delete_elem(&pending_open_idx, &tgid);
    return 0;
}

/* (no fallback syscalls openat hooks; raw_syscalls handles open mapping) */

/* LSM hook removed in favor of userspace mapping */

/* ---------- sys_enter_close ---------- */
SEC("tracepoint/syscalls/sys_enter_close")
int tp_enter_close(struct trace_event_raw_sys_enter *ctx)
{
    __s32 fd;
    bpf_probe_read_kernel(&fd, sizeof(fd), &ctx->args[0]);
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    struct fdkey k;
    k.tgid = tgid;
    k.fd = fd;
    __u32 *idxp = bpf_map_lookup_elem(&fd_portidx, &k);
    if (!idxp) return 0;

    /* Use scratch buffer to avoid stack access issues */
    __u32 k0 = 0;
    struct close_ctx *cc = bpf_map_lookup_elem(&scratch5, &k0);
    if (!cc) return 0;
    cc->fd = fd;
    bpf_map_update_elem(&cl_ctx, &tgid, cc, BPF_ANY);
    return 0;
}

/* ---------- sys_exit_close ---------- */
SEC("tracepoint/syscalls/sys_exit_close")
int tp_exit_close(struct trace_event_raw_sys_exit *ctx)
{
    __s64 ret;
    bpf_probe_read_kernel(&ret, sizeof(ret), &ctx->ret);
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    struct close_ctx *cc = bpf_map_lookup_elem(&cl_ctx, &tgid);
    if (!cc) return 0;

    struct fdkey k;
    k.tgid = tgid;
    k.fd = cc->fd;
    bpf_map_delete_elem(&cl_ctx, &tgid);

    if (ret == 0) {
        __u32 *idxp = bpf_map_lookup_elem(&fd_portidx, &k);
        /* only emit CLOSE if we emitted OPEN */
        __u8 *emitted = bpf_map_lookup_elem(&fd_open_emitted, &k);
        if (emitted && idxp) {
            struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
            if (e) {
                fill_common(e, EV_CLOSE);
                e->cmd = 0; e->ret = 0; e->dir = 0; e->port_idx = *idxp;
                e->data_len = 0; e->data_trunc = 0;
                bpf_ringbuf_submit(e, 0);
            }
        }
        /* cleanup state */
        bpf_map_delete_elem(&fd_open_emitted, &k);
        bpf_map_delete_elem(&rd_ctx, &k);
        bpf_map_delete_elem(&fd_interest, &k);
        if (idxp) bpf_map_delete_elem(&fd_portidx, &k);
    }
    return 0;
}

/* ---------- sys_enter_write: app -> device ---------- */
SEC("tracepoint/syscalls/sys_enter_write")
int tp_enter_write(struct trace_event_raw_sys_enter *ctx)
{
    __s32 fd;
    const void __user *buf;
    size_t count;
    
    // Extract syscall arguments
    bpf_probe_read_kernel(&fd, sizeof(fd), &ctx->args[0]);
    bpf_probe_read_kernel(&buf, sizeof(buf), &ctx->args[1]);
    bpf_probe_read_kernel(&count, sizeof(count), &ctx->args[2]);
    
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    // Check if this fd is of interest
    struct fdkey k;
    k.tgid = tgid;
    k.fd = fd;
    __u32 *idxp = bpf_map_lookup_elem(&fd_portidx, &k);
    if (!idxp) return 0;
    /* Only log WRITE if fd was opened writable and OPEN was already emitted */
    __u8 *was_wr = bpf_map_lookup_elem(&fd_is_writable, &k);
    if (!was_wr) return 0;
    __u8 *em = bpf_map_lookup_elem(&fd_open_emitted, &k);
    if (!em) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(e, EV_WRITE);
    e->dir = 1; e->ret = 0; e->cmd = 0; e->port_idx = *idxp;
    
    // Capture data (limit to MAX_DATA)
    size_t cap = count > MAX_DATA ? MAX_DATA : count;
    e->data_len = cap;
    e->data_trunc = count > MAX_DATA ? (count - MAX_DATA) : 0;
    
    // Copy data from userspace buffer
    if (cap && buf) {
        bpf_probe_read_user(e->data, cap, buf);
    }
    
    // Submit event
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------- sys_enter_read: device -> app (capture on enter only, optional) ---------- */
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

    /* Always store read context, check interest in exit */
    /* Use scratch buffer to avoid stack access issues */
    __u32 k0 = 0;
    struct read_ctx *rc = bpf_map_lookup_elem(&scratch3, &k0);
    if (!rc) return 0;
    
    rc->fd = fd;
    rc->buf = buf;
    rc->count = count;
    bpf_map_update_elem(&rd_ctx, &tgid, rc, BPF_ANY);
    return 0;
}

/* (Optional) sys_exit_read could copy dev->app bytes using the recorded buf+ret
   If you want that too, I'll extend this with a small per-task slot for the fd. */

/* ---------- sys_exit_read: device -> app (capture actual data) ---------- */
SEC("tracepoint/syscalls/sys_exit_read")
int tp_exit_read(struct trace_event_raw_sys_exit *ctx)
{
    __s64 ret;
    bpf_probe_read_kernel(&ret, sizeof(ret), &ctx->ret);
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    /* Find the read context we saved on enter */
    struct read_ctx *rc = bpf_map_lookup_elem(&rd_ctx, &tgid);
    if (!rc) return 0;

    /* Check if this fd is of interest */
    struct fdkey k;
    k.tgid = tgid;
    k.fd = rc->fd;
    __u32 *idxp = bpf_map_lookup_elem(&fd_portidx, &k);
    if (!idxp) {
        bpf_map_delete_elem(&rd_ctx, &tgid);
        return 0;
    }

    /* Only report successful reads with data */
    if (ret <= 0) {
        bpf_map_delete_elem(&rd_ctx, &tgid);
        return 0;
    }

    /* Only capture READ if OPEN was emitted (now works for all opens) */
    __u8 *emitted = bpf_map_lookup_elem(&fd_open_emitted, &k);
    if (!emitted) {
        bpf_map_delete_elem(&rd_ctx, &tgid);
        return 0;
    }

    /* Do NOT emit OPEN from READ path */

    /* For reliability across kernels/verifier, do not copy DEV->APP payload here */
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&rd_ctx, &tgid);
        return 0;
    }

    fill_common(e, EV_READ);
    e->dir = 0; e->ret = ret; e->cmd = 0;
    e->port_idx = *idxp;
    e->data_len = 0; /* payload omitted to satisfy older verifiers */
    e->data_trunc = 0;
    bpf_ringbuf_submit(e, 0);

    bpf_map_delete_elem(&rd_ctx, &tgid);
    return 0;
}

/* ---------- sys_enter_ioctl ---------- */
SEC("tracepoint/syscalls/sys_enter_ioctl")
int tp_enter_ioctl(struct trace_event_raw_sys_enter *ctx)
{
    __s32 fd;
    __u32 cmd;
    bpf_probe_read_kernel(&fd, sizeof(fd), &ctx->args[0]);
    bpf_probe_read_kernel(&cmd, sizeof(cmd), &ctx->args[1]);
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    struct fdkey k;
    k.tgid = tgid;
    k.fd = fd;
    __u32 *idxp = bpf_map_lookup_elem(&fd_portidx, &k);
    if (!idxp) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(e, EV_IOCTL);
    e->cmd = cmd; e->ret = 0; e->dir = 0; e->port_idx = *idxp;
    e->data_len = 0; e->data_trunc = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

