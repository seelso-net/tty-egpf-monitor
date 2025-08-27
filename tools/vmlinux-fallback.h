/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __VMLINUX_H
#define __VMLINUX_H

/* Minimal fallback header for systems without /sys/kernel/btf/vmlinux.
 * Only includes types and structs used by src/sniffer.bpf.c
 */

typedef unsigned char      __u8;
typedef unsigned short     __u16;
typedef unsigned int       __u32;
typedef unsigned long long __u64;
typedef signed char        __s8;
typedef short              __s16;
typedef int                __s32;
typedef long long          __s64;
typedef __u32              __be32;
typedef __u16              __be16;
typedef __u32              __wsum;
typedef unsigned long      size_t;

/* Basic aliases used in helpers */
typedef __u64 u64; typedef __u32 u32; typedef __u16 u16; typedef __u8 u8;

/* Tracepoint contexts used */
struct trace_event_raw_sys_enter { __u64 args[6]; __u64 id; };
struct trace_event_raw_sys_exit { __u64 ret; __u64 id; };

#endif /* __VMLINUX_H */

