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

/* Minimal BPF map type values used in map definitions */
#ifndef BPF_MAP_TYPE_HASH
#define BPF_MAP_TYPE_HASH 1
#endif
#ifndef BPF_MAP_TYPE_ARRAY
#define BPF_MAP_TYPE_ARRAY 2
#endif
#ifndef BPF_MAP_TYPE_PERCPU_ARRAY
#define BPF_MAP_TYPE_PERCPU_ARRAY 4
#endif
#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF 27
#endif

/* Minimal BPF map update flags */
#ifndef BPF_ANY
#define BPF_ANY 0
#endif
#ifndef BPF_NOEXIST
#define BPF_NOEXIST 1
#endif
#ifndef BPF_EXIST
#define BPF_EXIST 2
#endif

/* Tracepoint contexts used */
struct trace_event_raw_sys_enter { __u64 args[6]; __u64 id; };
struct trace_event_raw_sys_exit { __u64 ret; __u64 id; };

/* Forward declarations */
struct task_struct;
struct files_struct;
struct fdtable;
struct file;
struct inode;

/* Minimal structure definitions for eBPF access */
struct task_struct {
	/* Only include the fields we actually access */
	struct files_struct *files;
	/* Add padding to avoid size mismatches */
	char _padding[4096 - sizeof(struct files_struct*)];
};

struct files_struct {
	/* Only include the fields we actually access */
	struct fdtable *fdt;
	/* Add padding to avoid size mismatches */
	char _padding[4096 - sizeof(struct fdtable*)];
};

struct fdtable {
	/* Only include the fields we actually access */
	struct file **fd;
	/* Add padding to avoid size mismatches */
	char _padding[4096 - sizeof(struct file**)];
};

struct file {
	/* Only include the fields we actually access */
	struct inode *f_inode;
	/* Add padding to avoid size mismatches */
	char _padding[4096 - sizeof(struct inode*)];
};

struct inode {
	/* Only include the fields we actually access */
	__u64 i_rdev;
	/* Add padding to avoid size mismatches */
	char _padding[4096 - sizeof(__u64)];
};

#endif /* __VMLINUX_H */

