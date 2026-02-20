#pragma once

#ifndef __VMLINUX_H__
#define __VMLINUX_H__
#endif

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef short __s16;
typedef int __s32;
typedef long long __s64;
typedef __u64 size_t;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;

enum {
	BPF_ANY     = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST   = 2,
};

enum bpf_map_type {
	BPF_MAP_TYPE_HASH     = 1,
	BPF_MAP_TYPE_ARRAY    = 2,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_RINGBUF  = 27,
};

#if defined(__TARGET_ARCH_arm64)
struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
} __attribute__((preserve_access_index));
#endif

struct pt_regs {
#if defined(__TARGET_ARCH_x86)
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long bp;
	unsigned long bx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long ax;
	unsigned long cx;
	unsigned long dx;
	unsigned long si;
	unsigned long di;
	unsigned long orig_ax;
	unsigned long ip;
	unsigned long cs;
	unsigned long flags;
	unsigned long sp;
	unsigned long ss;
#elif defined(__TARGET_ARCH_arm64)
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
#endif
} __attribute__((preserve_access_index));

struct sock_common {
	__u16 skc_num;
	__be16 skc_dport;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
} __attribute__((preserve_access_index));

struct iovec {
	void *iov_base;
	__u64 iov_len;
} __attribute__((preserve_access_index));

struct iov_iter {
	__u8 iter_type;
	struct iovec __ubuf_iovec;
	const struct iovec *__iov;
} __attribute__((preserve_access_index));

struct msghdr {
	struct iov_iter msg_iter;
} __attribute__((preserve_access_index));
