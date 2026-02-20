#include "vmlinux_min.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define PEEK 16

struct http_event {
	__u64 dur_ns;
	__u16 port;
	__u16 status;
	__u8  kind;
	__u8  pad0;
	__u16 pad1;
};

struct http_event *unused_http_event __attribute__((unused));

struct recv_ctx {
	__u64 sk;
	__u64 buf;
};

struct ds_ctx {
	__u64 ts;
	__u16 dport;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u16);
	__type(value, __u8);
} watched_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u16);
	__type(value, __u8);
} downstream_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, __u64);
} inflight SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct recv_ctx);
} recvs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, struct ds_ctx);
} ds_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u64);
} ds_pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 16);
} events SEC(".maps");

static __always_inline __u16 sockPort(struct sock *sk)
{
	return BPF_CORE_READ(sk, __sk_common.skc_num);
}

static __always_inline __u16 sockDport(struct sock *sk)
{
	__be16 d = BPF_CORE_READ(sk, __sk_common.skc_dport);
	return (d >> 8) | (d << 8);
}

static __always_inline __u64 iterBase(struct msghdr *msg)
{
	__u8 t = BPF_CORE_READ(msg, msg_iter.iter_type);
	if (t == 0)
		return (__u64)BPF_CORE_READ(msg, msg_iter.__ubuf_iovec.iov_base);
	if (t == 1) {
		const struct iovec *iov = BPF_CORE_READ(msg, msg_iter.__iov);
		if (!iov)
			return 0;
		return (__u64)BPF_CORE_READ(iov, iov_base);
	}
	return 0;
}

static __always_inline int isRequestStart(const char *b)
{
	if (b[0] == 'G' && b[1] == 'E' && b[2] == 'T' && b[3] == ' ')
		return 1;
	if (b[0] == 'P' && b[1] == 'O' && b[2] == 'S' && b[3] == 'T')
		return 1;
	if (b[0] == 'P' && b[1] == 'U' && b[2] == 'T' && b[3] == ' ')
		return 1;
	if (b[0] == 'H' && b[1] == 'E' && b[2] == 'A' && b[3] == 'D')
		return 1;
	if (b[0] == 'D' && b[1] == 'E' && b[2] == 'L' && b[3] == 'E')
		return 1;
	if (b[0] == 'P' && b[1] == 'A' && b[2] == 'T' && b[3] == 'C')
		return 1;
	if (b[0] == 'O' && b[1] == 'P' && b[2] == 'T' && b[3] == 'I')
		return 1;
	return 0;
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(tcpRecvEnter, struct sock *sk, struct msghdr *msg)
{
	__u16 port = sockPort(sk);
	if (bpf_map_lookup_elem(&watched_ports, &port)) {
		__u64 buf = iterBase(msg);
		if (!buf)
			return 0;
		struct recv_ctx rc = { .sk = (__u64)sk, .buf = buf };
		__u64 id = bpf_get_current_pid_tgid();
		bpf_map_update_elem(&recvs, &id, &rc, BPF_ANY);
	}
	return 0;
}

SEC("kretprobe/tcp_recvmsg")
int BPF_KRETPROBE(tcpRecvExit, long ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct recv_ctx *rc = bpf_map_lookup_elem(&recvs, &id);
	if (rc) {
		__u64 sk = rc->sk;
		__u64 buf = rc->buf;
		bpf_map_delete_elem(&recvs, &id);
		if (ret >= 4) {
			char head[PEEK] = {};
			if (!bpf_probe_read_user(head, sizeof(head), (void *)buf) && isRequestStart(head)) {
				__u64 now = bpf_ktime_get_ns();
				bpf_map_update_elem(&inflight, &sk, &now, BPF_ANY);
			}
		}
	}
	struct ds_ctx *c = bpf_map_lookup_elem(&ds_start, &id);
	if (c) {
		__u16 dport = c->dport;
		__u64 ts = c->ts;
		bpf_map_delete_elem(&ds_start, &id);
		if (ret > 0) {
			struct http_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
			if (e) {
				e->dur_ns = bpf_ktime_get_ns() - ts;
				e->port = dport;
				e->status = 0;
				e->kind = 1;
				e->pad0 = 0;
				e->pad1 = 0;
				bpf_ringbuf_submit(e, 0);
			}
		}
	}
	return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcpSendEnter, struct sock *sk, struct msghdr *msg)
{
	__u16 port = sockPort(sk);
	if (bpf_map_lookup_elem(&watched_ports, &port)) {
		__u64 key = (__u64)sk;
		__u64 *start = bpf_map_lookup_elem(&inflight, &key);
		if (!start)
			return 0;
		__u64 buf = iterBase(msg);
		if (!buf)
			return 0;
		char head[PEEK] = {};
		if (bpf_probe_read_user(head, sizeof(head), (void *)buf))
			return 0;
		if (head[0] != 'H' || head[1] != 'T' || head[2] != 'T' || head[3] != 'P' || head[8] != ' ')
			return 0;
		if (head[9] < '1' || head[9] > '5')
			return 0;
		__u16 status = (head[9] - '0') * 100 + (head[10] - '0') * 10 + (head[11] - '0');
		__u64 now = bpf_ktime_get_ns();
		struct http_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (!e) {
			bpf_map_delete_elem(&inflight, &key);
			return 0;
		}
		e->dur_ns = now - *start;
		e->port = port;
		e->status = status;
		e->kind = 0;
		e->pad0 = 0;
		e->pad1 = 0;
		bpf_ringbuf_submit(e, 0);
		bpf_map_delete_elem(&inflight, &key);
		return 0;
	}
	__u16 dport = sockDport(sk);
	if (bpf_map_lookup_elem(&downstream_ports, &dport)) {
		__u64 id = bpf_get_current_pid_tgid();
		struct ds_ctx c = { .ts = bpf_ktime_get_ns(), .dport = dport };
		bpf_map_update_elem(&ds_start, &id, &c, BPF_ANY);
	}
	return 0;
}
