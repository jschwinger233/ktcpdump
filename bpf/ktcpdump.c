// +build ignore
// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_core_read.h"

#define MAX_STACK_DEPTH 50
#define MAX_DATA_SIZE 1500
#define MAX_TRACK_SIZE 10240

const static u32 ZERO = 0;

struct event {
	u64 at;
	u64 ts;
	u64 skb;
	u32 data_len;
	u8 has_mac: 1;
	u8 unused: 7;
	u8 data[MAX_DATA_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct event);
	__uint(max_entries, 1);
} event_stash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, u64);
	__type(value, struct skb *);
	__uint(max_entries, MAX_TRACK_SIZE);
} stackid_skb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct skb *);
	__type(value, u64);
	__uint(max_entries, MAX_TRACK_SIZE);
} skb_stackid SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1<<29);
} event_ringbuf SEC(".maps");

static __always_inline u64
get_stackid(struct pt_regs *ctx)
{
	u64 caller_fp;
	u64 fp = PT_REGS_FP(ctx);
	for (int depth = 0; depth < MAX_STACK_DEPTH; depth++) {
		if (bpf_probe_read_kernel(&caller_fp, sizeof(caller_fp), (void *)fp) < 0)
			break;

		if (caller_fp == 0)
			break;

		fp = caller_fp;
	}
	return fp;
}

/* kprobe_skb_by_stackid will be attached to all kprobe targets in -k. */
SEC("kprobe/skb_by_stackid")
int kprobe_skb_by_stackid(struct pt_regs *ctx) {
	u64 stackid = get_stackid(ctx);

	struct sk_buff **pskb = bpf_map_lookup_elem(&stackid_skb, &stackid);
	if (!pskb || !*pskb)
		return BPF_OK;
	struct sk_buff *skb = *pskb;

	// TODO: pcap filter
	if (BPF_CORE_READ(skb, mark) == 0)
		return BPF_OK;

	struct event *event = bpf_map_lookup_elem(&event_stash, &ZERO);
	if (!event)
		return BPF_OK;

	event->at = PT_REGS_FP(ctx);
	event->ts = bpf_ktime_get_boot_ns();
	event->skb = (u64)skb;
	event->has_mac = BPF_CORE_READ(skb, mac_len) ? true : false;

	u16 off_l2_or_l3 = event->has_mac
		? BPF_CORE_READ(skb, mac_header)
		: BPF_CORE_READ(skb, network_header);
	event->data_len = BPF_CORE_READ(skb, tail) - (u32)off_l2_or_l3;

	void *skb_head = BPF_CORE_READ(skb, head);
	u32 data_len = event->data_len > MAX_DATA_SIZE
		? MAX_DATA_SIZE
		: event->data_len;
	bpf_probe_read_kernel(&event->data, data_len, (void *)(skb_head + off_l2_or_l3));

	bpf_ringbuf_output(&event_ringbuf, event, sizeof(*event), 0);
	return BPF_OK;
}

/* kretprobe_skb will be attached to all kretprobe targets with skb retval */
SEC("kretprobe/skb_build")
int kretprobe_skb_build(struct pt_regs *ctx) {
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_RC(ctx);

	u64 stackid = get_stackid(ctx);

	bpf_map_update_elem(&stackid_skb, &stackid, &skb, BPF_ANY);
	bpf_map_update_elem(&skb_stackid, &skb, &stackid, BPF_ANY);
	return BPF_OK;
}

/* skb_free will be attached to kfree_skbmem. */
SEC("kprobe/skb_free")
int kprobe_skb_free(struct pt_regs *ctx) {
	u64 stackid = get_stackid(ctx);

	bpf_map_delete_elem(&stackid_skb, &stackid);

	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	u64 skb_addr = (u64)skb;

	u64 *pstackid = bpf_map_lookup_elem(&skb_stackid, &skb_addr);
	if (pstackid)
		bpf_map_delete_elem(&stackid_skb, pstackid);
	bpf_map_delete_elem(&skb_stackid, &skb_addr);

	return BPF_OK;
}

char __license[] SEC("license") = "Dual BSD/GPL";
