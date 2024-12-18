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
const static u8 TRUE = 1;

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
	__type(key, struct sk_buff *);
	__type(value, u8);
	__uint(max_entries, MAX_TRACK_SIZE);
} alive_skbs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1<<29);
} event_ringbuf SEC(".maps");

#define is_skb_on_reg(r) \
	reg = BPF_CORE_READ(ctx, r); \
	if (reg && bpf_map_lookup_elem(&alive_skbs, &reg)) \
		return reg;

static __always_inline u64 search_skb_from_register(struct pt_regs *ctx)
{
	u64 reg = 0;
	is_skb_on_reg(r15);
	is_skb_on_reg(r14);
	is_skb_on_reg(r13);
	is_skb_on_reg(r12);
	is_skb_on_reg(bp);
	is_skb_on_reg(bx);
	is_skb_on_reg(r11);
	is_skb_on_reg(r10);
	is_skb_on_reg(r9);
	is_skb_on_reg(r8);
	is_skb_on_reg(ax);
	is_skb_on_reg(cx);
	is_skb_on_reg(dx);
	is_skb_on_reg(si);
	is_skb_on_reg(di);
	return 0;
}

static __always_inline u64 search_skb_from_stack(struct pt_regs *ctx)
{
	u64 sp = (u64)PT_REGS_SP(ctx);

	u64 maybe_skb;
	for (int i = 0; i < MAX_STACK_DEPTH; i++) {
		u64 addr = sp + i * sizeof(u64);
		bpf_probe_read_kernel(&maybe_skb, sizeof(maybe_skb), (void *)addr);
		if (bpf_map_lookup_elem(&alive_skbs, &maybe_skb))
			return maybe_skb;
	}

	return 0;
}

/* kprobe_skb_by_search will be attached to all kprobe targets in -k. */
SEC("kprobe/skb_by_search")
int kprobe_skb_by_search(struct pt_regs *ctx) {
	struct sk_buff *skb;

	skb = (struct sk_buff *)search_skb_from_register(ctx);
	if (!skb) {
		skb = (struct sk_buff *)search_skb_from_stack(ctx);
		bpf_printk("skb from stack: %llx\n", skb);
	} else {
		bpf_printk("skb from register: %llx\n", skb);
	}
	if (!skb)
		return BPF_OK;

	// TODO: pcap filter
	if (BPF_CORE_READ(skb, mark) != 0x08000000)
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
	bpf_map_update_elem(&alive_skbs, &skb, &TRUE, BPF_ANY);
	return BPF_OK;
}

/* skb_free will be attached to kfree_skbmem. */
SEC("kprobe/skb_free")
int kprobe_skb_free(struct pt_regs *ctx) {
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	bpf_map_delete_elem(&alive_skbs, &skb);

	return BPF_OK;
}

char __license[] SEC("license") = "Dual BSD/GPL";
