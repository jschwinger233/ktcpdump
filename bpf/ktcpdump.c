// +build ignore
// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

#define MAX_STACK_DEPTH 50
#define MAX_DATA_SIZE 9000
#define MAX_TRACK_SIZE 10240

const static u32 ZERO = 0;
const static u8 TRUE = 1;

struct event {
	u64 at;
	u64 ts;
	u64 skb;
	u64 call;
	u32 data_len;
	u16 protocol;
	u8 has_mac;
	u8 dev[16];
};

const struct event *_ __attribute__((unused));

struct skb_data {
	u8 data[MAX_DATA_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u8[MAX_DATA_SIZE + sizeof(struct event)]);
	__uint(max_entries, 1);
} ringbuf_data SEC(".maps");

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

static __noinline bool
kprobe_pcap_filter_l3(void *_skb, void *__skb, void *___skb, void *data, void* data_end)
{
	return data != data_end && _skb == __skb && __skb == ___skb;
}

static __noinline bool
kprobe_pcap_filter_l2(void *_skb, void *__skb, void *___skb, void *data, void* data_end)
{
	return data != data_end && _skb == __skb && __skb == ___skb;
}

static __always_inline bool
kprobe_pcap_filter(struct sk_buff *skb, u8 *has_mac, u16 *off_l2_or_l3)
{
	void *skb_head = BPF_CORE_READ(skb, head);
	void *data_end = skb_head + BPF_CORE_READ(skb, tail);

	u16 mac_header = BPF_CORE_READ(skb, mac_header);
	u16 network_header = BPF_CORE_READ(skb, network_header);
	*has_mac = BPF_CORE_READ(skb, dev, hard_header_len) && mac_header < network_header ? 1 : 0;
	*off_l2_or_l3 = *has_mac ? mac_header : network_header;

	if (!*has_mac) {
		void *data = skb_head + BPF_CORE_READ(skb, network_header);
		return kprobe_pcap_filter_l3((void *)skb, (void *)skb, (void *)skb,
					     data, data_end);
	}

	void *data = skb_head + BPF_CORE_READ(skb, mac_header);
	return kprobe_pcap_filter_l2((void *)skb, (void *)skb, (void *)skb,
				     data, data_end);
}

static __always_inline void
get_call_target(struct pt_regs *ctx, u64 *call, u64 cookie)
{
	switch (cookie) {
	case 1:
		BPF_CORE_READ_INTO(call, ctx, r15);
		break;
	case 2:
		BPF_CORE_READ_INTO(call, ctx, r14);
		break;
	case 3:
		BPF_CORE_READ_INTO(call, ctx, r13);
		break;
	case 4:
		BPF_CORE_READ_INTO(call, ctx, r12);
		break;
	case 5:
		BPF_CORE_READ_INTO(call, ctx, bp);
		break;
	case 6:
		BPF_CORE_READ_INTO(call, ctx, bx);
		break;
	case 7:
		BPF_CORE_READ_INTO(call, ctx, r11);
		break;
	case 8:
		BPF_CORE_READ_INTO(call, ctx, r10);
		break;
	case 9:
		BPF_CORE_READ_INTO(call, ctx, r9);
		break;
	case 10:
		BPF_CORE_READ_INTO(call, ctx, r8);
		break;
	case 11:
		BPF_CORE_READ_INTO(call, ctx, ax);
		break;
	case 12:
		BPF_CORE_READ_INTO(call, ctx, cx);
		break;
	case 13:
		BPF_CORE_READ_INTO(call, ctx, dx);
		break;
	case 14:
		BPF_CORE_READ_INTO(call, ctx, si);
		break;
	case 15:
		BPF_CORE_READ_INTO(call, ctx, di);
		break;
	default:
		*call = 0;
	}
}

SEC("kprobe/skb_by_search")
int kprobe_skb_by_search(struct pt_regs *ctx)
{
	struct sk_buff *skb;

	skb = (struct sk_buff *)search_skb_from_register(ctx);
	if (!skb)
		skb = (struct sk_buff *)search_skb_from_stack(ctx);
	if (!skb)
		return BPF_OK;

	u8 has_mac;
	u16 off_l2_or_l3;
	if (!kprobe_pcap_filter(skb, &has_mac, &off_l2_or_l3))
		return BPF_OK;

	void *ringbuf = bpf_map_lookup_elem(&ringbuf_data, &ZERO);
	if (!ringbuf)
		return BPF_OK;

	struct event *event = (struct event *)ringbuf;

	event->at = PT_REGS_IP(ctx);
	event->ts = bpf_ktime_get_boot_ns();
	event->skb = (u64)skb;
	event->has_mac = has_mac;
	event->protocol = BPF_CORE_READ(skb, protocol);
	BPF_CORE_READ_STR_INTO(&event->dev, skb, dev, name);
	get_call_target(ctx, &event->call, bpf_get_attach_cookie(ctx));

	event->data_len = BPF_CORE_READ(skb, tail) - (u32)off_l2_or_l3;
	event->data_len = event->data_len > MAX_DATA_SIZE
		? MAX_DATA_SIZE
		: event->data_len;

	u32 data_len = event->data_len;

	struct skb_data *skb_data = (struct skb_data *)(event + 1);

	void *skb_head = BPF_CORE_READ(skb, head);

	bpf_probe_read_kernel(&skb_data->data, data_len, (void *)(skb_head + off_l2_or_l3));
	bpf_ringbuf_output(&event_ringbuf, ringbuf, sizeof(*event) + data_len, 0);

	return BPF_OK;
}

SEC("kretprobe/skb_build")
int kretprobe_skb_build(struct pt_regs *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_RC(ctx);
	bpf_map_update_elem(&alive_skbs, &skb, &TRUE, BPF_ANY);
	return BPF_OK;
}

SEC("kprobe/skb_free")
int kprobe_skb_free(struct pt_regs *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	bpf_map_delete_elem(&alive_skbs, &skb);

	return BPF_OK;
}

char __license[] SEC("license") = "Dual BSD/GPL";
