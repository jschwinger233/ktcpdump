#ifndef __BPF_TIMER_H__
#define __BPF_TIMER_H__

#include "vmlinux.h"

#define CLOCK_MONOTONIC 1
#define CLOCK_BOOTTIME 2
struct bpf_timer {
  __u64 __opaque[2];
} __attribute__((aligned(8)));

struct bpf_dynptr {
  __u64 __opaque[2];
} __attribute__((aligned(8)));

struct bpf_list_head {
  __u64 __opaque[2];
} __attribute__((aligned(8)));

struct bpf_list_node {
  __u64 __opaque[3];
} __attribute__((aligned(8)));

struct bpf_rb_root {
  __u64 __opaque[2];
} __attribute__((aligned(8)));

struct bpf_rb_node {
  __u64 __opaque[4];
} __attribute__((aligned(8)));

struct bpf_refcount {
  __u32 __opaque[1];
} __attribute__((aligned(4)));

struct bpf_iter_num {
  __u64 __opaque[1];
} __attribute__((aligned(8)));

#endif