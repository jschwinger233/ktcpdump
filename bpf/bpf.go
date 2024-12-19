package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native -type event -type skb_data Bpf ./ktcpdump.c -- -I./headers -I. -Wall
