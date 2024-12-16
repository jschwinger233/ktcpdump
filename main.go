package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/jschwinger233/ktcpdump/bpf"
)

func main() {
	spec, err := bpf.LoadBpf()
	if err != nil {
		log.Fatalf("Failed to load BPF: %s\n", err)
	}

	var opts ebpf.CollectionOptions
	opts.Programs.LogLevel = ebpf.LogLevelInstruction
	opts.Programs.LogSize = ebpf.DefaultVerifierLogSize * 100
	objs := bpf.BpfObjects{}
	if err := spec.LoadAndAssign(&objs, &opts); err != nil {
		var (
			ve          *ebpf.VerifierError
			verifierLog string
		)
		if errors.As(err, &ve) {
			verifierLog = fmt.Sprintf("Verifier error: %+v\n", ve)
		}

		log.Fatalf("Failed to load objects: %s\n%+v", verifierLog, err)
	}

	k, err := link.Kprobe("kfree_skbmem", objs.KprobeSkbFree, nil)
	if err != nil {
		log.Fatalf("Failed to attach kfree_skbmem: %+v\n", err)
	}
	defer k.Close()

	k, err = link.Kprobe(os.Args[1], objs.KprobeSkbByStackid, nil)
	if err != nil {
		log.Fatalf("Failed to attach ip_rcv: %+v\n", err)
	}
	defer k.Close()

	targets := []string{}
	btfSpec, err := btf.LoadKernelSpec()
	if err != nil {
		log.Fatalf("Failed to load kernel BTF: %+v\n", err)
	}
	iter := btfSpec.Iterate()
	for iter.Next() {
		typ := iter.Type
		fn, ok := typ.(*btf.Func)
		if !ok {
			continue
		}
		fnProto := fn.Type.(*btf.FuncProto)
		if ptr, ok := fnProto.Return.(*btf.Pointer); ok {
			if strct, ok := ptr.Target.(*btf.Struct); ok {
				if strct.Name == "sk_buff" {
					targets = append(targets, fn.Name)
					continue
				}
			}
		}
	}
	for _, target := range targets {
		kr, err := link.Kretprobe(target, objs.KretprobeSkbBuild, nil)
		if err != nil {
			// skip if not exist
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			log.Fatalf("Failed to attach %s: %+v\n", target, err)
		}
		defer kr.Close()
	}

	eventsReader, err := ringbuf.NewReader(objs.EventRingbuf)
	if err != nil {
		log.Fatalf("Failed to create ringbuf reader: %+v\n", err)
	}
	defer eventsReader.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	go func() {
		<-ctx.Done()
		eventsReader.Close()
	}()
	println("tracing")
	for {
		rec, err := eventsReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("failed to read ringbuf: %+v", err)
			continue
		}

		var event bpf.BpfEvent
		if err = binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("failed to parse ringbuf event: %+v", err)
			continue
		}

		fmt.Printf("skb=%x len=%d\n", event.Skb, event.DataLen)
	}
}
