package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	// TODO: slog
	"log"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/elastic/go-sysinfo"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/jschwinger233/elibpcap"
	"github.com/jschwinger233/ktcpdump/bpf"
)

var targetPattern *regexp.Regexp

func init() {
	targetPattern = regexp.MustCompile(`(?P<sym>[^+]*)(?:\+(?P<addr>.+))?`)
}

func main() {
	spec, err := bpf.LoadBpf()
	if err != nil {
		log.Fatalf("Failed to load BPF: %s\n", err)
	}

	prog, ok := spec.Programs["kprobe_skb_by_search"]
	if !ok {
		log.Fatalf("Failed to find kprobe_skb_by_search\n")
	}
	if prog.Instructions, err = elibpcap.Inject(
		config.Pcapfilter,
		prog.Instructions,
		elibpcap.Options{
			AtBpf2Bpf:  "kprobe_pcap_filter_l2",
			DirectRead: false,
			L2Skb:      true,
		},
	); err != nil {
		log.Fatalf("Failed to inject kprobe_pcap_filter_l2: %s\n", err)
	}
	if prog.Instructions, err = elibpcap.Inject(
		config.Pcapfilter,
		prog.Instructions,
		elibpcap.Options{
			AtBpf2Bpf:  "kprobe_pcap_filter_l3",
			DirectRead: false,
			L2Skb:      false,
		},
	); err != nil && strings.Contains(fmt.Sprintf("%+v", err), "expression rejects all packets") {
		if prog.Instructions, err = elibpcap.Inject(
			"__reject_all__",
			prog.Instructions,
			elibpcap.Options{
				AtBpf2Bpf:  "kprobe_pcap_filter_l3",
				DirectRead: false,
				L2Skb:      false,
			},
		); err != nil {
			log.Fatalf("Failed to inject kprobe_pcap_filter_l3: %s\n", err)
		}
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

	asms := map[uint64]string{}

	for _, target := range config.Targets {
		match := targetPattern.FindStringSubmatch(target)
		result := make(map[string]string)
		for i, name := range targetPattern.SubexpNames() {
			if i != 0 && name != "" {
				result[name] = match[i]
			}
		}
		if result["sym"] != "" && result["addr"] == "" {
			_, err := strconv.Atoi(result["sym"])
			isDigit := err == nil
			if strings.HasPrefix(result["sym"], "0x") || isDigit {
				result["addr"] = result["sym"]
				delete(result, "sym")
			}
		}

		var address uint64
		var err error
		var attachJumps bool
		if result["addr"] == "*" {
			attachJumps = true
			delete(result, "addr")
		}
		if result["addr"] != "" {
			if strings.HasPrefix(result["addr"], "0x") {
				address, err = strconv.ParseUint(result["addr"][2:], 16, 64)
			} else {
				address, err = strconv.ParseUint(result["addr"], 10, 64)
			}
			if err != nil {
				log.Fatalf("Invalid address: %s\n", result["addr"])
			}
		}

		var symbol string
		var offset uint64
		if result["sym"] == "" && address == 0 {
			log.Fatalf("Invalid target: %s\n", target)
		} else if result["sym"] == "" && address != 0 {
			sym, _ := NearestSymbol(address)
			symbol = sym.Name
			offset = sym.Addr - address
		} else if result["sym"] != "" && address == 0 {
			symbol = result["sym"]
			offset = 0
		} else {
			symbol = result["sym"]
			offset = address
		}

		a := Kaddr(symbol, false, false)
		if attachJumps {
			jumps, err := FindJumps(symbol)
			if err != nil {
				log.Fatalf("Failed to find jumps for %s: %s\n", symbol, err)
			}
			for _, jump := range jumps {

				println("symbol:", symbol, "offset:", jump)
				if _, ok := asms[a+jump]; ok {
					continue
				}
				asms[a+jump] = getAsm(a + jump)
				k, err := link.Kprobe(symbol, objs.KprobeSkbBySearch, &link.KprobeOptions{Offset: jump})
				if err != nil {
					log.Fatalf("Failed to attach targets %s+%d: %+v\n", symbol, jump, err)
				}
				defer k.Close()
			}
		} else {
			// TODO: --verbose
			println("symbol:", symbol, "offset:", offset)

			asms[a+offset] = getAsm(a + offset)
			k, err = link.Kprobe(symbol, objs.KprobeSkbBySearch, &link.KprobeOptions{Offset: offset})
			if err != nil {
				log.Fatalf("Failed to attach targets %s: %+v\n", target, err)
			}
			defer k.Close()
		}
	}

	skbBuildFuncs := []string{}
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
					skbBuildFuncs = append(skbBuildFuncs, fn.Name)
					continue
				}
			}
		}
	}
	skbBuildAddrs := make([]uintptr, 0, len(skbBuildFuncs))
	for _, skbBuildFunc := range skbBuildFuncs {
		addr := Kaddr(skbBuildFunc, true, true)
		if addr == 0 {
			// TODO: fallback to kprobe
			println("Symbol not found for skb build:", skbBuildFunc)
			continue
		}
		skbBuildAddrs = append(skbBuildAddrs, uintptr(addr))
	}
	kr, err := link.KretprobeMulti(objs.KretprobeSkbBuild, link.KprobeMultiOptions{Addresses: skbBuildAddrs})
	if err != nil {
		log.Fatalf("Failed to attach skb build funcs: %+v\n", err)
	}
	defer kr.Close()

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

	host, err := sysinfo.Host()
	if err != nil {
		log.Fatalf("Failed to get host info: %s\n", err)
	}
	bootTime := host.Info().BootTime

	f, err := os.Create(config.PcapFilename)
	if err != nil {
		log.Fatalf("Failed to create pcap file: %s\n", err)
	}
	defer f.Close()

	pcapw := pcapgo.NewWriter(f)
	linktype := layers.LinkTypeEthernet
	if err = pcapw.WriteFileHeader(1600, linktype); err != nil {
		log.Fatalf("Failed to write pcap file header: %s\n", err)
	}

	fmt.Printf("%-4s %-18s %-10s %-18s %-16s %s\n", "no", "skb", "skb->len", "pc", "location", "asm")
	i := 0

	for {
		i++
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

		sym, _ := NearestSymbol(event.At)
		asm := asms[event.At-1]
		if asm == "" {
			asm = asms[event.At-4]
		}
		fmt.Printf("%-4d %-18x %-10d %-18x %-16s %s\n", i, event.Skb, event.SkbLen, event.At, fmt.Sprintf("%s+%d", sym.Name, event.At-sym.Addr), asm)

		rec, err = eventsReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("failed to read ringbuf: %+v", err)
			continue
		}
		skbData := make([]byte, event.DataLen)
		if err = binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &skbData); err != nil {
			log.Printf("failed to parse ringbuf skbdata: %v", err)
			continue
		}

		captureInfo := gopacket.CaptureInfo{
			Timestamp:     bootTime.Add(time.Duration(event.Ts)),
			CaptureLength: int(event.DataLen),
			Length:        int(event.DataLen),
		}
		payload := []byte{}

		if event.HasMac == 0 {
			for i := 0; i < 12; i++ {
				payload = append(payload, 0)
			}
			ethertype := make([]byte, 2)
			binary.BigEndian.PutUint16(ethertype, uint16(event.Protocol))
			payload = append(payload, ethertype[1], ethertype[0])

		}
		payload = append(payload, skbData...)
		if err = pcapw.WritePacket(captureInfo, payload); err != nil {
			log.Printf("failed to write packet: %v", err)
		}

	}
}
