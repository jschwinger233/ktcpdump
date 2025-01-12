package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	log "log/slog"
	"os"
	"os/signal"
	"regexp"
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
		log.Error("Failed to load BPF", "err", err)
		return
	}

	prog, ok := spec.Programs["kprobe_skb_by_search"]
	if !ok {
		log.Error("Failed to find kprobe_skb_by_search")
		return
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
		log.Error("Failed to inject kprobe_pcap_filter_l2", "err", err)
		return
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
			log.Error("Failed to inject kprobe_pcap_filter_l3", "err", err)
			return
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

		log.Error("Failed to load objects", "verifierLog", verifierLog, "err", err)
		return
	}

	k, err := link.Kprobe("kfree_skbmem", objs.KprobeSkbFree, nil)
	if err != nil {
		log.Error("Failed to attach kfree_skbmem", "err", err)
		return
	}
	defer k.Close()

	var attachByLine bool
	for _, target := range config.Targets {
		match := targetPattern.FindStringSubmatch(target)
		result := make(map[string]string)
		for i, name := range targetPattern.SubexpNames() {
			if i != 0 && name != "" {
				result[name] = match[i]
			}
		}
		if result["sym"] != "" && result["addr"] == "" {
			_, ok := IsDigit(result["sym"])
			if ok {
				result["addr"] = result["sym"]
				delete(result, "sym")
			}
		}

		var ok bool
		var err error
		var address uint64
		if result["addr"] == "*" {
			attachByLine = true
			delete(result, "addr")
		}
		if result["addr"] != "" {
			address, ok = IsDigit(result["addr"])
			if !ok {
				log.Error("Invalid address", "addr", result["addr"])
				return
			}
		}

		var symbol string
		var offset uint64
		if result["sym"] == "" && address == 0 {
			log.Error("Invalid target", "target", target)
			return
		} else if result["sym"] == "" && address != 0 {
			sym, _ := NearestKsym(address)
			symbol = sym.Name
			offset = sym.Addr - address
		} else if result["sym"] != "" && address == 0 {
			symbol = result["sym"]
			offset = 0
		} else {
			symbol = result["sym"]
			offset = address
		}
		ksym, err := KsymByName(symbol)
		if err != nil {
			log.Error("Failed to find ksym", "symbol", symbol, "err", err)
			return
		}
		symbol = ksym.Name

		if attachByLine {
			kcore, err := NewKcore()
			if err != nil {
				log.Error("Failed to new kcore", "err", err)
				return
			}
			jumps, err := kcore.FindLines(symbol)
			if err != nil {
				log.Error("Failed to find jumps", "symbol", symbol, "err", err)
				return
			}
			for _, js := range jumps {
				for _, j := range js {
					log.Debug("Attaching", "symbol", symbol, "offset", j)
					k, err := link.Kprobe(symbol, objs.KprobeSkbBySearch, &link.KprobeOptions{Offset: j})
					if err != nil {
						log.Debug("Failed to attach targets", "symbol", symbol, "offset", j, "err", err)
						continue
					}
					defer k.Close()
					break
				}
			}
		} else {
			k, err = link.Kprobe(symbol, objs.KprobeSkbBySearch, &link.KprobeOptions{Offset: offset})
			if err != nil {
				log.Error("Failed to attach", "target", target, "err", err)
				return
			}
			defer k.Close()
		}
	}

	var kdwarf *Kdwarf
	if attachByLine {
		kdwarf, err = GetKdwarf()
		if err != nil {
			log.Error("Failed to get kdwarf", "err", err)
			return
		}
	}

	skbBuildFuncs := []string{}
	btfSpec, err := btf.LoadKernelSpec()
	if err != nil {
		log.Error("Failed to load kernel BTF", "err", err)
		return
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
	for _, skbBuildFunc := range skbBuildFuncs {

		ksym, err := KsymByName(skbBuildFunc)
		if err != nil {
			log.Error("Failed to find ksym", "symbol", skbBuildFunc, "err", err)
			continue
		}
		log.Debug("Attaching", "symbol", ksym.Name)
		kr, err := link.Kretprobe(ksym.Name, objs.KretprobeSkbBuild, nil)
		if err != nil {
			log.Debug("Failed to attach skb build func", "symbol", ksym.Name, "err", err)
			continue
		}
		defer kr.Close()
	}

	eventsReader, err := ringbuf.NewReader(objs.EventRingbuf)
	if err != nil {
		log.Error("Failed to create ringbuf reader", "err", err)
		return
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
		log.Error("Failed to get host info", "err", err)
		return
	}
	bootTime := host.Info().BootTime

	f, err := os.Create(config.PcapFilename)
	if err != nil {
		log.Error("Failed to create pcap file", "err", err)
		return
	}
	defer f.Close()

	pcapw := pcapgo.NewWriter(f)
	linktype := layers.LinkTypeEthernet
	if err = pcapw.WriteFileHeader(1600, linktype); err != nil {
		log.Error("Failed to write pcap file header", "err", err)
		return
	}

	fmt.Printf("%-4s %-18s %-10s %-18s %-16s", "no", "skb", "skb->len", "pc", "ksym")
	if attachByLine {
		fmt.Printf(" addr2line")
	}
	fmt.Println()
	i := 0

	for {
		i++
		rec, err := eventsReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Debug("failed to read ringbuf", "err", err)
			continue
		}

		var event bpf.BpfEvent
		if err = binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &event); err != nil {
			log.Debug("failed to parse ringbuf event", "err", err)
			continue
		}

		if err != nil {
			log.Error("Failed to get dwarf", "err", err)
			return
		}
		sym, _ := NearestKsym(event.At)

		var lineInfo *LineInfo
		if attachByLine {
			lineInfo, err = kdwarf.GetLineInfo(sym.Name, event.At-sym.Addr-1)
			if err != nil {
				lineInfo, err = kdwarf.GetLineInfo(sym.Name, event.At-sym.Addr-4)
			}
		}

		fmt.Printf("%-4d %-18x %-10d %-18x %-16s", i, event.Skb, event.SkbLen, event.At, fmt.Sprintf("%s+%d", sym.Name, event.At-sym.Addr))
		if attachByLine {
			fmt.Printf(" %s:%d", lineInfo.Filename, lineInfo.Line)
		}
		fmt.Println()

		rec, err = eventsReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Debug("failed to read ringbuf", "err", err)
			continue
		}
		skbData := make([]byte, event.DataLen)

		retried := false
	RETRY:
		if err = binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &skbData); err != nil {
			if !retried {
				retried = true
				time.Sleep(time.Millisecond)
				goto RETRY
			} else {
				log.Warn("failed to parse ringbuf skbdata",
					"skb", fmt.Sprintf("%x", event.Skb),
					"data_len", event.DataLen,
					"err", err)
				continue
			}
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
			captureInfo.Length += 14
			captureInfo.CaptureLength += 14

		}
		payload = append(payload, skbData...)
		if err = pcapw.WritePacket(captureInfo, payload); err != nil {
			log.Debug("failed to write packet", "err", err)
		}

	}
}
