// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package bpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type BpfEvent struct {
	At       uint64
	Ts       uint64
	Skb      uint64
	Call     uint64
	DataLen  uint32
	Protocol uint16
	HasMac   uint8
	Dev      [16]uint8
	_        [1]byte
}

// LoadBpf returns the embedded CollectionSpec for Bpf.
func LoadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load Bpf: %w", err)
	}

	return spec, err
}

// LoadBpfObjects loads Bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*BpfObjects
//	*BpfPrograms
//	*BpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// BpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfSpecs struct {
	BpfProgramSpecs
	BpfMapSpecs
}

// BpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfProgramSpecs struct {
	KprobeSkbBySearch *ebpf.ProgramSpec `ebpf:"kprobe_skb_by_search"`
	KprobeSkbFree     *ebpf.ProgramSpec `ebpf:"kprobe_skb_free"`
	KretprobeSkbBuild *ebpf.ProgramSpec `ebpf:"kretprobe_skb_build"`
}

// BpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfMapSpecs struct {
	AliveSkbs    *ebpf.MapSpec `ebpf:"alive_skbs"`
	EventRingbuf *ebpf.MapSpec `ebpf:"event_ringbuf"`
	RingbufData  *ebpf.MapSpec `ebpf:"ringbuf_data"`
}

// BpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfObjects struct {
	BpfPrograms
	BpfMaps
}

func (o *BpfObjects) Close() error {
	return _BpfClose(
		&o.BpfPrograms,
		&o.BpfMaps,
	)
}

// BpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfMaps struct {
	AliveSkbs    *ebpf.Map `ebpf:"alive_skbs"`
	EventRingbuf *ebpf.Map `ebpf:"event_ringbuf"`
	RingbufData  *ebpf.Map `ebpf:"ringbuf_data"`
}

func (m *BpfMaps) Close() error {
	return _BpfClose(
		m.AliveSkbs,
		m.EventRingbuf,
		m.RingbufData,
	)
}

// BpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfPrograms struct {
	KprobeSkbBySearch *ebpf.Program `ebpf:"kprobe_skb_by_search"`
	KprobeSkbFree     *ebpf.Program `ebpf:"kprobe_skb_free"`
	KretprobeSkbBuild *ebpf.Program `ebpf:"kretprobe_skb_build"`
}

func (p *BpfPrograms) Close() error {
	return _BpfClose(
		p.KprobeSkbBySearch,
		p.KprobeSkbFree,
		p.KretprobeSkbBuild,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_x86_bpfel.o
var _BpfBytes []byte
