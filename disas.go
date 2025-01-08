package main

import (
	"debug/elf"
	"fmt"
	"os"
	"sync"

	"golang.org/x/arch/x86/x86asm"
)

const (
	kcorePath string = "/proc/kcore"
)

var (
	kcoreOnce sync.Once
	kcore     *Kcore
)

type Kcore struct {
	path string
	file *os.File
	elf  *elf.File
}

func NewKcore() (*Kcore, error) {
	file, err := os.Open(kcorePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open kcore: %w", err)
	}
	elf, err := elf.NewFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to open kcore: %w", err)
	}
	return &Kcore{
		path: kcorePath,
		file: file,
		elf:  elf,
	}, nil
}

func GetKcore() (_ *Kcore, err error) {
	kcoreOnce.Do(func() {
		kcore, err = NewKcore()
	})
	return kcore, err
}

func (k *Kcore) FindLines(symbol string) (lineInfos map[LineInfo][]uint64, err error) {
	lineInfos = make(map[LineInfo][]uint64)

	kdwarf, err := GetKdwarf()
	if err != nil {
		return
	}

	ksym, err := KsymByName(symbol)
	if err != nil {
		return
	}
	addr := ksym.Addr
	this, next := NearestKsym(addr)
	leng := next.Addr - this.Addr

	for _, prog := range k.elf.Progs {
		if prog.Vaddr <= addr && prog.Vaddr+prog.Memsz >= addr {
			bytes := make([]byte, leng)
			if _, err = k.file.ReadAt(bytes, int64(prog.Off+addr-prog.Vaddr)); err != nil {
				fmt.Println(err)
			}
			if len(bytes) == 0 {
				continue
			}
			off := 0
			for {
				inst, err := x86asm.Decode(bytes, 64)
				if err != nil {
					inst = x86asm.Inst{Len: 1}
					off += 1
				} else {
					lineInfo, err := kdwarf.GetLineInfo(symbol, uint64(off))
					if err == nil {
						lineInfos[*lineInfo] = append(lineInfos[*lineInfo], uint64(off))
					}
				}

				bytes = bytes[inst.Len:]
				off += inst.Len
				if len(bytes) == 0 {
					break
				}
			}

		}
	}

	return
}
