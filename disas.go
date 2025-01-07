package main

import (
	"debug/elf"
	"fmt"
	"log"
	"os"
	"sync"

	"golang.org/x/arch/x86/x86asm"
)

var (
	kcore     *os.File
	kcoreElf  *elf.File
	kcoreOnce sync.Once

	kcorePath   string = "/proc/kcore"
	vmlinuxPath string = "/usr/lib/debug/boot/vmlinux-6.8.0-49-generic"

	initOffset uint64
)

func init() {
	kcoreOnce.Do(parseKCore)

}

func parseKCore() {
	var err error
	if kcore, err = os.Open("/proc/kcore"); err != nil {
		log.Fatalf("failed to open /proc/kcore: %s", err)
	}
	if kcoreElf, err = elf.NewFile(kcore); err != nil {
		log.Fatalf("failed to new kcore elf: %s", err)
	}

}

func FindJumps(dwarf *DWARFParser, symbol string) (lineInfos map[LineInfo][]uint64, err error) {
	lineInfos = make(map[LineInfo][]uint64)
	kcoreOnce.Do(parseKCore)

	ksym, err := KsymByName(symbol)
	if err != nil {
		return
	}
	addr := ksym.Addr
	this, next := NearestKsym(addr)
	leng := next.Addr - this.Addr

	for _, prog := range kcoreElf.Progs {
		if prog.Vaddr <= addr && prog.Vaddr+prog.Memsz >= addr {
			bytes := make([]byte, leng)
			if _, err = kcore.ReadAt(bytes, int64(prog.Off+addr-prog.Vaddr)); err != nil {
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
					lineInfo, err := dwarf.GetLineInfo(symbol, uint64(off))
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
