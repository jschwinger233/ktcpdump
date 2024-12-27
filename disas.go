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
)

func parseKCore() {
	var err error
	if kcore, err = os.Open("/proc/kcore"); err != nil {
		log.Fatalf("failed to open /proc/kcore: %s", err)
	}
	if kcoreElf, err = elf.NewFile(kcore); err != nil {
		log.Fatalf("failed to new kcore elf: %s", err)
	}

}

func FindJumps(symbol string) (jumps []uint64, err error) {
	kcoreOnce.Do(parseKCore)

	addr := Kaddr(symbol, false, false)
	this, next := NearestSymbol(addr)
	leng := next.Addr - this.Addr

	jumps = append(jumps, 0)
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
				}
				if inst.Op == x86asm.CALL {
					jumps = append(jumps, uint64(off))
				} else if inst.Op >= x86asm.JA && inst.Op <= x86asm.JS {
					jumps = append(jumps, uint64(off)+uint64(inst.Len))
					for _, arg := range inst.Args {
						if arg == nil {
							break
						}
						rel, ok := arg.(x86asm.Rel)
						if !ok {
							break
						}
						jumps = append(jumps, uint64(off)+uint64(rel)+uint64(inst.Len))
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
