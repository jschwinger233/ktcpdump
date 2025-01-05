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

	initOffset uint64 = 0x20a00000
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

func FindJumps2(symbol string) (jumps []uint64, err error) {
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

func getAsm(addr uint64) string {
	kcoreOnce.Do(parseKCore)

	for _, prog := range kcoreElf.Progs {
		if prog.Vaddr <= addr && prog.Vaddr+prog.Memsz >= addr {
			bytes := make([]byte, 64)
			if _, err := kcore.ReadAt(bytes, int64(prog.Off+addr-prog.Vaddr)); err != nil {
				log.Fatalf("failed to read kcore %v", err)
			}
			if len(bytes) == 0 {
				log.Fatalf("failed to read kcore")
			}
			inst, err := x86asm.Decode(bytes, 64)
			if err != nil {
				log.Fatalf("failed to decode: %s", err)
			}
			if inst.Op == x86asm.CALL {
				for _, arg := range inst.Args {
					if arg == nil {
						break
					}
					rel, ok := arg.(x86asm.Rel)
					if !ok {
						break
					}
					callees := addr + uint64(rel) + uint64(inst.Len)
					return fmt.Sprintf("call %s", Ksym(callees))
				}
			} else {
				return inst.String()
			}
			if len(bytes) == 0 {
				break
			}
		}
	}

	return ""
}

func FindJumps(dwarf *DWARFParser, symbol string) (jumps []uint64, err error) {
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
			lineInfos := make(map[LineInfo]uint64)
			for {
				inst, err := x86asm.Decode(bytes, 64)
				if err != nil {
					inst = x86asm.Inst{Len: 1}
					off += 1
				} else {
					curAddr := addr + uint64(off)
					lineInfo, err := dwarf.GetLineInfo(curAddr - initOffset)
					//println("lineInfo:", lineInfo)
					if err == nil {
						_, ok := lineInfos[*lineInfo]
						if !ok {
							lineInfos[*lineInfo] = uint64(off)
							//fmt.Printf("0x%x: %s:%d\n", curAddr-initOffset, lineInfo.Filename, lineInfo.Line)
						}
					}
				}

				bytes = bytes[inst.Len:]
				off += inst.Len
				if len(bytes) == 0 {
					break
				}
			}

			//println(len(lineInfos))
			for _, a := range lineInfos {
				jumps = append(jumps, a)
			}
		}
	}

	return
}
