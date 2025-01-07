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

	kcoreElf, err := elf.NewFile(kcore)
	if err != nil {
		log.Fatalf("Failed to parse ELF file %s: %v", "/proc/kcore", err)
	}

	vmlinuxFile, err := os.Open(vmlinuxPath)
	if err != nil {
		log.Fatalf("Failed to open %s: %v", vmlinuxPath, err)
	}
	defer vmlinuxFile.Close()

	vmlinuxElf, err := elf.NewFile(vmlinuxFile)
	if err != nil {
		log.Fatalf("Failed to parse ELF file %s: %v", vmlinuxPath, err)
	}

	var vmlinuxBaseAddr uint64
	for _, prog := range vmlinuxElf.Progs {
		if prog.Type == elf.PT_LOAD {
			vmlinuxBaseAddr = prog.Vaddr
			break
		}
	}
	if vmlinuxBaseAddr == 0 {
		log.Fatalf("Failed to find the first LOAD segment in %s", vmlinuxPath)
	}

	var kcoreBaseAddr uint64
	for _, prog := range kcoreElf.Progs {
		if prog.Type == elf.PT_LOAD {
			kcoreBaseAddr = prog.Vaddr
			break
		}
	}
	if kcoreBaseAddr == 0 {
		log.Fatalf("Failed to find the first LOAD segment in %s", kcorePath)
	}

	kaslrOffset := kcoreBaseAddr - vmlinuxBaseAddr
	println("kaslrOffset:", kaslrOffset)
	initOffset = kaslrOffset
	initOffset = 0x23e03530
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
					curAddr := addr + uint64(off)
					lineInfo, err := dwarf.GetLineInfo(curAddr - initOffset)
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
