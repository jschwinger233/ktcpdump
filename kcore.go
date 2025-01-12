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

type Instruction struct {
	Symbol     string
	Offset     uint64
	Call       bool
	CallTarget string
	*LineInfo
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

func (k *Kcore) ParseInsns(symbol string) (insns map[uint64]*Instruction, err error) {
	insns = make(map[uint64]*Instruction)
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
					insn := Instruction{
						Symbol: symbol,
						Offset: uint64(off),
					}
					if inst.Op == x86asm.CALL {
						insn.Call = true
						for _, arg := range inst.Args {
							if arg == nil {
								break
							}
							rel, ok := arg.(x86asm.Rel)
							if !ok {
								reg, ok := arg.(x86asm.Reg)
								if ok {
									insn.CallTarget = reg.String()
									break
								}
							}
							callee := addr + uint64(off) + uint64(rel) + uint64(inst.Len)
							ksym, err := KsymByAddr(callee)
							if err == nil {
								insn.CallTarget = ksym.Name
							}
							break
						}
					}
					lineInfo, err := kdwarf.GetLineInfo(symbol, uint64(off))
					if err == nil {
						insn.LineInfo = lineInfo
					}
					insns[uint64(off)] = &insn
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
