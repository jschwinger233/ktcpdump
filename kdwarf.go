package main

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"sync"
)

var (
	kdwarfOnce sync.Once
	kdwarf     *Kdwarf
)

type LineInfo struct {
	Filename string
	Line     int
}

type Kdwarf struct {
	path      string
	file      *elf.File
	dwarfData *dwarf.Data

	lineInfos map[uint64]*LineInfo
	symbols   map[string]uint64
}

func NewKdwarf(path string) (*Kdwarf, error) {
	file, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open ELF file: %w", err)
	}

	dwarfData, err := file.DWARF()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to get DWARF data: %w", err)
	}

	kdwarf := &Kdwarf{
		file:      file,
		path:      path,
		dwarfData: dwarfData,
		symbols:   make(map[string]uint64),
		lineInfos: make(map[uint64]*LineInfo),
	}
	if err := kdwarf.parseSymbols(); err != nil {
		return nil, err
	}
	return kdwarf, kdwarf.parseLineInfos()
}

func GetKdwarf() (_ *Kdwarf, err error) {
	if config.DbgImagePath == "" {
		return nil, fmt.Errorf("-d vmlinux-dbg is required")
	}
	kdwarfOnce.Do(func() {
		kdwarf, err = NewKdwarf(config.DbgImagePath)
	})
	return kdwarf, err
}

func (p *Kdwarf) parseSymbols() (err error) {
	symbolTable, err := p.file.Symbols()
	if err != nil {
		return
	}

	for _, sym := range symbolTable {
		if sym.Name != "" {
			p.symbols[sym.Name] = sym.Value
		}
	}
	return nil
}

func (p *Kdwarf) parseLineInfos() (err error) {
	reader := p.dwarfData.Reader()
	for {
		entry, err := reader.Next()
		if err != nil {
			return fmt.Errorf("error reading DWARF entry: %w", err)
		}
		if entry == nil {
			break
		}

		if entry.Tag == dwarf.TagCompileUnit {
			lineReader, err := p.dwarfData.LineReader(entry)
			if err != nil {
				return fmt.Errorf("failed to get line reader: %w", err)
			}

			var lineEntry dwarf.LineEntry
			for {
				err := lineReader.Next(&lineEntry)
				if err == dwarf.ErrUnknownPC {
					continue
				}
				if err != nil {
					break
				}

				info := &LineInfo{
					Filename: lineEntry.File.Name,
					Line:     lineEntry.Line,
				}
				p.lineInfos[lineEntry.Address] = info

			}
		}
	}
	return
}

func (p *Kdwarf) GetLineInfo(symbol string, offset uint64) (*LineInfo, error) {
	address, found := p.symbols[symbol]
	if !found {
		return nil, fmt.Errorf("symbol %s not found in DWARF data", symbol)
	}

	address += offset

	if lineInfo, found := p.lineInfos[address]; found {
		return lineInfo, nil
	}
	return nil, fmt.Errorf("address 0x%x not found in DWARF data", address)
}
