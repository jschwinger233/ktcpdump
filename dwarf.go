package main

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"log"
	"sync"
)

const (
	linuxImageDbgsymPath = "/usr/lib/debug/boot/vmlinux-6.8.0-49-generic"
)

var dwarfData *dwarf.Data

func init() {
	file, err := elf.Open(linuxImageDbgsymPath)
	if err != nil {
		log.Fatalf("failed to open ELF file: %s", err)
	}
	defer file.Close()

	dwarfData, err = file.DWARF()
	if err != nil {
		log.Fatalf("failed to get DWARF data: %s", err)
	}

}

type LineInfo struct {
	Filename string
	Line     int
}

type DWARFParser struct {
	filePath   string
	file       *elf.File
	dwarfData  *dwarf.Data
	lineCache  sync.Map
	cacheMutex sync.Mutex
	loaded     bool
	symbols    map[string]uint64
}

func NewDWARFParser(elfPath string) (*DWARFParser, error) {
	file, err := elf.Open(elfPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open ELF file: %w", err)
	}

	dwarfData, err := file.DWARF()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to get DWARF data: %w", err)
	}

	parser := &DWARFParser{
		file:      file,
		filePath:  elfPath,
		dwarfData: dwarfData,
		symbols:   make(map[string]uint64),
	}
	parser.parseSymbols()
	return parser, nil
}

func (p *DWARFParser) Close() error {
	return nil
}

func (p *DWARFParser) parseSymbols() (err error) {
	// Decode symbols
	symbolTable, err := p.file.Symbols()
	if err != nil {
		return
	}

	// Cache symbol information
	for _, sym := range symbolTable {
		if sym.Name != "" {
			p.symbols[sym.Name] = sym.Value
		}
	}
	println("symbols", len(p.symbols), p.symbols["__fib_validate_source"])
	return nil
}

func (p *DWARFParser) GetLineInfo(symbol string, offset uint64) (*LineInfo, error) {
	address, found := p.symbols[symbol]
	if !found {
		return nil, fmt.Errorf("symbol %s not found in DWARF data", symbol)
	}
	address += offset
	if p.loaded {
		if cached, found := p.lineCache.Load(address); found {
			return cached.(*LineInfo), nil
		}
		return nil, fmt.Errorf("address 0x%x not found in DWARF data", address)
	}

	reader := p.dwarfData.Reader()
	for {
		entry, err := reader.Next()
		if err != nil {
			return nil, fmt.Errorf("error reading DWARF entry: %w", err)
		}
		if entry == nil {
			break
		}

		if entry.Tag == dwarf.TagCompileUnit {
			lineReader, err := p.dwarfData.LineReader(entry)
			if err != nil {
				return nil, fmt.Errorf("failed to get line reader: %w", err)
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
				p.lineCache.Store(lineEntry.Address, info)

			}
		}
	}

	p.loaded = true

	return p.GetLineInfo(symbol, offset)
}
