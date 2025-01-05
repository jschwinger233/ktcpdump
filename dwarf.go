package main

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"log"
	"sync"
)

var dwarfData *dwarf.Data

func init() {
	file, err := elf.Open("/usr/lib/debug/boot/vmlinux-6.8.0-49-generic")
	if err != nil {
		log.Fatalf("failed to open ELF file: %s", err)
	}
	defer file.Close()

	dwarfData, err = file.DWARF()
	if err != nil {
		log.Fatalf("failed to get DWARF data: %s", err)
	}

}

// LineInfo holds the filename and line number for a specific address.
type LineInfo struct {
	Filename string
	Line     int
}

// GetLineInfo reads an ELF file and retrieves the filename and line number for the given address.
func GetLineInfo(address uint64) (*LineInfo, error) {
	reader := dwarfData.Reader()
	for {
		entry, err := reader.Next()
		if err != nil {
			return nil, fmt.Errorf("error reading DWARF entry: %w", err)
		}
		if entry == nil {
			// End of DWARF entries
			break
		}

		if entry.Tag == dwarf.TagCompileUnit {
			// Parse the line table for the compile unit
			lineReader, err := dwarfData.LineReader(entry)
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

				// Check if the address matches
				if lineEntry.Address == address {
					return &LineInfo{
						Filename: lineEntry.File.Name,
						Line:     lineEntry.Line,
					}, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("address 0x%x not found in DWARF data", address)
}

// DWARFParser wraps ELF and DWARF data with caching for performance.
type DWARFParser struct {
	filePath   string
	dwarfData  *dwarf.Data
	lineCache  sync.Map // Cache for address -> LineInfo
	cacheMutex sync.Mutex
	loaded     bool
}

// NewDWARFParser initializes the parser and loads DWARF data.
func NewDWARFParser(elfPath string) (*DWARFParser, error) {
	// Open the ELF file
	file, err := elf.Open(elfPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open ELF file: %w", err)
	}

	// Retrieve the DWARF data
	dwarfData, err := file.DWARF()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to get DWARF data: %w", err)
	}

	return &DWARFParser{
		filePath:  elfPath,
		dwarfData: dwarfData,
	}, nil
}

// Close releases resources (if needed).
func (p *DWARFParser) Close() error {
	// In this example, nothing needs to be closed since we don't keep the ELF file open.
	return nil
}

// GetLineInfo retrieves the filename and line number for a given address.
func (p *DWARFParser) GetLineInfo(address uint64) (*LineInfo, error) {
	// Check cache first
	if p.loaded {
		if cached, found := p.lineCache.Load(address); found {
			return cached.(*LineInfo), nil
		}
		return nil, fmt.Errorf("address 0x%x not found in DWARF data", address)
	}

	// Parse the DWARF line information
	reader := p.dwarfData.Reader()
	for {
		entry, err := reader.Next()
		if err != nil {
			return nil, fmt.Errorf("error reading DWARF entry: %w", err)
		}
		if entry == nil {
			// End of DWARF entries
			break
		}

		if entry.Tag == dwarf.TagCompileUnit {
			// Parse the line table for the compile unit
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

				// Cache the line information for all encountered addresses
				info := &LineInfo{
					Filename: lineEntry.File.Name,
					Line:     lineEntry.Line,
				}
				p.lineCache.Store(lineEntry.Address, info)

				// Return if the address matches
			}
		}
	}

	p.loaded = true

	return p.GetLineInfo(address)

	return nil, fmt.Errorf("address 0x%x not found in DWARF data", address)
}
