package main

import (
	"bufio"
	"errors"
	"log"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
)

type Symbol struct {
	Type            string
	Name            string
	Addr            uint64
	AvailableFilter bool
}

const (
	kallsymsPath                 = "/proc/kallsyms"
	availableFilterFunctionsPath = "/sys/kernel/debug/tracing/available_filter_functions"
)

var (
	kallsyms             []*Symbol
	kallsymsByName       map[string]*Symbol  = make(map[string]*Symbol)
	kallsymsByAddr       map[uint64]*Symbol  = make(map[uint64]*Symbol)
	availableFilterFuncs map[string]struct{} = make(map[string]struct{})
)

func init() {
	readKallsyms()
	readAvailableFilterFunctions()

	for _, sym := range kallsyms {
		if _, ok := availableFilterFuncs[sym.Name]; ok {
			sym.AvailableFilter = true
		}
	}
}

func readKallsyms() {
	data, err := os.ReadFile(kallsymsPath)
	if err != nil {
		log.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		addr, err := strconv.ParseUint(parts[0], 16, 64)
		if err != nil {
			continue
		}
		typ, name := parts[1], parts[2]
		symbol := &Symbol{typ, name, addr, false}
		kallsyms = append(kallsyms, symbol)
		kallsymsByName[name] = symbol
		kallsymsByAddr[addr] = symbol
	}
	sort.Slice(kallsyms, func(i, j int) bool {
		return kallsyms[i].Addr < kallsyms[j].Addr
	})
}

func readAvailableFilterFunctions() {
	f, err := os.Open(availableFilterFunctionsPath)
	if err != nil {
		log.Fatalf("Failed to open available_filter_functions: %s\n", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		availableFilterFuncs[scanner.Text()] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("Failed to read available_filter_functions: %s\n", err)
	}
}

func NearestKsym(addr uint64) (this, next *Symbol) {
	idx, _ := slices.BinarySearchFunc(kallsyms, addr, func(x *Symbol, addr uint64) int { return int(x.Addr - addr) })
	if idx == len(kallsyms) {
		return kallsyms[idx-1], nil
	}
	if kallsyms[idx].Addr == addr {
		return kallsyms[idx], kallsyms[idx+1]
	}
	if idx == 0 {
		return kallsyms[0], kallsyms[1]
	}
	return kallsyms[idx-1], kallsyms[idx]
}

func KsymByAddr(addr uint64) (sym *Symbol, err error) {
	sym, ok := kallsymsByAddr[addr]
	if !ok {
		return nil, errors.New("symbol not found")
	}
	return sym, nil
}

func KsymByName(name string) (sym *Symbol, err error) {
	name, err = normalizeKname(name)
	if err != nil {
		return
	}
	return kallsymsByName[name], nil
}

func normalizeKname(name string) (string, error) {
	possibleSuffixes := []string{
		"",
		".cold",
		".constprop.0",
		".constprop.0.cold",
		".constprop.0.isra.0",
		".constprop.0.isra.0.cold",
		".isra.0",
		".isra.0.cold",
		".part.0",
		".part.0.cold",
		".part.0.constprop.0",
		".part.0.isra.0",
		".part.0.isra.0.cold",
	}
	for _, suffix := range possibleSuffixes {
		if _, ok := kallsymsByName[name+suffix]; ok {
			return name + suffix, nil
		}
	}
	return "", errors.New("symbol not found")
}
