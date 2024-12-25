package main

import (
	"bufio"
	"log"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
)

type Symbol struct {
	Type string
	Name string
	Addr uint64
}

var kallsyms []Symbol
var kallsymsByName map[string]Symbol = make(map[string]Symbol)
var kallsymsByAddr map[uint64]Symbol = make(map[uint64]Symbol)

var availableFilterFuncs map[string]struct{} = make(map[string]struct{})

func init() {
	readKallsyms()
	readAvailableFilterFunctions()
}

func readKallsyms() {
	data, err := os.ReadFile("/proc/kallsyms")
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
		kallsyms = append(kallsyms, Symbol{typ, name, addr})
		kallsymsByName[name] = Symbol{typ, name, addr}
		kallsymsByAddr[addr] = Symbol{typ, name, addr}
	}
	sort.Slice(kallsyms, func(i, j int) bool {
		return kallsyms[i].Addr < kallsyms[j].Addr
	})
}

func RefreshKallsyms() {
	readKallsyms()
}

func NearestSymbol(addr uint64) (Symbol, uint64) {
	idx, _ := slices.BinarySearchFunc(kallsyms, addr, func(x Symbol, addr uint64) int { return int(x.Addr - addr) })
	if idx == len(kallsyms) {
		return kallsyms[idx-1], 0
	}
	if kallsyms[idx].Addr == addr {
		return kallsyms[idx], 0
	}
	if idx == 0 {
		return kallsyms[0], 0
	}
	return kallsyms[idx-1], addr - kallsyms[idx-1].Addr
}

func Kaddr(sym string, maybeSuffix bool, checkAvailability bool) (addr uint64) {
	defer func() {
		if addr != 0 {
			if _, ok := availableFilterFuncs[sym]; !ok && checkAvailability {
				addr = 0
			}
		}
	}()

	if addr := kallsymsByName[sym].Addr; addr != 0 {
		return addr
	}
	if maybeSuffix {
		possibleSuffixes := []string{".cold", ".constprop.0", ".isra"}
		for _, suffix := range possibleSuffixes {
			if addr := kallsymsByName[sym+suffix].Addr; addr != 0 {
				sym = sym + suffix
				return addr
			}
		}

	}
	return
}

func Ksym(addr uint64) string {
	return kallsymsByAddr[addr].Name
}

func FirstKsym() (sym Symbol) {
	for _, sym = range kallsyms {
		if sym.Type == "t" {
			return
		}
	}
	return
}

func LastKsym() (sym Symbol) {
	for i := len(kallsyms) - 1; i >= 0; i-- {
		sym = kallsyms[i]
		if sym.Type == "t" {
			return
		}
	}
	return
}

func readAvailableFilterFunctions() {
	f, err := os.Open("/sys/kernel/debug/tracing/available_filter_functions")
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
