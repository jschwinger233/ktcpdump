package main

import (
	"strconv"
	"strings"
)

func IsDigit(c string) (uint64, bool) {
	if strings.HasPrefix(c, "0x") {
		address, err := strconv.ParseUint(c[2:], 16, 64)
		if err == nil {
			return address, true
		}
	}

	address, err := strconv.ParseUint(c, 10, 64)
	if err == nil {
		return address, true
	}

	address, err = strconv.ParseUint(c, 16, 64)
	if err == nil {
		return address, true
	}

	return 0, false
}

func RegisterToCookie(register string) (cookie uint64) {
	switch register {
	case "R15":
		cookie = 1
	case "R14":
		cookie = 2
	case "R13":
		cookie = 3
	case "R12":
		cookie = 4
	case "RBP":
		cookie = 5
	case "RBX":
		cookie = 6
	case "R11":
		cookie = 7
	case "R10":
		cookie = 8
	case "R9":
		cookie = 9
	case "R8":
		cookie = 10
	case "RAX":
		cookie = 11
	case "RCX":
		cookie = 12
	case "RDX":
		cookie = 13
	case "RSI":
		cookie = 14
	case "RDI":
		cookie = 15
	}
	return
}
