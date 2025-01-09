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

	address, err := strconv.ParseUint(c, 16, 64)
	if err == nil {
		return address, true
	}

	address, err = strconv.ParseUint(c, 10, 64)
	if err == nil {
		return address, true
	}

	return 0, false
}
