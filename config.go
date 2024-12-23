package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/pflag"
)

type Config struct {
	Pcapfilter   string
	Targets      []string
	PcapFilename string
}

var config Config

func init() {
	var help bool
	pflag.BoolVarP(&help, "help", "h", false, "")
	pflag.StringSliceVarP(&config.Targets, "targets", "t", nil, "e.g. ip_rcv,tcp_v4_rcv")
	pflag.StringVarP(&config.PcapFilename, "w", "w", "/tmp/a.pcap", "e.g. /tmp/a.pcap")
	pflag.Parse()

	config.Pcapfilter = strings.Join(pflag.Args(), " ")

	if help || len(config.Targets) == 0 || len(config.Pcapfilter) == 0 {
		fmt.Fprintf(os.Stderr, "ktcpdump -t kfunc [ -w file ] expresssion\n")
		pflag.PrintDefaults()
		os.Exit(1)
	}
}
