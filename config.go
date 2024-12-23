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
	pflag.StringSliceVarP(&config.Targets, "targets", "t", []string{"ip_rcv", "dev_hard_start_xmit"}, "e.g. ip_rcv,dev_hard_start_xmit")
	pflag.StringVarP(&config.PcapFilename, "w", "w", "/tmp/a.pcap", "e.g. /tmp/a.pcap")
	pflag.Parse()

	config.Pcapfilter = strings.Join(pflag.Args(), " ")

	if help || len(config.Pcapfilter) == 0 {
		fmt.Fprintf(os.Stderr, "ktcpdump [ -t kfunc ] [ -w file ] expresssion\n")
		pflag.PrintDefaults()
		os.Exit(1)
	}
}
