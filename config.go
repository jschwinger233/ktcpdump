package main

import (
	"fmt"
	log "log/slog"
	"os"
	"strings"

	"github.com/spf13/pflag"
)

type Config struct {
	Pcapfilter   string
	Targets      []string
	PcapFilename string
	Verbose      bool
	DbgImagePath string
}

var config Config

func init() {
	var help bool
	pflag.BoolVarP(&help, "help", "h", false, "")
	pflag.StringSliceVarP(&config.Targets, "i", "i", []string{"ip_rcv", "dev_hard_start_xmit"}, "symbol|symbol+offset|address")
	pflag.StringVarP(&config.PcapFilename, "w", "w", "/tmp/a.pcap", "write packets to a file")
	pflag.BoolVarP(&config.Verbose, "v", "v", false, "verbose output")
	pflag.StringVarP(&config.DbgImagePath, "d", "d", "", "path to debug image")
	pflag.Parse()

	config.Pcapfilter = strings.Join(pflag.Args(), " ")

	if help || len(config.Pcapfilter) == 0 {
		fmt.Fprintf(os.Stderr, "ktcpdump [ -i kfunc ] [ -w file ] [ -d vmlinux-dbg ] [ -v ] expresssion\n")
		pflag.PrintDefaults()
		os.Exit(1)
	}

	if config.Verbose {
		log.SetDefault(log.New(log.NewTextHandler(os.Stdout, &log.HandlerOptions{Level: log.LevelDebug})))
	}
}
