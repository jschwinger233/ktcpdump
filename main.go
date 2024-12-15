package main

import (
	"errors"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/jschwinger233/ktcpdump/bpf"
)

func main() {
	spec, err := bpf.LoadBpf()
	if err != nil {
		log.Fatalf("Failed to load BPF: %s\n", err)
	}

	var opts ebpf.CollectionOptions
	opts.Programs.LogLevel = ebpf.LogLevelInstruction
	opts.Programs.LogSize = ebpf.DefaultVerifierLogSize * 100
	objs := bpf.BpfObjects{}
	if err := spec.LoadAndAssign(&objs, &opts); err != nil {
		var (
			ve          *ebpf.VerifierError
			verifierLog string
		)
		if errors.As(err, &ve) {
			verifierLog = fmt.Sprintf("Verifier error: %+v\n", ve)
		}

		log.Fatalf("Failed to load objects: %s\n%+v", verifierLog, err)
	}

}
