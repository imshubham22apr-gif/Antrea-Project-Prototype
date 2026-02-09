package main

import (
	"flag"
	"fmt"
	"os"

	"antrea-bpf-prototype/compare"
	"antrea-bpf-prototype/filter"
	"antrea-bpf-prototype/prototype"
	"antrea-bpf-prototype/tcpdump"
)

func main() {
	var (
		protocol = flag.String("protocol", "", "Protocol (tcp, udp, icmp)")
		srcIP    = flag.String("src-ip", "", "Source IP address")
		dstIP    = flag.String("dst-ip", "", "Destination IP address")
		srcPort  = flag.Int("src-port", 0, "Source port")
		dstPort  = flag.Int("dst-port", 0, "Destination port")
		help     = flag.Bool("help", false, "Show usage")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Antrea BPF Prototype - Packet Filter Validation\n\n")
		fmt.Fprintf(os.Stderr, "Usage: go run main.go [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  go run main.go --protocol tcp --dst-port 80\n")
		fmt.Fprintf(os.Stderr, "  go run main.go --protocol udp --src-ip 192.168.1.1 --dst-port 53\n")
		fmt.Fprintf(os.Stderr, "  go run main.go --dst-ip 10.0.0.1 --src-port 8080 --dst-port 443\n")
	}

	flag.Parse()

	if *help {
		flag.Usage()
		return
	}

	// Create and validate filter
	f := &filter.PacketFilter{
		Protocol: *protocol,
		SrcIP:    *srcIP,
		DstIP:    *dstIP,
		SrcPort:  *srcPort,
		DstPort:  *dstPort,
	}

	if err := f.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintf(os.Stderr, "Use --help for usage information\n")
		os.Exit(1)
	}

	fmt.Printf("Parsed filter: %s\n\n", f.String())
	
	// Generate tcpdump reference BPF
	tcpdumpBPF, err := tcpdump.GenerateBPF(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate tcpdump BPF: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n%s\n", tcpdumpBPF.String())
	
	// Generate prototype Antrea-style BPF
	prototypeBPF, err := prototype.GenerateBPF(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate prototype BPF: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n%s\n", prototypeBPF.String())
	
	// Compare the results
	comparison := compare.Compare(tcpdumpBPF, prototypeBPF)
	comparison.Display()
}