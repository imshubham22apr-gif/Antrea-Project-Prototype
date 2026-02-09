package filter

import (
	"fmt"
	"net"
	"strings"
)

// PacketFilter represents a structured packet filtering rule
type PacketFilter struct {
	Protocol string // tcp, udp, icmp (empty means any)
	SrcIP    string // source IP address (empty means any)
	DstIP    string // destination IP address (empty means any)
	SrcPort  int    // source port (0 means any)
	DstPort  int    // destination port (0 means any)
}

// Validate checks if the filter configuration is valid
func (f *PacketFilter) Validate() error {
	// Validate protocol
	if f.Protocol != "" {
		protocol := strings.ToLower(f.Protocol)
		if protocol != "tcp" && protocol != "udp" && protocol != "icmp" {
			return fmt.Errorf("invalid protocol '%s', must be tcp, udp, or icmp", f.Protocol)
		}
		f.Protocol = protocol
	}

	// Validate source IP
	if f.SrcIP != "" {
		if net.ParseIP(f.SrcIP) == nil {
			return fmt.Errorf("invalid source IP address: %s", f.SrcIP)
		}
	}

	// Validate destination IP
	if f.DstIP != "" {
		if net.ParseIP(f.DstIP) == nil {
			return fmt.Errorf("invalid destination IP address: %s", f.DstIP)
		}
	}

	// Validate ports
	if f.SrcPort < 0 || f.SrcPort > 65535 {
		return fmt.Errorf("invalid source port %d, must be 0-65535", f.SrcPort)
	}
	if f.DstPort < 0 || f.DstPort > 65535 {
		return fmt.Errorf("invalid destination port %d, must be 0-65535", f.DstPort)
	}

	// Check if at least one filter criterion is specified
	if f.Protocol == "" && f.SrcIP == "" && f.DstIP == "" && f.SrcPort == 0 && f.DstPort == 0 {
		return fmt.Errorf("at least one filter criterion must be specified")
	}

	// ICMP doesn't use ports
	if f.Protocol == "icmp" && (f.SrcPort != 0 || f.DstPort != 0) {
		return fmt.Errorf("ICMP protocol does not support port filtering")
	}

	return nil
}

// String returns a human-readable representation of the filter
func (f *PacketFilter) String() string {
	var parts []string

	if f.Protocol != "" {
		parts = append(parts, fmt.Sprintf("Protocol: %s", f.Protocol))
	}
	if f.SrcIP != "" {
		parts = append(parts, fmt.Sprintf("Source IP: %s", f.SrcIP))
	}
	if f.DstIP != "" {
		parts = append(parts, fmt.Sprintf("Destination IP: %s", f.DstIP))
	}
	if f.SrcPort != 0 {
		parts = append(parts, fmt.Sprintf("Source Port: %d", f.SrcPort))
	}
	if f.DstPort != 0 {
		parts = append(parts, fmt.Sprintf("Destination Port: %d", f.DstPort))
	}

	return strings.Join(parts, ", ")
}

// ToTcpdumpFilter converts the filter to tcpdump filter syntax
func (f *PacketFilter) ToTcpdumpFilter() string {
	var parts []string

	if f.Protocol != "" {
		parts = append(parts, f.Protocol)
	}

	if f.SrcIP != "" {
		parts = append(parts, fmt.Sprintf("src %s", f.SrcIP))
	}

	if f.DstIP != "" {
		parts = append(parts, fmt.Sprintf("dst %s", f.DstIP))
	}

	if f.SrcPort != 0 {
		parts = append(parts, fmt.Sprintf("src port %d", f.SrcPort))
	}

	if f.DstPort != 0 {
		parts = append(parts, fmt.Sprintf("dst port %d", f.DstPort))
	}

	return strings.Join(parts, " and ")
}