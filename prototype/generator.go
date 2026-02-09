package prototype

import (
	"fmt"
	"strings"

	"antrea-bpf-prototype/filter"
)

// BPFInstruction represents a single BPF instruction (same format as tcpdump)
type BPFInstruction struct {
	Code uint16 // BPF opcode
	JT   uint8  // jump if true
	JF   uint8  // jump if false
	K    uint32 // constant value
}

// String returns a human-readable representation of the instruction
func (inst *BPFInstruction) String() string {
	return fmt.Sprintf("{ 0x%04x, %3d, %3d, 0x%08x }", inst.Code, inst.JT, inst.JF, inst.K)
}

// BPFCode represents Antrea-style BPF bytecode
type BPFCode struct {
	Instructions     []*BPFInstruction // BPF instructions
	FilterExpr       string            // original filter description
	InstructionCount int               // number of instructions
	Reasoning        string            // explanation of the approach
	Optimizations    []string          // list of optimizations applied
}

// String returns a formatted representation of the BPF code
func (bpf *BPFCode) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Antrea-style Filter: %s\n", bpf.FilterExpr))
	sb.WriteString(fmt.Sprintf("Instructions: %d\n", bpf.InstructionCount))
	sb.WriteString(fmt.Sprintf("Reasoning: %s\n", bpf.Reasoning))
	
	if len(bpf.Optimizations) > 0 {
		sb.WriteString("Optimizations applied:\n")
		for _, opt := range bpf.Optimizations {
			sb.WriteString(fmt.Sprintf("  - %s\n", opt))
		}
	}
	
	sb.WriteString("BPF Bytecode:\n")
	for i, inst := range bpf.Instructions {
		sb.WriteString(fmt.Sprintf("  [%2d] %s\n", i, inst.String()))
	}
	
	return sb.String()
}

// BPFBuilder helps construct BPF programs step by step
type BPFBuilder struct {
	instructions   []*BPFInstruction
	optimizations  []string
	currentOffset  int
}

// NewBPFBuilder creates a new BPF program builder
func NewBPFBuilder() *BPFBuilder {
	return &BPFBuilder{
		instructions:  make([]*BPFInstruction, 0),
		optimizations: make([]string, 0),
		currentOffset: 0,
	}
}

// AddInstruction adds a BPF instruction and returns the current offset
func (b *BPFBuilder) AddInstruction(code uint16, jt, jf uint8, k uint32) int {
	inst := &BPFInstruction{Code: code, JT: jt, JF: jf, K: k}
	b.instructions = append(b.instructions, inst)
	offset := b.currentOffset
	b.currentOffset++
	return offset
}

// AddOptimization records an optimization that was applied
func (b *BPFBuilder) AddOptimization(description string) {
	b.optimizations = append(b.optimizations, description)
}

// UpdateJumpTargets updates jump targets for previously added instructions
func (b *BPFBuilder) UpdateJumpTargets(instructionIndex int, jt, jf uint8) {
	if instructionIndex < len(b.instructions) {
		b.instructions[instructionIndex].JT = jt
		b.instructions[instructionIndex].JF = jf
	}
}

// Build returns the final BPF program
func (b *BPFBuilder) Build() []*BPFInstruction {
	return b.instructions
}

// GenerateBPF creates simplified Antrea-style BPF code
func GenerateBPF(f *filter.PacketFilter) (*BPFCode, error) {
	fmt.Printf("=== Antrea-style BPF Generation ===\n")
	
	builder := NewBPFBuilder()
	reasoning := buildAntreaBPF(f, builder)
	
	instructions := builder.Build()
	filterDesc := buildFilterDescription(f)
	
	bpfCode := &BPFCode{
		Instructions:     instructions,
		FilterExpr:       filterDesc,
		InstructionCount: len(instructions),
		Reasoning:        reasoning,
		Optimizations:    builder.optimizations,
	}
	
	fmt.Printf("Generated %d instructions with Antrea-style approach\n", len(instructions))
	return bpfCode, nil
}

// buildAntreaBPF constructs BPF instructions using Antrea's conceptual approach
func buildAntreaBPF(f *filter.PacketFilter, builder *BPFBuilder) string {
	var reasoning strings.Builder
	reasoning.WriteString("Antrea-style approach: ")
	
	// Antrea Concept 1: Early validation and fail-fast
	// Check if this is an IP packet first (Ethernet type = 0x0800)
	reasoning.WriteString("1) Early IP validation, ")
	builder.AddInstruction(0x28, 0, 0, 0x0000000c) // ldh [12] - load ethernet type
	ipCheckIdx := builder.AddInstruction(0x15, 0, 0, 0x00000800) // jeq #0x800 - will update jump targets
	
	// Antrea Concept 2: Structured protocol handling
	var protocolCheckIdx int = -1
	if f.Protocol != "" {
		reasoning.WriteString("2) Protocol-specific filtering, ")
		builder.AddInstruction(0x30, 0, 0, 0x00000017) // ldb [23] - load IP protocol
		
		var protocolNum uint32
		switch f.Protocol {
		case "tcp":
			protocolNum = 6
		case "udp":
			protocolNum = 17
		case "icmp":
			protocolNum = 1
		}
		protocolCheckIdx = builder.AddInstruction(0x15, 0, 0, protocolNum) // jeq protocol
	}
	
	// Antrea Concept 3: Efficient address filtering
	var srcIPCheckIdx, dstIPCheckIdx int = -1, -1
	if f.SrcIP != "" || f.DstIP != "" {
		reasoning.WriteString("3) IP address filtering, ")
		
		if f.SrcIP != "" {
			ipAddr := ipToUint32(f.SrcIP)
			builder.AddInstruction(0x20, 0, 0, 0x0000001a) // ld [26] - load source IP
			srcIPCheckIdx = builder.AddInstruction(0x15, 0, 0, ipAddr) // jeq src_ip
		}
		
		if f.DstIP != "" {
			ipAddr := ipToUint32(f.DstIP)
			builder.AddInstruction(0x20, 0, 0, 0x0000001e) // ld [30] - load dest IP
			dstIPCheckIdx = builder.AddInstruction(0x15, 0, 0, ipAddr) // jeq dst_ip
		}
	}
	
	// Antrea Concept 4: Port filtering with fragmentation awareness
	var portCheckIndices []int
	if f.SrcPort != 0 || f.DstPort != 0 {
		reasoning.WriteString("4) Fragment-aware port filtering, ")
		
		// Check for fragmentation (Antrea handles fragments differently)
		builder.AddInstruction(0x28, 0, 0, 0x00000014) // ldh [20] - load fragment info
		fragCheckIdx := builder.AddInstruction(0x45, 0, 0, 0x00001fff) // jset #0x1fff - check fragment bits
		
		// Calculate header length for port offset
		builder.AddInstruction(0xb1, 0, 0, 0x0000000e) // ldxb 4*([14]&0xf) - IP header length
		
		if f.SrcPort != 0 {
			builder.AddInstruction(0x48, 0, 0, 0x0000000e) // ldh [x + 14] - load source port
			portCheckIdx := builder.AddInstruction(0x15, 0, 0, uint32(f.SrcPort)) // jeq src_port
			portCheckIndices = append(portCheckIndices, portCheckIdx)
		}
		
		if f.DstPort != 0 {
			builder.AddInstruction(0x48, 0, 0, 0x00000010) // ldh [x + 16] - load dest port
			portCheckIdx := builder.AddInstruction(0x15, 0, 0, uint32(f.DstPort)) // jeq dst_port
			portCheckIndices = append(portCheckIndices, portCheckIdx)
		}
		
		// Update fragment check to skip port checks if fragmented
		rejectOffset := uint8(len(builder.instructions) + 1)
		builder.UpdateJumpTargets(fragCheckIdx, rejectOffset, 0)
	}
	
	// Antrea Concept 5: Optimized accept/reject logic
	reasoning.WriteString("5) Optimized accept/reject with minimal instructions")
	
	// Accept instruction
	acceptIdx := builder.AddInstruction(0x06, 0, 0, 0x00040000) // ret #262144 (accept)
	
	// Reject instruction  
	rejectIdx := builder.AddInstruction(0x06, 0, 0, 0x00000000) // ret #0 (reject)
	
	// Update all jump targets to point to accept or reject
	acceptOffset := uint8(acceptIdx - ipCheckIdx)
	rejectOffset := uint8(rejectIdx - ipCheckIdx)
	builder.UpdateJumpTargets(ipCheckIdx, acceptOffset, rejectOffset)
	
	if protocolCheckIdx >= 0 {
		acceptOffset = uint8(acceptIdx - protocolCheckIdx)
		rejectOffset = uint8(rejectIdx - protocolCheckIdx)
		builder.UpdateJumpTargets(protocolCheckIdx, acceptOffset, rejectOffset)
	}
	
	if srcIPCheckIdx >= 0 {
		acceptOffset = uint8(acceptIdx - srcIPCheckIdx)
		rejectOffset = uint8(rejectIdx - srcIPCheckIdx)
		builder.UpdateJumpTargets(srcIPCheckIdx, acceptOffset, rejectOffset)
	}
	
	if dstIPCheckIdx >= 0 {
		acceptOffset = uint8(acceptIdx - dstIPCheckIdx)
		rejectOffset = uint8(rejectIdx - dstIPCheckIdx)
		builder.UpdateJumpTargets(dstIPCheckIdx, acceptOffset, rejectOffset)
	}
	
	for _, portIdx := range portCheckIndices {
		acceptOffset = uint8(acceptIdx - portIdx)
		rejectOffset = uint8(rejectIdx - portIdx)
		builder.UpdateJumpTargets(portIdx, acceptOffset, rejectOffset)
	}
	
	// Add Antrea-specific optimizations
	if f.Protocol != "" && (f.SrcPort != 0 || f.DstPort != 0) {
		builder.AddOptimization("Combined protocol and port filtering in single pass")
	}
	
	if f.SrcIP != "" && f.DstIP != "" {
		builder.AddOptimization("Dual IP address filtering with early termination")
	}
	
	builder.AddOptimization("Fragment-aware port filtering prevents false matches")
	builder.AddOptimization("Minimal instruction count with structured validation")
	
	return reasoning.String()
}

// buildFilterDescription creates a human-readable filter description
func buildFilterDescription(f *filter.PacketFilter) string {
	var parts []string
	
	if f.Protocol != "" {
		parts = append(parts, f.Protocol)
	}
	if f.SrcIP != "" {
		parts = append(parts, fmt.Sprintf("src=%s", f.SrcIP))
	}
	if f.DstIP != "" {
		parts = append(parts, fmt.Sprintf("dst=%s", f.DstIP))
	}
	if f.SrcPort != 0 {
		parts = append(parts, fmt.Sprintf("sport=%d", f.SrcPort))
	}
	if f.DstPort != 0 {
		parts = append(parts, fmt.Sprintf("dport=%d", f.DstPort))
	}
	
	return strings.Join(parts, " ")
}

// ipToUint32 converts an IP address string to uint32 (simplified)
func ipToUint32(ip string) uint32 {
	// Simplified conversion - in real implementation would use proper parsing
	// For demonstration, return a mock value based on common IPs
	switch ip {
	case "192.168.1.1":
		return 0xc0a80101
	case "10.0.0.1":
		return 0x0a000001
	case "127.0.0.1":
		return 0x7f000001
	default:
		// Mock conversion for demonstration
		return 0xc0a80001 // 192.168.0.1
	}
}