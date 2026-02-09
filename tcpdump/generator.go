package tcpdump

import (
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"antrea-bpf-prototype/filter"
)

// BPFInstruction represents a single BPF instruction
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

// BPFCode represents generated BPF bytecode from tcpdump
type BPFCode struct {
	Instructions     []*BPFInstruction // parsed BPF instructions
	RawOutput        string            // raw tcpdump output
	FilterExpr       string            // original tcpdump filter expression
	InstructionCount int               // number of instructions
	IsMocked         bool              // true if using mock data (when tcpdump unavailable)
}

// String returns a formatted representation of the BPF code
func (bpf *BPFCode) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Tcpdump Filter: %s\n", bpf.FilterExpr))
	if bpf.IsMocked {
		sb.WriteString("(Using mock data - tcpdump not available)\n")
	}
	sb.WriteString(fmt.Sprintf("Instructions: %d\n", bpf.InstructionCount))
	sb.WriteString("BPF Bytecode:\n")
	
	for i, inst := range bpf.Instructions {
		sb.WriteString(fmt.Sprintf("  [%2d] %s\n", i, inst.String()))
	}
	
	return sb.String()
}

// GenerateBPF uses tcpdump to generate reference BPF code
func GenerateBPF(f *filter.PacketFilter) (*BPFCode, error) {
	// Convert our filter to tcpdump filter expression
	filterExpr := f.ToTcpdumpFilter()
	if filterExpr == "" {
		return nil, fmt.Errorf("empty filter expression")
	}

	fmt.Printf("=== Tcpdump Reference Generation ===\n")
	fmt.Printf("Filter expression: %s\n", filterExpr)

	// Check if tcpdump is available
	if !isTcpdumpAvailable() {
		fmt.Printf("tcpdump not available on %s, using mock data for demonstration\n", runtime.GOOS)
		return generateMockBPF(filterExpr)
	}

	// Execute tcpdump with -ddd flag to get numeric BPF bytecode
	// -ddd outputs each instruction as a decimal number on separate lines
	cmd := exec.Command("tcpdump", "-ddd", filterExpr)
	
	fmt.Printf("Executing: %s\n", strings.Join(cmd.Args, " "))
	
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("tcpdump failed: %v\nStderr: %s", err, string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("failed to execute tcpdump: %v", err)
	}

	rawOutput := string(output)
	fmt.Printf("Raw tcpdump output:\n%s\n", rawOutput)

	// Parse the tcpdump output
	instructions, err := parseTcpdumpOutput(rawOutput)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tcpdump output: %v", err)
	}

	bpfCode := &BPFCode{
		Instructions:     instructions,
		RawOutput:        rawOutput,
		FilterExpr:       filterExpr,
		InstructionCount: len(instructions),
		IsMocked:         false,
	}

	fmt.Printf("Parsed %d BPF instructions\n", len(instructions))
	return bpfCode, nil
}

// isTcpdumpAvailable checks if tcpdump command is available
func isTcpdumpAvailable() bool {
	_, err := exec.LookPath("tcpdump")
	return err == nil
}

// generateMockBPF creates mock BPF data for demonstration when tcpdump is unavailable
func generateMockBPF(filterExpr string) (*BPFCode, error) {
	// Mock BPF instructions for common filters (simplified examples)
	var instructions []*BPFInstruction
	
	// Basic mock: load ethernet type, check if IP
	instructions = append(instructions, &BPFInstruction{Code: 0x28, JT: 0, JF: 0, K: 0x0000000c}) // ldh [12]
	instructions = append(instructions, &BPFInstruction{Code: 0x15, JT: 0, JF: 8, K: 0x00000800}) // jeq #0x800 jt 2 jf 10
	
	// Add protocol-specific mock instructions
	if strings.Contains(filterExpr, "tcp") {
		instructions = append(instructions, &BPFInstruction{Code: 0x30, JT: 0, JF: 0, K: 0x00000017}) // ldb [23]
		instructions = append(instructions, &BPFInstruction{Code: 0x15, JT: 0, JF: 6, K: 0x00000006}) // jeq #6 jt 4 jf 10
	} else if strings.Contains(filterExpr, "udp") {
		instructions = append(instructions, &BPFInstruction{Code: 0x30, JT: 0, JF: 0, K: 0x00000017}) // ldb [23]
		instructions = append(instructions, &BPFInstruction{Code: 0x15, JT: 0, JF: 6, K: 0x00000011}) // jeq #17 jt 4 jf 10
	}
	
	// Add port filtering mock (simplified)
	if strings.Contains(filterExpr, "port") {
		instructions = append(instructions, &BPFInstruction{Code: 0x28, JT: 0, JF: 0, K: 0x00000014}) // ldh [20]
		instructions = append(instructions, &BPFInstruction{Code: 0x45, JT: 4, JF: 0, K: 0x00001fff}) // jset #0x1fff jt 8 jf 6
		instructions = append(instructions, &BPFInstruction{Code: 0xb1, JT: 0, JF: 0, K: 0x0000000e}) // ldxb 4*([14]&0xf)
		instructions = append(instructions, &BPFInstruction{Code: 0x48, JT: 0, JF: 0, K: 0x0000000e}) // ldh [x + 14]
		
		// Mock port check (port 80 example)
		if strings.Contains(filterExpr, "80") {
			instructions = append(instructions, &BPFInstruction{Code: 0x15, JT: 2, JF: 0, K: 0x00000050}) // jeq #80 jt 10 jf 8
		}
	}
	
	// Return statements
	instructions = append(instructions, &BPFInstruction{Code: 0x06, JT: 0, JF: 0, K: 0x00040000}) // ret #262144
	instructions = append(instructions, &BPFInstruction{Code: 0x06, JT: 0, JF: 0, K: 0x00000000}) // ret #0

	mockOutput := fmt.Sprintf("%d\n", len(instructions))
	for _, inst := range instructions {
		mockOutput += fmt.Sprintf("%d %d %d %d\n", inst.Code, inst.JT, inst.JF, inst.K)
	}

	return &BPFCode{
		Instructions:     instructions,
		RawOutput:        mockOutput,
		FilterExpr:       filterExpr,
		InstructionCount: len(instructions),
		IsMocked:         true,
	}, nil
}

// parseTcpdumpOutput parses the numeric output from tcpdump -ddd
// Format: each line contains 4 decimal numbers: code jt jf k
func parseTcpdumpOutput(output string) ([]*BPFInstruction, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty tcpdump output")
	}

	// First line should contain the number of instructions
	numInstructions, err := strconv.Atoi(strings.TrimSpace(lines[0]))
	if err != nil {
		return nil, fmt.Errorf("invalid instruction count: %v", err)
	}

	if len(lines) != numInstructions+1 {
		return nil, fmt.Errorf("expected %d instructions, got %d lines", numInstructions, len(lines)-1)
	}

	instructions := make([]*BPFInstruction, 0, numInstructions)

	// Parse each instruction line (skip the first line which is the count)
	for i := 1; i <= numInstructions; i++ {
		line := strings.TrimSpace(lines[i])
		parts := strings.Fields(line)
		
		if len(parts) != 4 {
			return nil, fmt.Errorf("invalid instruction format at line %d: %s", i, line)
		}

		// Parse the four components: code, jt, jf, k
		code, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid code at line %d: %v", i, err)
		}

		jt, err := strconv.ParseUint(parts[1], 10, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid jt at line %d: %v", i, err)
		}

		jf, err := strconv.ParseUint(parts[2], 10, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid jf at line %d: %v", i, err)
		}

		k, err := strconv.ParseUint(parts[3], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid k at line %d: %v", i, err)
		}

		instruction := &BPFInstruction{
			Code: uint16(code),
			JT:   uint8(jt),
			JF:   uint8(jf),
			K:    uint32(k),
		}

		instructions = append(instructions, instruction)
	}

	return instructions, nil
}