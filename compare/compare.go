package compare

import (
	"fmt"
	"strings"

	"antrea-bpf-prototype/prototype"
	"antrea-bpf-prototype/tcpdump"
)

// InstructionType represents the semantic purpose of a BPF instruction
type InstructionType int

const (
	LoadEtherType InstructionType = iota
	CheckIP
	LoadProtocol
	CheckProtocol
	LoadSourceIP
	CheckSourceIP
	LoadDestIP
	CheckDestIP
	LoadFragmentInfo
	CheckFragment
	LoadHeaderLength
	LoadSourcePort
	LoadDestPort
	CheckSourcePort
	CheckDestPort
	Accept
	Reject
	Unknown
)

// String returns a human-readable name for the instruction type
func (it InstructionType) String() string {
	names := []string{
		"Load Ethernet Type", "Check IP Protocol", "Load IP Protocol", "Check Protocol",
		"Load Source IP", "Check Source IP", "Load Dest IP", "Check Dest IP",
		"Load Fragment Info", "Check Fragment", "Load Header Length",
		"Load Source Port", "Load Dest Port", "Check Source Port", "Check Dest Port",
		"Accept Packet", "Reject Packet", "Unknown",
	}
	if int(it) < len(names) {
		return names[it]
	}
	return "Unknown"
}

// SemanticInstruction represents the semantic meaning of a BPF instruction
type SemanticInstruction struct {
	Type        InstructionType
	Value       uint32 // The constant value being checked/loaded
	Description string // Human-readable description
	Index       int    // Original instruction index
}

// ComparisonResult represents the result of comparing two BPF programs
type ComparisonResult struct {
	TcpdumpBPF      *tcpdump.BPFCode
	PrototypeBPF    *prototype.BPFCode
	TcpdumpSemantic []*SemanticInstruction
	PrototypeSemantic []*SemanticInstruction
	Matches         []string
	Differences     []string
	MissingInPrototype []string
	ExtraInPrototype   []string
	StructuralDiffs    []string
	Verdict         string
	Score           float64 // 0.0 to 1.0, higher is better match
}

// Compare analyzes differences between tcpdump and prototype BPF
func Compare(tcpBPF *tcpdump.BPFCode, protoBPF *prototype.BPFCode) *ComparisonResult {
	fmt.Printf("=== BPF Comparison Analysis ===\n")
	
	result := &ComparisonResult{
		TcpdumpBPF:   tcpBPF,
		PrototypeBPF: protoBPF,
		Matches:      make([]string, 0),
		Differences:  make([]string, 0),
		MissingInPrototype: make([]string, 0),
		ExtraInPrototype:   make([]string, 0),
		StructuralDiffs:    make([]string, 0),
	}
	
	// Analyze semantic meaning of both programs
	result.TcpdumpSemantic = analyzeTcpdumpSemantics(tcpBPF.Instructions)
	result.PrototypeSemantic = analyzePrototypeSemantics(protoBPF.Instructions)
	
	// Compare semantic structures
	compareSemantics(result)
	
	// Calculate overall score and verdict
	calculateVerdict(result)
	
	fmt.Printf("Comparison complete: %s (Score: %.2f)\n", result.Verdict, result.Score)
	return result
}

// analyzeTcpdumpSemantics converts tcpdump BPF instructions to semantic meaning
func analyzeTcpdumpSemantics(instructions []*tcpdump.BPFInstruction) []*SemanticInstruction {
	semantics := make([]*SemanticInstruction, 0)
	
	for i, inst := range instructions {
		semantic := analyzeInstruction(inst.Code, inst.JT, inst.JF, inst.K, i)
		semantics = append(semantics, semantic)
	}
	
	return semantics
}

// analyzePrototypeSemantics converts prototype BPF instructions to semantic meaning
func analyzePrototypeSemantics(instructions []*prototype.BPFInstruction) []*SemanticInstruction {
	semantics := make([]*SemanticInstruction, 0)
	
	for i, inst := range instructions {
		semantic := analyzeInstruction(inst.Code, inst.JT, inst.JF, inst.K, i)
		semantics = append(semantics, semantic)
	}
	
	return semantics
}

// analyzeInstruction analyzes a single BPF instruction regardless of source
func analyzeInstruction(code uint16, jt, jf uint8, k uint32, index int) *SemanticInstruction {
	semantic := &SemanticInstruction{
		Index: index,
		Value: k,
	}
	
	// Analyze instruction based on opcode and context
	switch code {
	case 0x28: // ldh - load half word
		if k == 0x0000000c {
			semantic.Type = LoadEtherType
			semantic.Description = "Load Ethernet type field"
		} else if k == 0x00000014 {
			semantic.Type = LoadFragmentInfo
			semantic.Description = "Load IP fragment information"
		} else {
			semantic.Type = Unknown
			semantic.Description = fmt.Sprintf("Load half-word from offset 0x%x", k)
		}
		
	case 0x30: // ldb - load byte
		if k == 0x00000017 {
			semantic.Type = LoadProtocol
			semantic.Description = "Load IP protocol field"
		} else {
			semantic.Type = Unknown
			semantic.Description = fmt.Sprintf("Load byte from offset 0x%x", k)
		}
		
	case 0x20: // ld - load word
		if k == 0x0000001a {
			semantic.Type = LoadSourceIP
			semantic.Description = "Load source IP address"
		} else if k == 0x0000001e {
			semantic.Type = LoadDestIP
			semantic.Description = "Load destination IP address"
		} else {
			semantic.Type = Unknown
			semantic.Description = fmt.Sprintf("Load word from offset 0x%x", k)
		}
		
	case 0x48: // ldh [x + offset] - load half word with index
		if k == 0x0000000e {
			semantic.Type = LoadSourcePort
			semantic.Description = "Load source port (with header offset)"
		} else if k == 0x00000010 {
			semantic.Type = LoadDestPort
			semantic.Description = "Load destination port (with header offset)"
		} else {
			semantic.Type = Unknown
			semantic.Description = fmt.Sprintf("Load half-word with offset 0x%x", k)
		}
		
	case 0x15: // jeq - jump if equal
		if k == 0x00000800 {
			semantic.Type = CheckIP
			semantic.Description = "Check if packet is IP (0x800)"
		} else if k == 0x00000006 {
			semantic.Type = CheckProtocol
			semantic.Description = "Check if protocol is TCP (6)"
		} else if k == 0x00000011 {
			semantic.Type = CheckProtocol
			semantic.Description = "Check if protocol is UDP (17)"
		} else if k == 0x00000001 {
			semantic.Type = CheckProtocol
			semantic.Description = "Check if protocol is ICMP (1)"
		} else if k >= 1 && k <= 65535 {
			// Likely a port check
			semantic.Type = CheckDestPort
			semantic.Description = fmt.Sprintf("Check if destination port is %d", k)
		} else if k >= 0xc0000000 { // Likely an IP address
			semantic.Type = CheckSourceIP
			semantic.Description = fmt.Sprintf("Check source IP (0x%08x)", k)
		} else {
			semantic.Type = Unknown
			semantic.Description = fmt.Sprintf("Check if value equals 0x%08x", k)
		}
		
	case 0x45: // jset - jump if bits set
		if k == 0x00001fff {
			semantic.Type = CheckFragment
			semantic.Description = "Check for IP fragmentation"
		} else {
			semantic.Type = Unknown
			semantic.Description = fmt.Sprintf("Check if bits 0x%08x are set", k)
		}
		
	case 0xb1: // ldxb - load byte into index register
		semantic.Type = LoadHeaderLength
		semantic.Description = "Load IP header length into index register"
		
	case 0x06: // ret - return
		if k == 0x00040000 || k > 0 {
			semantic.Type = Accept
			semantic.Description = fmt.Sprintf("Accept packet (return %d bytes)", k)
		} else {
			semantic.Type = Reject
			semantic.Description = "Reject packet (return 0)"
		}
		
	default:
		semantic.Type = Unknown
		semantic.Description = fmt.Sprintf("Unknown instruction: 0x%04x", code)
	}
	
	return semantic
}

// compareSemantics compares the semantic structures of both programs
func compareSemantics(result *ComparisonResult) {
	tcpTypes := make(map[InstructionType]int)
	protoTypes := make(map[InstructionType]int)
	
	// Count instruction types in each program
	for _, sem := range result.TcpdumpSemantic {
		tcpTypes[sem.Type]++
	}
	
	for _, sem := range result.PrototypeSemantic {
		protoTypes[sem.Type]++
	}
	
	// Find matches
	for instType, tcpCount := range tcpTypes {
		if protoCount, exists := protoTypes[instType]; exists {
			if tcpCount == protoCount {
				result.Matches = append(result.Matches, 
					fmt.Sprintf("Both implement %s (%d instructions)", instType.String(), tcpCount))
			} else {
				result.Differences = append(result.Differences,
					fmt.Sprintf("%s: tcpdump has %d, prototype has %d", instType.String(), tcpCount, protoCount))
			}
		} else {
			result.MissingInPrototype = append(result.MissingInPrototype,
				fmt.Sprintf("Missing %s (%d instructions)", instType.String(), tcpCount))
		}
	}
	
	// Find extra instructions in prototype
	for instType, protoCount := range protoTypes {
		if _, exists := tcpTypes[instType]; !exists {
			result.ExtraInPrototype = append(result.ExtraInPrototype,
				fmt.Sprintf("Extra %s (%d instructions)", instType.String(), protoCount))
		}
	}
	
	// Analyze structural differences
	analyzeStructuralDifferences(result)
}

// analyzeStructuralDifferences looks for structural patterns and differences
func analyzeStructuralDifferences(result *ComparisonResult) {
	// Check instruction count difference
	tcpCount := len(result.TcpdumpBPF.Instructions)
	protoCount := len(result.PrototypeBPF.Instructions)
	
	if tcpCount == protoCount {
		result.Matches = append(result.Matches, "Same instruction count")
	} else {
		diff := protoCount - tcpCount
		if diff > 0 {
			result.StructuralDiffs = append(result.StructuralDiffs,
				fmt.Sprintf("Prototype has %d more instructions than tcpdump", diff))
		} else {
			result.StructuralDiffs = append(result.StructuralDiffs,
				fmt.Sprintf("Prototype has %d fewer instructions than tcpdump", -diff))
		}
	}
	
	// Check for fragment handling
	tcpHasFragment := hasInstructionType(result.TcpdumpSemantic, CheckFragment)
	protoHasFragment := hasInstructionType(result.PrototypeSemantic, CheckFragment)
	
	if protoHasFragment && !tcpHasFragment {
		result.StructuralDiffs = append(result.StructuralDiffs,
			"Prototype includes fragment handling that tcpdump mock doesn't have")
	}
	
	// Check for IP address filtering
	tcpHasIPFilter := hasInstructionType(result.TcpdumpSemantic, CheckSourceIP) || 
					  hasInstructionType(result.TcpdumpSemantic, CheckDestIP)
	protoHasIPFilter := hasInstructionType(result.PrototypeSemantic, CheckSourceIP) || 
						hasInstructionType(result.PrototypeSemantic, CheckDestIP)
	
	if protoHasIPFilter && !tcpHasIPFilter {
		result.StructuralDiffs = append(result.StructuralDiffs,
			"Prototype implements IP address filtering")
	}
}

// hasInstructionType checks if a semantic list contains a specific instruction type
func hasInstructionType(semantics []*SemanticInstruction, instType InstructionType) bool {
	for _, sem := range semantics {
		if sem.Type == instType {
			return true
		}
	}
	return false
}

// calculateVerdict determines the overall comparison result
func calculateVerdict(result *ComparisonResult) {
	totalMatches := len(result.Matches)
	totalDifferences := len(result.Differences) + len(result.MissingInPrototype) + len(result.ExtraInPrototype)
	
	// Calculate score based on matches vs differences
	if totalMatches+totalDifferences == 0 {
		result.Score = 0.0
		result.Verdict = "INCONCLUSIVE: No comparable instructions found"
		return
	}
	
	result.Score = float64(totalMatches) / float64(totalMatches+totalDifferences)
	
	// Determine verdict based on score and specific criteria
	if result.Score >= 0.8 {
		result.Verdict = "EXCELLENT MATCH: Prototype closely matches tcpdump behavior"
	} else if result.Score >= 0.6 {
		result.Verdict = "GOOD MATCH: Prototype implements core functionality with some differences"
	} else if result.Score >= 0.4 {
		result.Verdict = "PARTIAL MATCH: Prototype covers some functionality but has significant gaps"
	} else {
		result.Verdict = "POOR MATCH: Prototype differs significantly from tcpdump approach"
	}
	
	// Adjust verdict for important missing functionality
	if len(result.MissingInPrototype) > 0 {
		for _, missing := range result.MissingInPrototype {
			if strings.Contains(missing, "Check IP Protocol") {
				result.Verdict = "CRITICAL ISSUE: " + result.Verdict + " (Missing IP validation)"
				break
			}
		}
	}
}

// Display formats and prints the comparison results
func (r *ComparisonResult) Display() {
	fmt.Printf("\n")
	r.displayHeader()
	r.displaySideBySideComparison()
	r.displayVerdictSummary()
}

// displayHeader shows the main comparison header
func (r *ComparisonResult) displayHeader() {
	fmt.Printf("┌" + strings.Repeat("─", 78) + "┐\n")
	fmt.Printf("│" + centerText("BPF VALIDATION COMPARISON", 78) + "│\n")
	fmt.Printf("├" + strings.Repeat("─", 38) + "┬" + strings.Repeat("─", 39) + "┤\n")
	fmt.Printf("│" + centerText("TCPDUMP REFERENCE", 38) + "│" + centerText("ANTREA PROTOTYPE", 39) + "│\n")
	fmt.Printf("├" + strings.Repeat("─", 38) + "┼" + strings.Repeat("─", 39) + "┤\n")
}

// displaySideBySideComparison shows the main comparison content
func (r *ComparisonResult) displaySideBySideComparison() {
	// Instruction counts
	tcpCount := len(r.TcpdumpBPF.Instructions)
	protoCount := len(r.PrototypeBPF.Instructions)
	
	fmt.Printf("│ Instructions: %-23d │ Instructions: %-23d │\n", tcpCount, protoCount)
	fmt.Printf("│ Filter: %-29s │ Filter: %-29s │\n", 
		truncateString(r.TcpdumpBPF.FilterExpr, 29),
		truncateString(r.PrototypeBPF.FilterExpr, 29))
	
	if r.TcpdumpBPF.IsMocked {
		fmt.Printf("│ Source: Mock Data                    │ Source: Generated                     │\n")
	} else {
		fmt.Printf("│ Source: Real tcpdump                 │ Source: Generated                     │\n")
	}
	
	fmt.Printf("├" + strings.Repeat("─", 38) + "┼" + strings.Repeat("─", 39) + "┤\n")
	
	// Core functionality comparison
	r.displayFunctionalityComparison()
	
	fmt.Printf("├" + strings.Repeat("─", 38) + "┼" + strings.Repeat("─", 39) + "┤\n")
	
	// Key differences
	r.displayKeyDifferences()
	
	fmt.Printf("└" + strings.Repeat("─", 38) + "┴" + strings.Repeat("─", 39) + "┘\n")
}

// displayFunctionalityComparison shows core functionality with indicators
func (r *ComparisonResult) displayFunctionalityComparison() {
	// Create a map of all functionality
	allTypes := make(map[InstructionType]bool)
	tcpTypes := make(map[InstructionType]int)
	protoTypes := make(map[InstructionType]int)
	
	for _, sem := range r.TcpdumpSemantic {
		allTypes[sem.Type] = true
		tcpTypes[sem.Type]++
	}
	
	for _, sem := range r.PrototypeSemantic {
		allTypes[sem.Type] = true
		protoTypes[sem.Type]++
	}
	
	// Core functionality to display
	coreTypes := []InstructionType{
		CheckIP, CheckProtocol, CheckSourceIP, CheckDestIP, 
		CheckSourcePort, CheckDestPort, CheckFragment, Accept, Reject,
	}
	
	for _, instType := range coreTypes {
		if !allTypes[instType] {
			continue
		}
		
		tcpHas := tcpTypes[instType] > 0
		protoHas := protoTypes[instType] > 0
		
		tcpIndicator := getIndicator(tcpHas)
		protoIndicator := getIndicator(protoHas)
		
		funcName := getShortFunctionName(instType)
		
		fmt.Printf("│ %s %-32s │ %s %-32s │\n", 
			tcpIndicator, funcName,
			protoIndicator, funcName)
	}
}

// displayKeyDifferences shows important differences
func (r *ComparisonResult) displayKeyDifferences() {
	fmt.Printf("│" + centerText("KEY DIFFERENCES", 78) + "│\n")
	fmt.Printf("├" + strings.Repeat("─", 78) + "┤\n")
	
	// Show most important differences first
	differences := r.getTopDifferences(4)
	
	if len(differences) == 0 {
		fmt.Printf("│" + centerText("No significant differences found", 78) + "│\n")
	} else {
		for _, diff := range differences {
			fmt.Printf("│ %s %-72s │\n", diff.Icon, diff.Text)
		}
	}
}

// displayVerdictSummary shows the final verdict
func (r *ComparisonResult) displayVerdictSummary() {
	fmt.Printf("\n")
	
	// Score bar
	scoreBar := r.getScoreBar(50)
	fmt.Printf("SCORE: %.1f/10 %s\n", r.Score*10, scoreBar)
	
	// Verdict with color-coded background
	verdictColor := r.getVerdictColor()
	fmt.Printf("\n%s\n", verdictColor)
	
	// Quick stats
	matches := len(r.Matches)
	issues := len(r.Differences) + len(r.MissingInPrototype)
	enhancements := len(r.ExtraInPrototype)
	
	fmt.Printf("\nQUICK STATS: ✓ %d matches  ⚠ %d issues  + %d enhancements\n", 
		matches, issues, enhancements)
	
	// Key takeaway
	fmt.Printf("\nKEY TAKEAWAY: %s\n", r.getKeyTakeaway())
}

// Helper functions

func centerText(text string, width int) string {
	if len(text) >= width {
		return text[:width]
	}
	padding := (width - len(text)) / 2
	return strings.Repeat(" ", padding) + text + strings.Repeat(" ", width-padding-len(text))
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func getIndicator(has bool) string {
	if has {
		return "✓"
	}
	return "✗"
}

func getShortFunctionName(instType InstructionType) string {
	shortNames := map[InstructionType]string{
		CheckIP:         "IP Validation",
		CheckProtocol:   "Protocol Check",
		CheckSourceIP:   "Source IP Filter",
		CheckDestIP:     "Dest IP Filter", 
		CheckSourcePort: "Source Port Filter",
		CheckDestPort:   "Dest Port Filter",
		CheckFragment:   "Fragment Handling",
		Accept:          "Accept Logic",
		Reject:          "Reject Logic",
	}
	
	if name, exists := shortNames[instType]; exists {
		return name
	}
	return instType.String()
}

type Difference struct {
	Icon string
	Text string
	Priority int
}

func (r *ComparisonResult) getTopDifferences(maxCount int) []Difference {
	var diffs []Difference
	
	// High priority: Missing critical functionality
	for _, missing := range r.MissingInPrototype {
		if strings.Contains(missing, "IP Protocol") {
			diffs = append(diffs, Difference{"🚨", "CRITICAL: " + missing, 1})
		} else {
			diffs = append(diffs, Difference{"✗", missing, 3})
		}
	}
	
	// Medium priority: Extra functionality (often good)
	for _, extra := range r.ExtraInPrototype {
		if strings.Contains(extra, "Fragment") || strings.Contains(extra, "IP") {
			diffs = append(diffs, Difference{"✨", "ENHANCEMENT: " + extra, 2})
		} else {
			diffs = append(diffs, Difference{"+", extra, 4})
		}
	}
	
	// Lower priority: Structural differences
	for _, structural := range r.StructuralDiffs {
		diffs = append(diffs, Difference{"⚠", structural, 5})
	}
	
	// Sort by priority and take top items
	if len(diffs) > maxCount {
		diffs = diffs[:maxCount]
	}
	
	return diffs
}

func (r *ComparisonResult) getScoreBar(width int) string {
	filled := int(r.Score * float64(width))
	empty := width - filled
	
	bar := "["
	if r.Score >= 0.8 {
		bar += strings.Repeat("█", filled)
	} else if r.Score >= 0.6 {
		bar += strings.Repeat("▓", filled)
	} else {
		bar += strings.Repeat("▒", filled)
	}
	bar += strings.Repeat("░", empty)
	bar += "]"
	
	return bar
}

func (r *ComparisonResult) getVerdictColor() string {
	if r.Score >= 0.8 {
		return "🟢 VERDICT: " + r.Verdict
	} else if r.Score >= 0.6 {
		return "🟡 VERDICT: " + r.Verdict
	} else {
		return "🔴 VERDICT: " + r.Verdict
	}
}

func (r *ComparisonResult) getKeyTakeaway() string {
	if r.Score >= 0.8 {
		return "Prototype successfully implements tcpdump functionality with valuable enhancements."
	} else if r.Score >= 0.6 {
		return "Prototype covers core functionality but has some implementation differences."
	} else if r.Score >= 0.4 {
		return "Prototype partially implements the required functionality - review needed."
	} else {
		return "Prototype requires significant improvements to match tcpdump behavior."
	}
}