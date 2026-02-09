# BPF Validation Framework Architecture

## System Flow Diagram

```
┌─────────────────┐
│   User Input    │
│ --protocol tcp  │
│ --dst-port 80   │
│ --src-ip x.x.x  │
└─────────┬───────┘
          │
          ▼
┌─────────────────┐
│   CLI Parser    │
│ • Flag parsing  │
│ • Validation    │
│ • Error handling│
└─────────┬───────┘
          │
          ▼
┌─────────────────┐
│ PacketFilter    │
│ • Protocol      │
│ • Source IP     │
│ • Dest IP       │
│ • Ports         │
└─────────┬───────┘
          │
          ├─────────────────────────────────────┐
          │                                     │
          ▼                                     ▼
┌─────────────────┐                   ┌─────────────────┐
│ tcpdump Ref BPF │                   │ Antrea-style    │
│ Generator       │                   │ BPF Generator   │
│ • Real tcpdump  │                   │ • Fragment-aware│
│ • Mock fallback │                   │ • Optimized     │
│ • Parse output  │                   │ • Structured    │
└─────────┬───────┘                   └─────────┬───────┘
          │                                     │
          │            ┌─────────────────┐      │
          └───────────▶│ Semantic        │◀─────┘
                       │ Comparison      │
                       │ Engine          │
                       │ • Instruction   │
                       │   analysis      │
                       │ • Purpose       │
                       │   matching      │
                       │ • Difference    │
                       │   detection     │
                       └─────────┬───────┘
                                 │
                                 ▼
                       ┌─────────────────┐
                       │ Validation      │
                       │ Report          │
                       │ • Side-by-side  │
                       │ • Score & verdict│
                       │ • Visual output │
                       └─────────────────┘
```

## Component Details

### 1. User Input
- **Purpose**: Command-line interface for filter specification
- **Input**: CLI flags (protocol, IPs, ports)
- **Output**: Raw filter parameters

### 2. CLI Parser
- **Purpose**: Parse and validate user input
- **Functions**: Flag parsing, input validation, error handling
- **Output**: Structured PacketFilter object

### 3. PacketFilter
- **Purpose**: Unified filter representation
- **Structure**: Protocol, source/dest IPs, source/dest ports
- **Validation**: IP format, port ranges, protocol compatibility

### 4. tcpdump Reference BPF Generator
- **Purpose**: Generate "ground truth" BPF using tcpdump
- **Process**: 
  - Convert filter to tcpdump syntax
  - Execute `tcpdump -ddd <filter>`
  - Parse numeric BPF output
- **Fallback**: Mock BPF data when tcpdump unavailable

### 5. Antrea-style BPF Generator
- **Purpose**: Generate optimized BPF using Antrea concepts
- **Features**:
  - Fragment-aware port filtering
  - Structured L2→L3→L4 validation
  - Minimal instruction count
  - Early fail-fast logic

### 6. Semantic Comparison Engine
- **Purpose**: Compare BPF programs by semantic meaning
- **Analysis**:
  - Convert bytecode to semantic instructions
  - Match by purpose (not exact bytecode)
  - Identify missing/extra functionality
  - Calculate similarity score

### 7. Validation Report
- **Purpose**: Present comparison results clearly
- **Format**:
  - Side-by-side visual comparison
  - Color-coded indicators (✓/✗)
  - Numerical score and verdict
  - Key differences summary

## Data Flow

```
Filter Spec → Structured Filter → Parallel BPF Generation → Semantic Analysis → Report
```

## Key Design Principles

1. **Separation of Concerns**: Each component has a single responsibility
2. **Parallel Generation**: tcpdump and Antrea BPF generated independently
3. **Semantic Comparison**: Focus on functional equivalence, not bytecode matching
4. **Visual Feedback**: Clear, scannable output for quick decision-making
5. **Extensibility**: Easy to add new filter types or comparison metrics

## Integration Points

- **Antrea PacketCapture**: Use Antrea-style generator for production BPF
- **Antigravity Tests**: Use comparison engine for automated validation
- **CI/CD Pipeline**: Integrate validation into continuous testing

## Detailed Component Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           BPF Validation Framework                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │    main.go  │    │filter/      │    │tcpdump/     │    │prototype/   │     │
│  │             │    │types.go     │    │generator.go │    │generator.go │     │
│  │ • CLI setup │    │             │    │             │    │             │     │
│  │ • Flag parse│───▶│ • Filter    │───▶│ • Execute   │    │ • BPF       │     │
│  │ • Orchestr. │    │   struct    │    │   tcpdump   │    │   builder   │     │
│  │ • Display   │    │ • Validate  │    │ • Parse     │    │ • Antrea    │     │
│  └─────────────┘    │ • Convert   │    │   output    │    │   logic     │     │
│                     └─────────────┘    └─────────────┘    └─────────────┘     │
│                                                │                   │           │
│                                                ▼                   ▼           │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                    compare/compare.go                                   │   │
│  │                                                                         │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │   │
│  │  │ Semantic    │  │ Instruction │  │ Comparison  │  │ Visual      │   │   │
│  │  │ Analysis    │  │ Matching    │  │ Scoring     │  │ Display     │   │   │
│  │  │             │  │             │  │             │  │             │   │   │
│  │  │ • Parse     │  │ • Purpose   │  │ • Calculate │  │ • Side-by-  │   │   │
│  │  │   opcodes   │  │   based     │  │   score     │  │   side      │   │   │
│  │  │ • Identify  │  │ • Semantic  │  │ • Generate  │  │ • Color     │   │   │
│  │  │   purpose   │  │   equiv.    │  │   verdict   │  │   coded     │   │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## BPF Instruction Flow

```
Raw BPF Instructions
         │
         ▼
┌─────────────────┐
│ Semantic        │
│ Analysis        │
│                 │
│ 0x28 0x0c  →   │ Load Ethernet Type
│ 0x15 0x800 →   │ Check IP Protocol  
│ 0x30 0x17  →   │ Load IP Protocol
│ 0x15 0x06  →   │ Check TCP
│ 0x48 0x10  →   │ Load Dest Port
│ 0x15 0x50  →   │ Check Port 80
│ 0x06 0x40000 → │ Accept Packet
│ 0x06 0x00  →   │ Reject Packet
└─────────────────┘
         │
         ▼
┌─────────────────┐
│ Purpose         │
│ Classification  │
│                 │
│ • IP Validation │
│ • Protocol Check│
│ • Port Filter   │
│ • Accept/Reject │
└─────────────────┘
         │
         ▼
┌─────────────────┐
│ Comparison      │
│ Matrix          │
│                 │
│     TCP  Proto  │
│ ✓    ✓     ✓    │ tcpdump
│ ✓    ✓     ✓    │ prototype
│                 │
│ Score: 100%     │
└─────────────────┘
```

## Error Handling Flow

```
User Input
    │
    ▼
┌─────────────┐    Error    ┌─────────────┐
│ Validation  │────────────▶│ Usage Help  │
│             │             │ & Exit      │
└─────────────┘             └─────────────┘
    │ Valid
    ▼
┌─────────────┐    Error    ┌─────────────┐
│ tcpdump     │────────────▶│ Mock        │
│ Execution   │             │ Fallback    │
└─────────────┘             └─────────────┘
    │ Success
    ▼
┌─────────────┐    Error    ┌─────────────┐
│ BPF         │────────────▶│ Error       │
│ Generation  │             │ Report      │
└─────────────┘             └─────────────┘
    │ Success
    ▼
┌─────────────┐
│ Comparison  │
│ & Report    │
└─────────────┘
```