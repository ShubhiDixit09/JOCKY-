# JOCKY: Just-in-time Operational Computer & Network Knowledge/Yield framework
*An Authorized Domain-Specific Language, Compiler, and Distributed Engine for Cross-Platform Digital Forensics and Security Telemetry Research*

---

## Overview

**JOCKY** is an authorized cybersecurity research platform and Domain-Specific Language (DSL) designed for digital forensics, incident response (DFIR), and threat detection research across Windows and Linux endpoints.

### Key Capabilities
- **Capability-Governed DSL**: Fine-grained permissions (`process.read`, `memory.read`, `driver.read`, `network.read`) verified at compile time and enforced at runtime.
- **Read-Only Forensic Invariants**: Provable isolation guaranteeing zero host state mutation or unmanaged tampering.
- **Memory Forensics & Anomaly Detection**: Live scanning of Virtual Address Descriptors (VAD) for unbacked executable memory (`MEM_PRIVATE` + `EXECUTE`) characteristic of reflective DLL injection and process hollowing.
- **BYOVD Threat Detection**: Direct inspection of loaded kernel drivers, Authenticode WHQL verification, and correlation against the **LOLDrivers** catalog.
- **Evidence Integrity**: Merkle tree root computation, SHA-256 evidence hashing, and export to **CASE (JSON-LD)** and **STIX 2.1** formats.
- **Safe Laboratory Emulation**: Harmless synthetic telemetry generators allowing researchers to benchmark detection rules without deploying malicious payloads.

---

## Workspace Structure

```
.
├── Cargo.toml                    # Rust workspace manifest
├── crates/
│   ├── jocky-ast/                # Abstract Syntax Tree & Type definitions
│   ├── jocky-parser/             # Logos lexer & Pratt expression parser
│   ├── jocky-ir/                 # SSA IR, capability verifier, filter pushdown
│   ├── jocky-crypto/             # Merkle tree, evidence packaging, CASE/STIX
│   ├── jocky-agent/              # Windows & Linux native forensic collectors
│   ├── jocky-lab/                # Benign laboratory adversary emulation
│   └── jocky-cli/                # Command line interface & compiler runner
├── docs/
│   ├── GRAMMAR.ebnf              # Formal EBNF language grammar
│   ├── LITERATURE_REVIEW.md      # Annotated review of 10 peer-reviewed papers
│   └── ARCHITECTURE_SPECIFICATION.md # Full 16-section technical architecture
└── examples/
    ├── detect_byovd.jky          # BYOVD detection script
    ├── detect_unbacked_memory.jky# Memory injection detection script
    └── correlate_incident.jky    # Multi-stage temporal correlation script
```

---

## CLI Usage

### 1. Check & Validate a JOCKY Script
```bash
cargo run --bin jocky -- check examples/detect_byovd.jky
```

### 2. Audit Capabilities Requested
```bash
cargo run --bin jocky -- audit examples/detect_unbacked_memory.jky
```

### 3. Run Investigation Query & Export CASE JSON-LD Evidence
```bash
cargo run --bin jocky -- run examples/detect_byovd.jky
```

### 4. Execute Safe Laboratory Adversary Emulation
```bash
cargo run --bin jocky -- lab-simulate
```

---

## Safety & Defensive Compliance
JOCKY is designed strictly in compliance with ISO/IEC 27037 digital evidence standards, the Computer Fraud and Abuse Act (CFAA), and ethical vulnerability research principles. It does not provide mechanisms for disabling security agents, blinding kernel callbacks, or injecting weaponized exploits.
