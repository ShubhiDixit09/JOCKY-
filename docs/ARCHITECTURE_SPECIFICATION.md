# JOCKY Framework: Technical Architecture Specification
**Just-in-time Operational Computer & Network Knowledge/Yield framework**
*Author: Senior Compiler & Digital Forensics Engineering Team*  
*Classification: Academic Cybersecurity Research & Defensive Forensic Architecture*  
*Version: 1.0.0-PROD-SPEC*

---

## Table of Contents
1. [JOCKY Domain-Specific Language](#1-jocky-domain-specific-language)
2. [Compiler Architecture & Intermediate Representation](#2-compiler-architecture--intermediate-representation)
3. [Security-First Execution & Capability System](#3-security-first-execution--capability-system)
4. [Cross-Platform Forensic Collection Engine](#4-cross-platform-forensic-collection-engine)
5. [Memory Forensics & In-Memory Introspection](#5-memory-forensics--in-memory-introspection)
6. [Adversary Technique Detection & MITRE ATT&CK Mapping](#6-adversary-technique-detection--mitre-attck-mapping)
7. [Laboratory Benign Telemetry Emulation Subsystem](#7-laboratory-benign-telemetry-emulation-subsystem)
8. [Central Management Platform & Transport Security](#8-central-management-platform--transport-security)
9. [Forensic Evidence Model & Provenance Integrity](#9-forensic-evidence-model--provenance-integrity)
10. [Secure CI/CD & Software Supply Chain](#10-secure-cicd--software-supply-chain)
11. [Academic Research Survey](#11-academic-research-survey)
12. [Ten-Phase Implementation Roadmap](#12-ten-phase-implementation-roadmap)
13. [Technology Stack Evaluation & Recommendation](#13-technology-stack-evaluation--recommendation)
14. [Academic Novelty Analysis & Research Questions](#14-academic-novelty-analysis--research-questions)
15. [Experimental Evaluation Methodology](#15-experimental-evaluation-methodology)
16. [Safety Boundary & Dual-Use Governance](#16-safety-boundary--dual-use-governance)

---

## 1. JOCKY Domain-Specific Language

### 1.1 Philosophy & Paradigm
JOCKY is a declarative, strongly-typed, capability-governed domain-specific language designed specifically for digital forensics, incident response (DFIR), and defensive threat hunting. Traditional languages used in DFIR (such as Python, PowerShell, or Bash) are general-purpose, imperatively state-mutating, un-sandboxed, and prone to unintentional host modification (e.g. altering access timestamps, writing temporary files, or crashing processes).

JOCKY addresses this paradigm through three foundational tenets:
1. **Purity of State**: JOCKY scripts have read-only access to host system state. Language primitives cannot create unmanaged files, modify registry values, or inject code.
2. **First-Class Forensic Entities**: Operating system constructs (processes, modules, VAD regions, event records, drivers, sockets) are strongly-typed native primitives rather than arbitrary strings or raw pointers.
3. **Provable Capability Grants**: Every forensic operation requires explicit declaration in a cryptographic capability manifest.

### 1.2 Conceptual & Concrete Syntax
A JOCKY program is partitioned into four distinct blocks:
- **Case Header**: Declares the investigation identifier, timestamp, and metadata.
- **Capability Block**: Declares the strict, non-escalatable permissions granted to the script.
- **Import List**: Imports standard forensic modules (`std.forensics.windows`, `std.detect.injection`, etc.).
- **Query & Correlation Pipeline**: Declarative dataflow pipelines filtering, transforming, correlating, and exporting evidence.

```jocky
// Example JOCKY Script: Live Process Injection & BYOVD Detection
case "INC-2026-X01" description "Endpoint Anomaly Investigation";

capabilities {
    grant process.read;
    grant memory.read;
    grant driver.read;
    grant eventlog.read;
    grant evidence.export;
}

import std.forensics.windows as win;
import std.detect.injection as inj;
import std.detect.byovd as byovd;

// Query 1: Extract drivers and detect known-vulnerable or unsigned modules
query suspicious_drivers = host.drivers()
    | filter(d => d.is_known_vulnerable == true or d.is_whql == false);

detect byovd_anomaly on suspicious_drivers {
    technique: "T1068 / T1543.003 - Bring Your Own Vulnerable Driver",
    severity: CRITICAL,
    condition: suspicious_drivers.count() > 0,
    rationale: "Loaded kernel driver matches known vulnerable driver catalog (LOLDrivers)"
}

// Query 2: Scan for unbacked executable memory in active user processes
query unbacked_regions = host.processes()
    | filter(p => p.name !in ["System", "smss.exe", "Registry"])
    | map(p => {
        process: p,
        rwx_allocations: memory.scan_regions(
            pid: p.pid,
            protect_in: ["PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_READ"],
            type_in: ["MEM_PRIVATE"]
        )
    })
    | filter(res => res.rwx_allocations.count() > 0);

detect injection_anomaly on unbacked_regions {
    technique: "T1055 - Process Injection",
    severity: HIGH,
    condition: unbacked_regions.count() > 0,
    rationale: "Detected executable memory regions in user space not backed by a disk image file"
}

// Correlate findings across a 30-minute investigation window
correlate attack_chain {
    streams: [suspicious_drivers, unbacked_regions],
    window: 30m,
    join_on: suspicious_drivers.host_id == unbacked_regions.host_id,
    emit: {
        host: host.info(),
        driver_alerts: suspicious_drivers,
        memory_alerts: unbacked_regions,
        acquired_at: timestamp.now()
    }
}

// Export structured evidence package
evidence.export(
    attack_chain,
    format=CASE_JSON_LD,
    destination="vault://central-forensics.internal/cases/INC-2026-X01"
);
```

---

## 2. Compiler Architecture & Intermediate Representation

### 2.1 Compiler Pipeline Overview
The JOCKY compiler is constructed in modern Rust, organizing compilation into clean, distinct stages:

```
Source Code (.jky)
   │
   ▼
[ Lexer ] ────────── Logos-based tokenization (Zero-copy, high throughput)
   │
   ▼
[ Parser ] ───────── Pratt / Recursive Descent parser generating Typed AST
   │
   ▼
[ Semantic ] ─────── Symbol resolution, Type inference, Capability audit
   │
   ▼
[ JOCKY-IR ] ─────── Forensic SSA Intermediate Representation
   │
   ▼
[ Optimizer ] ────── Capability minimization, Filter pushdown, Dead query elimination
   │
   ▼
[ CodeGen ] ──────── WebAssembly (WASI) Bytecode (.jbc)
```

### 2.2 Forensic Intermediate Representation (JOCKY-IR)
JOCKY-IR is an SSA dataflow representation that formalizes forensic streams:
- `ForensicStream`: An asynchronous, backpressured sequence of typed records.
- `CapabilityRequirement`: Metadata attached to each IR basic block asserting required rights.
- `FilterPushdownNode`: Identifies predicates that can be translated directly into operating system filter queries (e.g. Windows Event Log XPath queries or Linux journald matches) rather than filtering in user-space memory.

```
func @scan_host(%case_id: string) -> !evidence.pkg
    capabilities [process.read, memory.read]
{
bb0:
    %0 = host.processes.enumerate() : !stream<!process.record>
    %1 = stream.filter %0, @predicate_not_system : !stream<!process.record>
    %2 = stream.map %1, @inspect_vad_rwx : !stream<!injection.result>
    %3 = stream.where %2, @has_anomalies : !stream<!injection.result>
    %4 = evidence.seal %3, %case_id : !evidence.pkg
    return %4
}
```

### 2.3 Compiler Optimization Passes
1. **Capability Minimization Pass**: Calculates the minimal union of capabilities required by all expressions. Unused capability grants produce compiler warnings.
2. **Filter Pushdown Pass**: Re-writes dataflow graphs so that filters on native log sources (e.g. `eventlog.query() | filter(e => e.id == 4688)`) push the criteria down to the native OS API (`EvtQuery` with XPath query `*[System[(EventID=4688)]]`), reducing context switches and RAM allocation by >90%.
3. **Purity Verification Pass**: Proves at compile time that the script performs no state mutations outside the designated evidence export sink.

---

## 3. Security-First Execution & Capability System

### 3.1 Granular Capability Architecture
JOCKY implements a capability security model where access to system resources requires explicit, unforgeable permissions:

| Capability | Scope of Access | OS Enforcement (Windows / Linux) |
| :--- | :--- | :--- |
| `process.read` | Query process metadata, threads, handles | `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`, `/proc/[pid]/status` |
| `memory.read` | Read virtual memory pages, VAD flags | `OpenProcess(PROCESS_VM_READ)`, `process_vm_readv` |
| `filesystem.read` | Read files, traverse directories, read MFT | `FILE_READ_DATA`, `O_RDONLY` |
| `registry.read` | Read registry keys, parse offline hives | `RegOpenKeyExW(KEY_READ)` |
| `driver.read` | Enumerate kernel drivers, check signatures | `EnumDeviceDrivers`, `/proc/modules` |
| `eventlog.read` | Read Windows Event Logs, systemd journals | `EvtQuery`, `/var/log/journal/` |
| `network.read` | Enumerate sockets, routing tables, DNS cache| `GetExtendedTcpTable`, `/proc/net/tcp` |
| `evidence.export` | Transmit encrypted packages to evidence vault| Sandboxed outbound mTLS socket |

### 3.2 Dual-Layer Sandboxing
1. **WebAssembly Virtual Machine**: Scripts run in an embedded `Wasmtime` engine. Memory is strictly bounded (configurable 128MB–512MB). Stack overflow protection, linear memory isolation, and fuel-based instruction limits guarantee that buggy or malicious scripts cannot crash the host agent or cause DoS.
2. **OS Process Isolation**:
   - **Linux**: Host agent worker processes run inside a restricted namespace (`CLONE_NEWPID`, `CLONE_NEWNET`) with `seccomp-bpf` syscall filters blocking `execve`, `fork`, and unauthorized writes.
   - **Windows**: Host agent runs in a restricted Job Object with token privilege stripping (`SeDebugPrivilege` disabled unless specifically authorized for memory acquisition).

---

## 4. Cross-Platform Forensic Collection Engine

### 4.1 Windows Forensic Architecture
The Windows collection engine is implemented natively in Rust using `windows-rs`:
- **EVTX Collector**: Native binary XML parser streaming `%SystemRoot%\System32\Winevt\Logs\*.evtx` directly. Bypasses live log tampering by reading locked files using volume snapshot semantics (`FILE_SHARE_READ | FILE_SHARE_WRITE`).
- **NTFS / MFT Engine**: Zero-copy B-Tree parser for `$MFT`. Analyzes `$STANDARD_INFORMATION` and `$FILE_NAME` timestamp attributes to automatically detect timestomping (`$SI.Modified < $FN.Modified`).
- **Registry Engine**: Parses both live registry keys (`RegOpenKeyExW`) and offline transaction logs (`ntuser.dat.LOG1`, `SYSTEM.LOG1`) to recover deleted persistence keys in `Run`, `RunOnce`, and Shell Service Objects.
- **Prefetch & Amcache**: Decompresses Windows 10/11 MAM-compressed `.pf` files to reconstruct executable launch counts, timestamps, and referenced DLLs. Parses `Amcache.hve` for uninstalled binary hashes.
- **Driver Verification**: Queries `EnumDeviceDrivers`, extracts on-disk binaries, verifies Authenticode signatures via `WinVerifyTrust`, and checks SHA-256 hashes against the **LOLDrivers** database.

### 4.2 Linux / Ubuntu Forensic Architecture
- **systemd-journald Parser**: Direct zero-copy reader for `/var/log/journal/*/*.journal` files, parsing structured log entries without invoking `journalctl`.
- **Auditd Integration**: Real-time reader for `/var/log/audit/audit.log`, extracting syscall invocation events (EXECVE, CONNECT, BIND).
- **`/proc` & `/sys` Introspection**: Parses `/proc/[pid]/maps` for memory permissions, `/proc/[pid]/exe` for disk path symlinks, `/proc/[pid]/cmdline`, and `/proc/net/tcp` for active sockets.
- **eBPF Observation Engine**: Implemented via Rust's `aya` framework. Deploys read-only tracepoints (`sys_enter_execve`, `sched_process_fork`) to capture short-lived adversary processes without kernel mutation.

---

## 5. Memory Forensics & In-Memory Introspection

### 5.1 Unbacked Executable Memory Scanner
Reflective DLL loaders and shellcode loaders allocate memory dynamically without backing by an on-disk image file. JOCKY detects this pattern:
1. Iterates process Virtual Address Descriptors (VAD) via `VirtualQueryEx` (Windows) or `/proc/[pid]/maps` (Linux).
2. Flags any memory segment where:
   - `Protection` is `PAGE_EXECUTE_READWRITE` (RWX) or `PAGE_EXECUTE_READ` (RX).
   - `Type` is `MEM_PRIVATE` (Windows) or mapping lacks a file pathname (Linux).
   - The region does not belong to a recognized JIT runtime (e.g. .NET CLR, JVM, or browser V8 engine).

### 5.2 Disk vs. Memory Binary Verification
To detect user-mode inline hooks, trampoline patches, and process hollowing:
1. Reads the mapped module list from PEB / `/proc/[pid]/maps`.
2. For each critical DLL (e.g. `ntdll.dll`, `kernel32.dll`, `libc.so`), opens the clean on-disk image file.
3. Compares the in-memory `.text` section against the on-disk section, applying base relocation adjustments.
4. If a function prologue contains deviation bytes (e.g. `0xE9` JMP, `0xFF 0x25` indirect jump) not documented in OS relocation tables, JOCKY flags an **Inline API Hooking Anomaly**.

### 5.3 YARA-X Memory Engine
Integrates the pure-Rust `yara-x` compiler and scanner. Rules are compiled into bytecode and evaluated across memory buffers in parallel using Rust's `rayon` work-stealing threadpool.

---

## 6. Adversary Technique Detection & MITRE ATT&CK Mapping

JOCKY natively maps detection rules to the MITRE ATT&CK enterprise matrix:

| MITRE ATT&CK ID | Technique Name | Detection Invariant in JOCKY |
| :--- | :--- | :--- |
| **T1055.012** | Process Hollowing | `PEB.ImageBaseAddress` diverges from mapped image base, or `.text` hash diverges from disk. |
| **T1055.001** | Reflective DLL Injection | Executable `MEM_PRIVATE` memory region containing unlinked PE header (`0x4D 0x5A` MZ magic). |
| **T1055.003** | Thread Execution Hijacking| Thread starting address points to non-module memory (`MEM_PRIVATE`) rather than an exported DLL symbol. |
| **T1068 / T1543.003**| BYOVD / Vulnerable Driver Load | Loaded kernel driver hash matches known vulnerable driver list (LOLDrivers catalog) or lacks WHQL signature. |
| **T1562.001** | Impair Defenses: Telemetry Gap | Gap in Sysmon/Defender event stream while host uptime is active and security service is disabled. |
| **T1071.001** | Domain Fronting / SNI Mismatch | TLS ClientHello SNI header diverges from inner HTTP `Host` header on shared CDN edge. |
| **T1071** | Suspicious Cloud API Abuse | Workstation scripting host (`powershell.exe`, `rundll32.exe`) querying Microsoft Graph or Cloudflare API. |

---

## 7. Laboratory Benign Telemetry Emulation Subsystem

To evaluate JOCKY detection algorithms safely in academic and enterprise laboratories, the `jocky-lab` crate generates **benign synthetic telemetry**:
- **Benign Injection Probe**: Spawns an isolated child process, allocates an RWX buffer, writes a benign ASCII probe (`"JOCKY_BENIGN_PROBE_CANARY"`), and triggers an ETW probe. No code execution or thread hijacking occurs.
- **Vulnerable Driver Simulation**: Emits a synthetic driver load telemetry event into a local test channel using a known test hash, evaluating whether detection rules trigger without loading physical kernel drivers.
- **Loopback TLS SNI Probe**: Opens a loopback TCP connection (`127.0.0.1:9443`), emits a TLS ClientHello with `SNI: cdn.test.local`, followed by an HTTP GET with `Host: c2.test.local`, verifying domain-fronting detection logic safely.

---

## 8. Central Management Platform & Transport Security

```
[ Investigation Console ]
          │ (mTLS / REST)
          ▼
[ API Gateway / RBAC ]
          │
          ▼
[ Investigation Server ] ─── [ Ed25519 Job Signer ]
          │
          ├──────────────────────────┐
          ▼ (mTLS gRPC Stream)       ▼ (mTLS gRPC Stream)
[ Windows Endpoint Agent ]     [ Ubuntu Endpoint Agent ]
```

### 8.1 Mutual TLS (mTLS) Architecture
- Communication utilizes TLS 1.3 with ECDHE key exchange, AES-256-GCM, and client certificate verification.
- Certificates are issued by a dedicated internal forensic PKI. Agents verify server identity; servers authenticate agent device identity.

### 8.2 Cryptographically Signed Jobs & RBAC
- Investigators authenticate with hardware tokens (FIDO2 / PIV) or Ed25519 keypairs.
- Every compiled JOCKY bytecode artifact is signed: `Signature = Sign(InvestigatorPrivKey, SHA256(Bytecode))`.
- Endpoint agents reject any job whose signature cannot be verified against the trusted investigator public keyring.

---

## 9. Forensic Evidence Model & Provenance Integrity

### 9.1 CASE & STIX 2.1 Serialization
Evidence is formatted in CASE (Cyber-investigation Analysis Standard Expression, JSON-LD) and STIX 2.1, ensuring immediate interoperability with SIEM, SOAR, and forensic case managers.

### 9.2 Provenance Chain & RFC 3161 Timestamps
Every evidence record contains:
1. `record_id`: UUIDv4 identifier.
2. `provenance`: Agent ID, operating system build, collector version, script AST hash, granted capabilities.
3. `timestamps`: High-precision UTC acquisition start and completion timestamps.
4. `evidence_hash`: BLAKE3 and SHA-256 hashes of the raw record data.
5. `rfc3161_token`: Cryptographic timestamp token issued by an RFC 3161 compliant Time Stamping Authority (TSA).
6. `merkle_root`: Inclusion proof in the case's append-only Merkle tree.

---

## 10. Secure CI/CD & Software Supply Chain

### 10.1 Pipeline Stages (SLSA Level 3)
1. **Source Attestation**: Signed Git commits required for merge.
2. **Deterministic Build Environment**: Fixed Docker build container with pinned Rust toolchain (`1.80.0`).
3. **Reproducible Compilation**: Enforces `SOURCE_DATE_EPOCH` and `cargo-auditable` to embed the complete dependency graph into PE/ELF binaries.
4. **SBOM Generation**: Emits SPDX and CycloneDX Software Bill of Materials using `syft`.
5. **Release Signing**: Binaries and Wasm standard library modules signed using **Cosign** (Sigstore).

---

## 11. Academic Research Survey
*(Refer to `docs/LITERATURE_REVIEW.md` for full annotated analyses of the 10 peer-reviewed papers spanning VAST, memory forensics, driver verification, LLVM obfuscation, and reproducible builds).*

---

## 12. Ten-Phase Implementation Roadmap

1. **Phase 1: Lexer, Parser & AST Engine** (Rust, `logos`, `chumsky`).
2. **Phase 2: JOCKY-IR & Standard Library** (Rust, SSA graph, capability pass, Wasm code generator).
3. **Phase 3: Windows Native Forensic Collector** (EVTX, MFT, Registry, Prefetch, LOLDrivers).
4. **Phase 4: Linux Native Forensic Collector** (systemd-journal, `/proc`, auditd, eBPF via `aya`).
5. **Phase 5: Memory Forensics & YARA Engine** (`yara-x`, unbacked memory scanner, disk vs memory diffing).
6. **Phase 6: Temporal Correlation & ATT&CK Engine** (Stream joins, MITRE mapping, severity scoring).
7. **Phase 7: Central Management Server** (gRPC with `tonic`, mTLS, Ed25519 signing, Merkle vault).
8. **Phase 8: Web Investigation Console** (React, TypeScript, timeline graph visualization).
9. **Phase 9: Laboratory Adversary Emulation Simulator** (Benign telemetry probes for validation).
10. **Phase 10: Evaluation & Academic Publication** (Benchmarking harnesses, precision/recall metrics, publication draft).

---

## 13. Technology Stack Evaluation & Recommendation

### Comparative Evaluation Matrix

| Architecture Option | Safety & Sandboxing | Capability Control | Binary Footprint | Cross-Platform Parity | Native Forensics Throughput |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Option A: Rust + LLVM** | Low (Native machine code) | Static only | Massive (>80MB) | Low (Separate PE/ELF) | High |
| **Option B: Rust + MLIR** | Low (Native machine code) | Static only | Extreme (>120MB)| Low (Separate PE/ELF) | High |
| **Option C: Rust + Wasm** | High (Wasm sandbox) | High (WASI) | Compact (<25MB) | High (Single bytecode) | Medium |
| **Option D: Go + LLVM** | Low (Native machine code) | Weak | Large (>45MB) | Low | Medium |
| **Option E: Custom VM** | High (Interpreter) | Medium | Minimal (<5MB) | High | Low (Interpreter overhead) |
| **Option F: Hybrid DSL (Recommended)**| **Superior (Dual-layer)** | **Strict (Host bindings)**| **Optimal (<20MB)**| **High (Single bytecode)** | **Maximum (Native Rust Core)** |

**Recommendation Justification**: **Option F** provides the optimal trade-off: scripts compile to safe, portable WebAssembly executed inside a lightweight Wasmtime runtime, while heavy forensic primitives (MFT B-tree scanning, raw EVTX parsing, YARA scanning) execute at native hardware speed inside the Rust agent.

---

## 14. Academic Novelty Analysis & Research Questions

### Novelty Differentiation
- Unlike **osquery**, JOCKY provides temporal window correlation, first-class memory forensics, and native capability access control.
- Unlike **Sigma**, JOCKY is an executable query and acquisition language rather than a passive detection schema.
- Unlike **Volatility**, JOCKY operates live on running endpoints with minimal memory overhead rather than requiring full physical memory image dumps.

### Core Research Questions
- **RQ1**: *Can a capability-typed domain-specific language eliminate unintended state modification and privilege escalation during live digital evidence acquisition?*
- **RQ2**: *How does an intermediate representation for forensic streaming queries affect CPU utilization, memory footprint, and query execution latency compared to SQL-based endpoint agents?*
- **RQ3**: *What is the detection accuracy (precision, recall, F1-score) of live in-memory PE/ELF header diffing against unbacked executable memory in detecting process injection without kernel hooking?*

---

## 15. Experimental Evaluation Methodology
- **Performance Benchmarks**: Query compilation latency (<50ms), agent memory resident set size (<35MB idle, <120MB active MFT scan), CPU utilization (<2% under standard event load).
- **Detection Accuracy**: Precision, recall, and F1-score evaluated against benign workstation baselines and safe laboratory synthetic probes.
- **Fleet Scalability**: Evaluation of central server ingestion throughput across simulated fleets of 10, 100, and 1,000 agents.

---

## 16. Safety Boundary & Dual-Use Governance
JOCKY is maintained strictly under defensive cybersecurity governance:
- **Zero Evasion Mechanics**: No unhooking, no callback blinding, no rootkit behaviors.
- **Read-Only Invariants**: Enforced at compiler, sandbox, and operating system API levels.
- **Auditability**: All queries and capabilities exercised are signed, timestamped, and immutably logged in compliance with ISO/IEC 27037 standards for digital evidence handling.
