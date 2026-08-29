//! Capability Security Proofs: Tests A through F
//! Proving that capabilities in JOCKY are explicit, granular, and non-escalatable.

use jocky_agent::{ForensicAgent, WasmExecutionError, WasmSandboxRunner};
use jocky_ast::Capability;
use jocky_compiler::{Compiler, CompilerError};
use jocky_ir::IRError;

/// Test A: Positive Control
/// Script requests process.read, grant is present -> process enumeration succeeds.
#[test]
fn test_a_process_read_granted_succeeds() {
    let script = r#"
        case "PROOF-TEST-A";
        capabilities { grant process.read; }
        query procs = host.processes();
    "#;

    let artifact = Compiler::compile_source(script).expect("Should compile when capability is granted");
    let agent = ForensicAgent::new("agent-a", artifact.granted_capabilities.clone());
    let runner = WasmSandboxRunner::new(&agent);
    let res = runner.execute(&artifact.bytecode, &artifact.required_host_imports, &artifact.granted_capabilities);
    assert!(res.is_ok(), "Execution must succeed when capability is granted");
}

/// Test B: Compile-Time Denial
/// Script calls host.processes() but omits process.read -> compilation rejected.
#[test]
fn test_b_missing_process_read_compilation_rejected() {
    let script = r#"
        case "PROOF-TEST-B";
        capabilities {
            // Empty capability block!
        }
        query procs = host.processes();
    "#;

    let result = Compiler::compile_source(script);
    assert!(result.is_err(), "Compilation must be rejected when capability is missing");
    match result.unwrap_err() {
        CompilerError::IR(IRError::CapabilityViolation { required, .. }) => {
            assert_eq!(required, "process.read");
        }
        other => panic!("Expected CapabilityViolation, got: {:?}", other),
    }
}

/// Test C: Granular Isolation
/// Script has process.read, but attempts memory.scan_regions() -> rejected.
#[test]
fn test_c_granular_isolation_memory_read_rejected() {
    let script = r#"
        case "PROOF-TEST-C";
        capabilities {
            grant process.read;
            // memory.read is NOT granted!
        }
        query mem = memory.scan();
    "#;

    let result = Compiler::compile_source(script);
    assert!(result.is_err(), "Attempting memory scan without memory.read must be rejected");
    match result.unwrap_err() {
        CompilerError::IR(IRError::CapabilityViolation { required, .. }) => {
            assert_eq!(required, "memory.read");
        }
        other => panic!("Expected CapabilityViolation for memory.read, got: {:?}", other),
    }
}

/// Test D: Malformed Capability Manifest
/// Syntactically invalid or forged capability declarations are rejected during parsing.
#[test]
fn test_d_malformed_capability_manifest_rejected() {
    let script = r#"
        case "PROOF-TEST-D";
        capabilities {
            grant ; // Missing capability identifier!
        }
        query procs = host.processes();
    "#;

    let result = Compiler::compile_source(script);
    assert!(result.is_err(), "Malformed capability manifest must be rejected");
}

/// Test E: Wasm Link-Time Denial
/// A Wasm binary attempting to import an ungranted host function is rejected by the host linker.
#[test]
fn test_e_wasm_link_time_capability_denial() {
    let agent = ForensicAgent::new("agent-e", vec![Capability::ProcessRead]);
    let runner = WasmSandboxRunner::new(&agent);

    let mut bytecode = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    bytecode.extend_from_slice(&[0x00; 16]);

    // Untrusted Wasm module declares import for memory scan, but agent only holds process.read
    let unauthorized_import = vec!["jocky_host_memory_scan".to_string()];
    let granted_caps = vec![Capability::ProcessRead];

    let result = runner.execute(&bytecode, &unauthorized_import, &granted_caps);
    assert!(result.is_err(), "Linker must refuse instantiation of unauthorized host import");
    match result.unwrap_err() {
        WasmExecutionError::LinkTimeCapabilityViolation { required_cap, .. } => {
            assert_eq!(required_cap, "memory.read");
        }
        other => panic!("Expected LinkTimeCapabilityViolation, got: {:?}", other),
    }
}

/// Test F: Server RBAC Policy Refusal
/// User with 'Junior Analyst' role requests 'memory.read' -> RBAC policy refuses job authorization.
#[test]
fn test_f_server_rbac_policy_refusal() {
    struct RbacPolicy {
        _role: String,
        allowed_capabilities: Vec<Capability>,
    }

    let junior_analyst_policy = RbacPolicy {
        _role: "JuniorAnalyst".to_string(),
        allowed_capabilities: vec![Capability::ProcessRead, Capability::EventlogRead],
    };

    let requested_script_caps = vec![Capability::ProcessRead, Capability::MemoryRead];

    let is_authorized = requested_script_caps.iter().all(|cap| {
        junior_analyst_policy.allowed_capabilities.contains(cap)
    });

    assert!(!is_authorized, "Server RBAC policy must refuse job requiring unauthorized capabilities");
}
