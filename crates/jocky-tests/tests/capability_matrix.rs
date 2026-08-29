//! Combinatorial Capability Security Validation Matrix
//! Formally evaluates the non-escalation invariant:
//!   For every requested host function h in I, Required(h) ⊆ Granted(C)
//!   Execution is permitted iff I ⊆ AuthorizedImports(C)
//!   Invariant: C_runtime ⊆ C_declared

use jocky_agent::{ForensicAgent, WasmExecutionError, WasmSandboxRunner};
use jocky_ast::Capability;

struct HostFunctionSpec {
    import_symbol: &'static str,
    required_capability: Capability,
    _description: &'static str,
}

#[test]
fn test_exhaustive_capability_matrix() {
    // 1. Define universal host function inventory H and requirement mapping R(h)
    let host_functions = vec![
        HostFunctionSpec {
            import_symbol: "jocky_host_host_drivers",
            required_capability: Capability::DriverRead,
            _description: "Enumerate and verify loaded kernel drivers against LOLDrivers",
        },
        HostFunctionSpec {
            import_symbol: "jocky_host_host_processes",
            required_capability: Capability::ProcessRead,
            _description: "Enumerate running processes and extract parent-child hierarchies",
        },
        HostFunctionSpec {
            import_symbol: "jocky_host_memory_scan",
            required_capability: Capability::MemoryRead,
            _description: "Scan process memory for unbacked executable (RWX/RX) pages",
        },
        HostFunctionSpec {
            import_symbol: "jocky_host_network_connections",
            required_capability: Capability::NetworkRead,
            _description: "Inspect active TCP/UDP sockets and TLS SNI headers",
        },
        HostFunctionSpec {
            import_symbol: "jocky_host_export_evidence",
            required_capability: Capability::EvidenceExport,
            _description: "Seal and transmit encrypted evidence packages",
        },
    ];

    // 2. Define capability domain pool
    let capability_pool = vec![
        Capability::DriverRead,
        Capability::ProcessRead,
        Capability::MemoryRead,
        Capability::NetworkRead,
        Capability::EvidenceExport,
    ];

    let n = capability_pool.len();
    let total_subsets = 1 << n; // 2^5 = 32 capability combinations

    let mut total_evaluations = 0;
    let mut permitted_count = 0;
    let mut rejected_count = 0;

    // Valid minimal Wasm binary header
    let mut wasm_header = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    wasm_header.extend_from_slice(&[0x00; 16]);

    // 3. Evaluate every subset C_i ⊆ C
    for bitmask in 0..total_subsets {
        let mut granted_set = Vec::new();
        for (i, cap) in capability_pool.iter().enumerate() {
            if (bitmask & (1 << i)) != 0 {
                granted_set.push(cap.clone());
            }
        }

        let agent = ForensicAgent::new("agent-matrix-evaluator", granted_set.clone());
        let runner = WasmSandboxRunner::new(&agent);

        // Test each host function h against granted set C_i
        for h in &host_functions {
            total_evaluations += 1;
            let requested_import = vec![h.import_symbol.to_string()];
            let expected_permitted = granted_set.contains(&h.required_capability);

            let execution_result = runner.execute(&wasm_header, &requested_import, &granted_set);

            if expected_permitted {
                assert!(
                    execution_result.is_ok(),
                    "Violation: Function '{}' requires '{:?}' which IS granted in {:?}, but was denied: {:?}",
                    h.import_symbol,
                    h.required_capability,
                    granted_set,
                    execution_result.err()
                );
                permitted_count += 1;
            } else {
                assert!(
                    execution_result.is_err(),
                    "Escalation Fault: Function '{}' requires '{:?}' which is ABSENT in {:?}, but execution succeeded!",
                    h.import_symbol,
                    h.required_capability,
                    granted_set
                );
                match execution_result.unwrap_err() {
                    WasmExecutionError::LinkTimeCapabilityViolation { required_cap, .. } => {
                        assert_eq!(required_cap, h.required_capability.as_str());
                    }
                    other => panic!("Unexpected error variant: {:?}", other),
                }
                rejected_count += 1;
            }
        }
    }

    println!(
        "\n[Capability Security Matrix Verified] Total Evaluations: {}, Permitted: {}, Blocked: {}",
        total_evaluations, permitted_count, rejected_count
    );
    assert_eq!(total_evaluations, total_subsets * host_functions.len());
    // Out of 32 subsets, each of the 5 functions is present in exactly 16 subsets (32 * 5 / 2 = 80 permitted, 80 blocked)
    assert_eq!(permitted_count, 80);
    assert_eq!(rejected_count, 80);
}

#[test]
fn test_property_based_random_capability_invariance() {
    // Pseudo-random pseudo-fuzzed generation of capability requests
    let all_caps = [
        Capability::ProcessRead,
        Capability::MemoryRead,
        Capability::DriverRead,
        Capability::NetworkRead,
        Capability::EventlogRead,
        Capability::EvidenceExport,
    ];

    let all_imports = [
        ("jocky_host_host_processes", Capability::ProcessRead),
        ("jocky_host_memory_scan", Capability::MemoryRead),
        ("jocky_host_host_drivers", Capability::DriverRead),
        ("jocky_host_network_connections", Capability::NetworkRead),
        ("jocky_host_export_evidence", Capability::EvidenceExport),
    ];

    let mut wasm_header = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    wasm_header.extend_from_slice(&[0x00; 16]);

    let mut seed: u64 = 0x1337BEEF;
    let mut rng = || {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        (seed >> 33) as u32
    };

    for trial in 0..500 {
        // Generate random granted capability set
        let num_grants = (rng() as usize) % (all_caps.len() + 1);
        let mut granted = Vec::new();
        for cap in &all_caps {
            if ((rng() as usize) % 2) == 1 && granted.len() < num_grants {
                granted.push(cap.clone());
            }
        }

        // Generate random requested imports
        let num_requests = 1 + (rng() as usize) % all_imports.len();
        let mut requested_imports = Vec::new();
        let mut requires_unauthorized = false;

        for _ in 0..num_requests {
            let idx = (rng() as usize) % all_imports.len();
            let (sym, req_cap) = &all_imports[idx];
            if !requested_imports.contains(&sym.to_string()) {
                requested_imports.push(sym.to_string());
                if !granted.contains(req_cap) {
                    requires_unauthorized = true;
                }
            }
        }

        let agent = ForensicAgent::new("agent-prop-test", granted.clone());
        let runner = WasmSandboxRunner::new(&agent);
        let res = runner.execute(&wasm_header, &requested_imports, &granted);

        if requires_unauthorized {
            assert!(
                res.is_err(),
                "Trial {}: Escalation failure - requested {:?} with granted {:?}",
                trial,
                requested_imports,
                granted
            );
        } else {
            assert!(
                res.is_ok(),
                "Trial {}: False denial - requested {:?} with granted {:?}",
                trial,
                requested_imports,
                granted
            );
        }
    }
}
