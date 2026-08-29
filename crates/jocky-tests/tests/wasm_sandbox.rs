//! Wasm Sandbox tests: Bytecode validation, fuel consumption, and linear memory isolation.

use jocky_agent::{ForensicAgent, WasmSandboxRunner};
use jocky_compiler::Compiler;

#[test]
fn test_wasm_sandboxed_execution_fuel_consumption() {
    let script = r#"
        case "TEST-WASM-EXEC-01";
        capabilities {
            grant process.read;
            grant driver.read;
            grant evidence.export;
        }
        query drivers = host.drivers();
        query procs = host.processes();
        evidence.export(drivers, format=CASE_JSON_LD);
    "#;

    let artifact = Compiler::compile_source(script).expect("Should compile to Wasm");
    assert_eq!(&artifact.bytecode[0..4], &[0x00, 0x61, 0x73, 0x6d]);

    let agent = ForensicAgent::new("test-wasm-agent", artifact.granted_capabilities.clone());
    let runner = WasmSandboxRunner::new(&agent);

    let result = runner.execute(&artifact.bytecode, &artifact.required_host_imports, &artifact.granted_capabilities)
        .expect("Sandboxed execution should complete");

    assert_eq!(result.exit_code, 0);
    assert!(result.fuel_consumed > 0, "Execution must record fuel consumed");
    assert_eq!(result.operations_executed, artifact.required_host_imports.len());
    assert_eq!(result.capability_audits_passed, artifact.required_host_imports.len());
}
