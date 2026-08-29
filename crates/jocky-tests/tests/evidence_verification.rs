//! Evidence Verification tests: Auditing Merkle tree, SHA-256 hashes, and CASE JSON-LD structure.

use jocky_agent::{ForensicAgent, WasmSandboxRunner};
use jocky_ast::Capability;
use jocky_compiler::Compiler;
use jocky_crypto::EvidencePackage;

#[test]
fn test_evidence_verification_end_to_end() {
    let script = r#"
        case "INC-VERIFY-E2E" description "Evidence verification test";

        capabilities {
            grant driver.read;
            grant process.read;
            grant evidence.export;
        }

        query drivers = host.drivers();
        evidence.export(drivers, format=CASE_JSON_LD);
    "#;

    let artifact = Compiler::compile_source(script).expect("Should compile cleanly");
    let agent = ForensicAgent::new("endpoint-agent-verify", artifact.granted_capabilities.clone());
    let runner = WasmSandboxRunner::new(&agent);
    runner.execute(&artifact.bytecode, &artifact.required_host_imports, &artifact.granted_capabilities)
        .expect("Execution must succeed");

    let drivers = agent.collect_drivers().expect("Should acquire drivers");
    let rec = agent.create_evidence_record("driver_inventory", &drivers, &Capability::DriverRead);
    let pkg = EvidencePackage::build(&artifact.case_id, vec![rec]);

    // Recalculate Merkle root independently
    let recomputed_root = EvidencePackage::compute_merkle_root(&pkg.records);
    assert_eq!(recomputed_root, pkg.merkle_root, "Merkle root must match independent recalculation");

    let case_json = pkg.to_case_json_ld();
    assert_eq!(case_json.get("@type").and_then(|v| v.as_str()), Some("InvestigationCase"));
    assert_eq!(case_json.get("case_id").and_then(|v| v.as_str()), Some("INC-VERIFY-E2E"));
}
