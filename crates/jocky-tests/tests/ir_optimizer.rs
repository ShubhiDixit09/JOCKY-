//! IR Optimizer tests: Snapshot and optimization pass verification.

use jocky_ast::Capability;
use jocky_ir::{IRInstruction, IRProgram};
use std::collections::HashSet;

#[test]
fn test_ir_filter_pushdown_eventlog() {
    let mut ir = IRProgram {
        case_id: "TEST-PUSH-01".to_string(),
        granted_capabilities: HashSet::from([Capability::EventlogRead]),
        required_capabilities: HashSet::from([Capability::EventlogRead]),
        instructions: vec![
            IRInstruction::AcquireSource {
                dst: 0,
                domain: "eventlog".to_string(),
                entity: "query".to_string(),
                filter_pushdown: None,
                required_capability: Capability::EventlogRead,
            },
            IRInstruction::FilterStream {
                dst: 1,
                src: 0,
                predicate: "e.event_id == 4688".to_string(),
            },
        ],
    };

    ir.optimize_filter_pushdown();

    match &ir.instructions[0] {
        IRInstruction::AcquireSource { filter_pushdown, .. } => {
            assert!(filter_pushdown.is_some(), "Filter pushdown must be populated");
            assert!(filter_pushdown.as_ref().unwrap().contains("EventID=4688"));
        }
        _ => panic!("Expected AcquireSource instruction"),
    }
}
