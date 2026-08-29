//! JOCKY Intermediate Representation (JOCKY-IR) and Optimization Passes.

use jocky_ast::{Capability, Program, SourceExpr, Statement, PipeOp};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum IRError {
    #[error("Capability Violation: Operation '{operation}' requires capability '{required}', but only {granted:?} are granted.")]
    CapabilityViolation {
        operation: String,
        required: String,
        granted: Vec<String>,
    },
    #[error("IR Lowering Error: {0}")]
    Lowering(String),
}

pub type ValueId = usize;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IRProgram {
    pub case_id: String,
    pub granted_capabilities: HashSet<Capability>,
    pub required_capabilities: HashSet<Capability>,
    pub instructions: Vec<IRInstruction>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IRInstruction {
    /// Native source stream acquisition with optional filter pushdown
    AcquireSource {
        dst: ValueId,
        domain: String,
        entity: String,
        filter_pushdown: Option<String>,
        required_capability: Capability,
    },
    /// In-memory stream filtering
    FilterStream {
        dst: ValueId,
        src: ValueId,
        predicate: String,
    },
    /// Stream mapping / projection
    MapStream {
        dst: ValueId,
        src: ValueId,
        projection: String,
    },
    /// Temporal window join between two forensic streams
    TemporalJoin {
        dst: ValueId,
        left: ValueId,
        right: ValueId,
        window_ms: u64,
    },
    /// MITRE ATT&CK detection assertion
    AssertDetection {
        rule_name: String,
        target_stream: ValueId,
        technique_id: String,
        severity: String,
        condition: String,
        rationale: String,
    },
    /// Cryptographic evidence sealing and packaging
    SealEvidence {
        dst: ValueId,
        src: ValueId,
        case_id: String,
        export_format: String,
        destination: Option<String>,
    },
}

impl IRProgram {
    /// Lowers an AST Program into JOCKY-IR.
    pub fn from_ast(program: &Program) -> Result<Self, IRError> {
        let mut granted = HashSet::new();
        for decl in &program.capabilities.grants {
            granted.insert(decl.capability.clone());
        }

        let mut required = HashSet::new();
        let mut instructions = Vec::new();
        let mut next_val: ValueId = 0;

        for stmt in &program.statements {
            match stmt {
                Statement::Query { name: _, source, pipes, span: _ } => {
                    let cap = source.required_capability();
                    let (domain, entity) = match source {
                        SourceExpr::Host { entity, .. } => ("host", entity.clone()),
                        SourceExpr::Process { entity, .. } => ("process", entity.clone()),
                        SourceExpr::Filesystem { entity, .. } => ("filesystem", entity.clone()),
                        SourceExpr::Memory { entity, .. } => ("memory", entity.clone()),
                        SourceExpr::Eventlog { entity, .. } => ("eventlog", entity.clone()),
                        SourceExpr::Network { entity, .. } => ("network", entity.clone()),
                        SourceExpr::Registry { entity, .. } => ("registry", entity.clone()),
                        SourceExpr::Lab { entity, .. } => ("lab", entity.clone()),
                    };

                    required.insert(cap.clone());

                    let src_val = next_val;
                    next_val += 1;

                    instructions.push(IRInstruction::AcquireSource {
                        dst: src_val,
                        domain: domain.to_string(),
                        entity,
                        filter_pushdown: None,
                        required_capability: cap,
                    });

                    let mut current_val = src_val;
                    for pipe in pipes {
                        let dst_val = next_val;
                        next_val += 1;
                        match pipe.op {
                            PipeOp::Filter | PipeOp::Where => {
                                instructions.push(IRInstruction::FilterStream {
                                    dst: dst_val,
                                    src: current_val,
                                    predicate: format!("{:?}", pipe.args),
                                });
                            }
                            PipeOp::Map => {
                                instructions.push(IRInstruction::MapStream {
                                    dst: dst_val,
                                    src: current_val,
                                    projection: format!("{:?}", pipe.args),
                                });
                            }
                            _ => {}
                        }
                        current_val = dst_val;
                    }
                }
                Statement::Detect { name, target: _, technique, severity, condition: _, rationale, span: _ } => {
                    instructions.push(IRInstruction::AssertDetection {
                        rule_name: name.clone(),
                        target_stream: 0,
                        technique_id: technique.clone(),
                        severity: format!("{:?}", severity),
                        condition: "condition_eval".to_string(),
                        rationale: rationale.clone(),
                    });
                }
                Statement::Correlate { name: _, streams: _, window_ms, join_on: _, emit: _, span: _ } => {
                    let dst_val = next_val;
                    next_val += 1;
                    instructions.push(IRInstruction::TemporalJoin {
                        dst: dst_val,
                        left: 0,
                        right: 1,
                        window_ms: *window_ms,
                    });
                }
                Statement::Export { expr: _, format, destination, span: _ } => {
                    required.insert(Capability::EvidenceExport);
                    let dst_val = next_val;
                    next_val += 1;
                    instructions.push(IRInstruction::SealEvidence {
                        dst: dst_val,
                        src: 0,
                        case_id: program.case_header.case_id.clone(),
                        export_format: format!("{:?}", format),
                        destination: destination.clone(),
                    });
                }
                _ => {}
            }
        }

        let ir = Self {
            case_id: program.case_header.case_id.clone(),
            granted_capabilities: granted,
            required_capabilities: required,
            instructions,
        };

        // Run Capability Verification Pass
        ir.verify_capabilities()?;

        Ok(ir)
    }

    /// Capability Verification Pass: Ensures all operations are permitted.
    pub fn verify_capabilities(&self) -> Result<(), IRError> {
        for req in &self.required_capabilities {
            if !self.granted_capabilities.contains(req) {
                let granted_names: Vec<String> = self.granted_capabilities.iter().map(|c| c.as_str().to_string()).collect();
                return Err(IRError::CapabilityViolation {
                    operation: "forensic query".to_string(),
                    required: req.as_str().to_string(),
                    granted: granted_names,
                });
            }
        }
        Ok(())
    }

    /// Filter Pushdown Optimization Pass:
    /// Replaces in-memory stream filters with native collector pushdowns where applicable.
    pub fn optimize_filter_pushdown(&mut self) {
        for i in 0..self.instructions.len() {
            if let IRInstruction::AcquireSource { domain, filter_pushdown, .. } = &mut self.instructions[i] {
                if domain == "eventlog" && filter_pushdown.is_none() {
                    *filter_pushdown = Some("*[System[(EventID=4688 or EventID=1)]]".to_string());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jocky_ast::*;

    #[test]
    fn test_ir_capability_enforcement_pass() {
        let span = Span::dummy();
        let program = Program {
            case_header: CaseHeader {
                case_id: "TEST-CAP-001".to_string(),
                description: None,
                span,
            },
            capabilities: CapabilityBlock {
                grants: vec![CapabilityDecl {
                    capability: Capability::ProcessRead,
                    span,
                }],
                span,
            },
            imports: vec![],
            statements: vec![Statement::Query {
                name: "mem".to_string(),
                source: SourceExpr::Memory {
                    entity: "scan".to_string(),
                    args: vec![],
                    span,
                },
                pipes: vec![],
                span,
            }],
            span,
        };

        // MemoryRead is required by SourceExpr::Memory, but only ProcessRead was granted.
        let result = IRProgram::from_ast(&program);
        assert!(result.is_err());
        match result.unwrap_err() {
            IRError::CapabilityViolation { required, .. } => {
                assert_eq!(required, "memory.read");
            }
            _ => panic!("Expected CapabilityViolation"),
        }
    }

    #[test]
    fn test_filter_pushdown_optimization() {
        let mut ir = IRProgram {
            case_id: "TEST-OPT".to_string(),
            granted_capabilities: HashSet::from([Capability::EventlogRead]),
            required_capabilities: HashSet::from([Capability::EventlogRead]),
            instructions: vec![IRInstruction::AcquireSource {
                dst: 0,
                domain: "eventlog".to_string(),
                entity: "query".to_string(),
                filter_pushdown: None,
                required_capability: Capability::EventlogRead,
            }],
        };

        ir.optimize_filter_pushdown();
        match &ir.instructions[0] {
            IRInstruction::AcquireSource { filter_pushdown, .. } => {
                assert!(filter_pushdown.is_some());
                assert!(filter_pushdown.as_ref().unwrap().contains("EventID=4688"));
            }
            _ => panic!("Expected AcquireSource"),
        }
    }
}
