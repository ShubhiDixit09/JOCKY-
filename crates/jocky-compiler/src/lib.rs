//! JOCKY Compiler: End-to-End pipeline from .jky source to WebAssembly binary artifact.

pub mod type_check;
pub mod wasm_emit;

pub use type_check::{TypeChecker, TypeError};
pub use wasm_emit::{WasmArtifact, WasmEmitter};

use jocky_ast::Program;
use jocky_ir::{IRError, IRProgram};
use jocky_parser::parse_source;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CompilerError {
    #[error("Parse error: {0}")]
    Parser(String),
    #[error("Type error: {0}")]
    Type(#[from] TypeError),
    #[error("IR / Capability error: {0}")]
    IR(#[from] IRError),
}

pub struct Compiler;

impl Compiler {
    /// Compiles JOCKY source code through all stages into a WasmArtifact
    pub fn compile_source(source: &str) -> Result<WasmArtifact, CompilerError> {
        // Stage 1 & 2: Lexing & Parsing into AST
        let program = parse_source(source).map_err(CompilerError::Parser)?;

        // Stage 3: Semantic Analysis & Static Type Checking
        let mut type_checker = TypeChecker::new();
        type_checker.check_program(&program)?;

        // Stage 4: Capability Verification & IR Lowering
        let mut ir = IRProgram::from_ast(&program)?;

        // Stage 5: Optimization Passes (Filter Pushdown, etc.)
        ir.optimize_filter_pushdown();

        // Stage 6: WebAssembly Code Generation
        let wasm_artifact = WasmEmitter::compile(&ir);

        Ok(wasm_artifact)
    }

    /// Compiles an already-parsed Program AST
    pub fn compile_ast(program: &Program) -> Result<WasmArtifact, CompilerError> {
        let mut type_checker = TypeChecker::new();
        type_checker.check_program(program)?;

        let mut ir = IRProgram::from_ast(program)?;
        ir.optimize_filter_pushdown();
        let wasm_artifact = WasmEmitter::compile(&ir);

        Ok(wasm_artifact)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compiler_end_to_end_success() {
        let code = r#"
            case "INC-E2E-001" description "End-to-End Compiler Test";

            capabilities {
                grant driver.read;
                grant evidence.export;
            }

            query drivers = host.drivers()
                | filter(d => d.is_whql == false);

            detect unsigned_driver on drivers {
                technique: "T1068",
                severity: HIGH,
                condition: drivers.count() > 0,
                rationale: "Unsigned driver in kernel memory"
            }

            evidence.export(drivers, format=CASE_JSON_LD);
        "#;

        let artifact = Compiler::compile_source(code).expect("Should compile end-to-end");
        assert_eq!(artifact.case_id, "INC-E2E-001");
        assert_eq!(&artifact.bytecode[0..4], &[0x00, 0x61, 0x73, 0x6d]);
        assert!(artifact.required_host_imports.contains(&"jocky_host_host_drivers".to_string()));
    }

    #[test]
    fn test_compiler_capability_violation_rejection() {
        let code = r#"
            case "INC-DENIED-001" description "Capability Denial Test";

            capabilities {
                // Missing driver.read!
                grant process.read;
            }

            query drivers = host.drivers();
        "#;

        let result = Compiler::compile_source(code);
        assert!(result.is_err());
        match result.unwrap_err() {
            CompilerError::IR(IRError::CapabilityViolation { required, .. }) => {
                assert_eq!(required, "driver.read");
            }
            other => panic!("Expected capability violation, got: {:?}", other),
        }
    }
}
