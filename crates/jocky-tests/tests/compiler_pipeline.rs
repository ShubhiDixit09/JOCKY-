//! Integration tests: Full compiler pipeline from .jky to Wasm.

use jocky_compiler::Compiler;

const VALID_FIXTURE: &str = include_str!("../../../tests/compiler/valid_programs/simple_query.jky");
const INVALID_SYNTAX_FIXTURE: &str = include_str!("../../../tests/compiler/invalid_syntax/bad_syntax.jky");
const INVALID_TYPE_FIXTURE: &str = include_str!("../../../tests/compiler/invalid_types/bad_types.jky");

#[test]
fn test_compiler_pipeline_valid_fixtures() {
    let artifact = Compiler::compile_source(VALID_FIXTURE).expect("Valid fixture must compile");
    assert_eq!(artifact.case_id, "TEST-VALID-01");
    assert_eq!(&artifact.bytecode[0..4], &[0x00, 0x61, 0x73, 0x6d]);
}

#[test]
fn test_compiler_pipeline_invalid_syntax_rejection() {
    let res = Compiler::compile_source(INVALID_SYNTAX_FIXTURE);
    assert!(res.is_err(), "Invalid syntax must be rejected");
}

#[test]
fn test_compiler_pipeline_invalid_type_rejection() {
    let res = Compiler::compile_source(INVALID_TYPE_FIXTURE);
    assert!(res.is_err(), "Type mismatch must be rejected");
}
