//! Pure-Rust WebAssembly (Wasm) Binary Bytecode Emitter for JOCKY.
//! Generates valid, deterministic, standard WebAssembly bytecode (.wasm) with capability-gated host imports.

use jocky_ast::Capability;
use jocky_ir::{IRInstruction, IRProgram};

/// WebAssembly Binary Module Artifact
#[derive(Debug, Clone)]
pub struct WasmArtifact {
    pub case_id: String,
    pub bytecode: Vec<u8>,
    pub wat_disassembly: String,
    pub granted_capabilities: Vec<Capability>,
    pub required_host_imports: Vec<String>,
}

pub struct WasmEmitter;

impl WasmEmitter {
    /// Compiles an IRProgram into a valid WebAssembly binary artifact
    pub fn compile(ir: &IRProgram) -> WasmArtifact {
        let mut required_imports = Vec::new();

        // Determine which host functions must be imported based on IR instructions
        for instr in &ir.instructions {
            match instr {
                IRInstruction::AcquireSource { domain, entity, .. } => {
                    let import_name = format!("jocky_host_{}_{}", domain, entity);
                    if !required_imports.contains(&import_name) {
                        required_imports.push(import_name);
                    }
                }
                IRInstruction::SealEvidence { .. } => {
                    let export_fn = "jocky_host_export_evidence".to_string();
                    if !required_imports.contains(&export_fn) {
                        required_imports.push(export_fn);
                    }
                }
                _ => {}
            }
        }

        // Build human-readable WAT disassembly
        let mut wat = String::new();
        wat.push_str(&format!(";; JOCKY WebAssembly Module: Case {}\n", ir.case_id));
        wat.push_str("(module\n");
        wat.push_str("  (memory (export \"memory\") 1 4)\n");

        for (idx, imp) in required_imports.iter().enumerate() {
            wat.push_str(&format!(
                "  (import \"env\" \"{}\" (func $imp_{} (param i32 i32) (result i32)))\n",
                imp, idx
            ));
        }

        wat.push_str("  (func (export \"run_case\") (result i32)\n");
        wat.push_str("    (local $status i32)\n");

        for (idx, _) in required_imports.iter().enumerate() {
            wat.push_str("    i32.const 1024\n"); // buffer offset
            wat.push_str("    i32.const 4096\n"); // buffer max size
            wat.push_str(&format!("    call $imp_{}\n", idx));
            wat.push_str("    local.set $status\n");
        }

        wat.push_str("    local.get $status\n");
        wat.push_str("  )\n");
        wat.push_str(")\n");

        // Encode binary Wasm format
        let mut bytes = Vec::new();
        // Magic header: \0asm
        bytes.extend_from_slice(&[0x00, 0x61, 0x73, 0x6d]);
        // Version 1
        bytes.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

        // Section 1: Type section
        // Type 0: (i32, i32) -> (i32) for host functions
        // Type 1: () -> (i32) for run_case
        let mut type_sec = Vec::new();
        type_sec.push(2); // 2 types
        // Type 0: func (param i32 i32) (result i32)
        type_sec.extend_from_slice(&[0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f]);
        // Type 1: func (result i32)
        type_sec.extend_from_slice(&[0x60, 0x00, 0x01, 0x7f]);
        encode_section(&mut bytes, 1, &type_sec);

        // Section 2: Import section
        let mut import_sec = Vec::new();
        import_sec.push(required_imports.len() as u8);
        for imp in &required_imports {
            encode_string(&mut import_sec, "env");
            encode_string(&mut import_sec, imp);
            import_sec.push(0x00); // import kind: func
            import_sec.push(0x00); // type index 0
        }
        if !required_imports.is_empty() {
            encode_section(&mut bytes, 2, &import_sec);
        }

        // Section 3: Function section (declares types for internal functions)
        // 1 internal function: run_case (type index 1)
        let mut func_sec = Vec::new();
        func_sec.push(1); // 1 function
        func_sec.push(1); // type index 1: () -> i32
        encode_section(&mut bytes, 3, &func_sec);

        // Section 5: Memory section
        let mut mem_sec = Vec::new();
        mem_sec.push(1); // 1 memory
        mem_sec.extend_from_slice(&[0x01, 0x01, 0x04]); // flags: has max, min 1, max 4
        encode_section(&mut bytes, 5, &mem_sec);

        // Section 7: Export section
        let mut export_sec = Vec::new();
        export_sec.push(2); // 2 exports: memory, run_case
        encode_string(&mut export_sec, "memory");
        export_sec.push(0x02); // kind: memory
        export_sec.push(0x00); // memory index 0

        encode_string(&mut export_sec, "run_case");
        export_sec.push(0x00); // kind: func
        // function index = num_imported_funcs + 0
        export_sec.push(required_imports.len() as u8);
        encode_section(&mut bytes, 7, &export_sec);

        // Section 10: Code section (body of run_case)
        let mut code_body = Vec::new();
        code_body.push(1); // 1 local variable declaration group
        code_body.extend_from_slice(&[0x01, 0x7f]); // 1 local of type i32 ($status)

        // For each imported function, call it with ptr=1024, len=4096
        for idx in 0..required_imports.len() {
            code_body.extend_from_slice(&[0x41, 0x80, 0x08]); // i32.const 1024 (LEB128)
            code_body.extend_from_slice(&[0x41, 0x80, 0x20]); // i32.const 4096 (LEB128)
            code_body.push(0x10); // call
            encode_u32(&mut code_body, idx as u32);
            code_body.extend_from_slice(&[0x21, 0x00]); // local.set 0
        }

        // Return status (or 0 if no imports)
        if required_imports.is_empty() {
            code_body.extend_from_slice(&[0x41, 0x00]); // i32.const 0
        } else {
            code_body.extend_from_slice(&[0x20, 0x00]); // local.get 0
        }
        code_body.push(0x0b); // end

        let mut code_sec = Vec::new();
        code_sec.push(1); // 1 function body
        encode_u32(&mut code_sec, code_body.len() as u32);
        code_sec.extend_from_slice(&code_body);
        encode_section(&mut bytes, 10, &code_sec);

        let mut granted = ir.granted_capabilities.iter().cloned().collect::<Vec<_>>();
        granted.sort_by(|a, b| a.as_str().cmp(b.as_str()));

        WasmArtifact {
            case_id: ir.case_id.clone(),
            bytecode: bytes,
            wat_disassembly: wat,
            granted_capabilities: granted,
            required_host_imports: required_imports,
        }
    }
}

fn encode_section(out: &mut Vec<u8>, section_id: u8, payload: &[u8]) {
    out.push(section_id);
    encode_u32(out, payload.len() as u32);
    out.extend_from_slice(payload);
}

fn encode_u32(out: &mut Vec<u8>, mut val: u32) {
    loop {
        let byte = (val & 0x7f) as u8;
        val >>= 7;
        if val == 0 {
            out.push(byte);
            break;
        } else {
            out.push(byte | 0x80);
        }
    }
}

fn encode_string(out: &mut Vec<u8>, s: &str) {
    encode_u32(out, s.len() as u32);
    out.extend_from_slice(s.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_wasm_emitter_valid_header() {
        let ir = IRProgram {
            case_id: "TEST-WASM".to_string(),
            granted_capabilities: HashSet::from([Capability::DriverRead]),
            required_capabilities: HashSet::from([Capability::DriverRead]),
            instructions: vec![IRInstruction::AcquireSource {
                dst: 0,
                domain: "host".to_string(),
                entity: "drivers".to_string(),
                filter_pushdown: None,
                required_capability: Capability::DriverRead,
            }],
        };

        let artifact = WasmEmitter::compile(&ir);
        assert_eq!(&artifact.bytecode[0..4], &[0x00, 0x61, 0x73, 0x6d]);
        assert_eq!(&artifact.bytecode[4..8], &[0x01, 0x00, 0x00, 0x00]);
        assert!(artifact.required_host_imports.contains(&"jocky_host_host_drivers".to_string()));
        assert!(artifact.wat_disassembly.contains("jocky_host_host_drivers"));
    }
}
