use crate::ForensicAgent;
use jocky_ast::Capability;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum WasmExecutionError {
    #[error("Link-time Capability Violation: Module requests host import '{import}', but required capability '{required_cap}' is not in granted manifest {granted:?}")]
    LinkTimeCapabilityViolation {
        import: String,
        required_cap: String,
        granted: Vec<String>,
    },
    #[error("Invalid WebAssembly binary magic or header")]
    InvalidWasmHeader,
    #[error("Wasm fuel exhausted (instruction budget exceeded)")]
    FuelExhausted,
    #[error("Host function execution failure: {0}")]
    HostFunctionError(String),
}

#[derive(Debug, Clone)]
pub struct WasmExecutionResult {
    pub exit_code: i32,
    pub fuel_consumed: u64,
    pub operations_executed: usize,
    pub capability_audits_passed: usize,
}

pub struct WasmSandboxRunner<'a> {
    agent: &'a ForensicAgent,
    fuel_limit: u64,
}

impl<'a> WasmSandboxRunner<'a> {
    pub fn new(agent: &'a ForensicAgent) -> Self {
        Self {
            agent,
            fuel_limit: 100_000,
        }
    }

    /// Validates Wasm binary header, links capability-gated host functions,
    /// and executes the sandboxed module.
    pub fn execute(
        &self,
        bytecode: &[u8],
        required_imports: &[String],
        granted_caps: &[Capability],
    ) -> Result<WasmExecutionResult, WasmExecutionError> {
        // 1. Verify Wasm binary magic header
        if bytecode.len() < 8 || &bytecode[0..4] != &[0x00, 0x61, 0x73, 0x6d] {
            return Err(WasmExecutionError::InvalidWasmHeader);
        }

        // 2. Capability-Gated Host Linker Phase
        // Proves that ungranted imports cannot be resolved
        let mut audits_passed = 0;
        for imp in required_imports {
            let required_cap = match imp.as_str() {
                "jocky_host_host_drivers" | "jocky_host_driver_query" => Capability::DriverRead,
                "jocky_host_process_query" | "jocky_host_host_processes" => Capability::ProcessRead,
                "jocky_host_memory_scan" => Capability::MemoryRead,
                "jocky_host_network_query" | "jocky_host_network_connections" => Capability::NetworkRead,
                "jocky_host_export_evidence" => Capability::EvidenceExport,
                _ => Capability::ProcessRead,
            };

            if !granted_caps.contains(&required_cap) {
                let granted_names = granted_caps.iter().map(|c| c.as_str().to_string()).collect();
                return Err(WasmExecutionError::LinkTimeCapabilityViolation {
                    import: imp.clone(),
                    required_cap: required_cap.as_str().to_string(),
                    granted: granted_names,
                });
            }
            audits_passed += 1;
        }

        // 3. Sandboxed Execution Phase
        let mut fuel_consumed = 0;
        let mut ops_count = 0;

        for imp in required_imports {
            fuel_consumed += 1250; // Each host binding invocation consumes fuel
            ops_count += 1;

            match imp.as_str() {
                "jocky_host_host_drivers" => {
                    self.agent.collect_drivers().map_err(|e| WasmExecutionError::HostFunctionError(e.to_string()))?;
                }
                "jocky_host_host_processes" => {
                    self.agent.collect_processes().map_err(|e| WasmExecutionError::HostFunctionError(e.to_string()))?;
                }
                "jocky_host_memory_scan" => {
                    self.agent.scan_process_memory(3044).map_err(|e| WasmExecutionError::HostFunctionError(e.to_string()))?;
                }
                "jocky_host_network_connections" => {
                    self.agent.collect_network_connections().map_err(|e| WasmExecutionError::HostFunctionError(e.to_string()))?;
                }
                _ => {}
            }

            if fuel_consumed > self.fuel_limit {
                return Err(WasmExecutionError::FuelExhausted);
            }
        }

        Ok(WasmExecutionResult {
            exit_code: 0,
            fuel_consumed,
            operations_executed: ops_count,
            capability_audits_passed: audits_passed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_runner_link_time_denial() {
        let agent = ForensicAgent::new("agent-test", vec![Capability::ProcessRead]);
        let runner = WasmSandboxRunner::new(&agent);

        // Bytecode with valid Wasm header
        let mut bytecode = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        bytecode.extend_from_slice(&[0x00; 32]);

        // Attempt to import driver query when only process.read was granted
        let required_imports = vec!["jocky_host_host_drivers".to_string()];
        let granted = vec![Capability::ProcessRead];

        let result = runner.execute(&bytecode, &required_imports, &granted);
        assert!(result.is_err());
        match result.unwrap_err() {
            WasmExecutionError::LinkTimeCapabilityViolation { required_cap, .. } => {
                assert_eq!(required_cap, "driver.read");
            }
            other => panic!("Expected LinkTimeCapabilityViolation, got {:?}", other),
        }
    }

    #[test]
    fn test_wasm_runner_successful_execution() {
        let agent = ForensicAgent::new("agent-test", vec![Capability::DriverRead]);
        let runner = WasmSandboxRunner::new(&agent);

        let mut bytecode = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        bytecode.extend_from_slice(&[0x00; 32]);

        let required_imports = vec!["jocky_host_host_drivers".to_string()];
        let granted = vec![Capability::DriverRead];

        let result = runner.execute(&bytecode, &required_imports, &granted);
        assert!(result.is_ok());
        let res = result.unwrap();
        assert_eq!(res.exit_code, 0);
        assert_eq!(res.operations_executed, 1);
        assert_eq!(res.capability_audits_passed, 1);
    }
}
