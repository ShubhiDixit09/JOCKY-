//! JOCKY Lab: Safe laboratory-only adversary emulation subsystem.
//! Generates benign, synthetic telemetry probes for evaluating detection rules without
//! performing harmful actions, executing exploit code, or tampering with system security.

use chrono::Utc;
use jocky_agent::{DriverRecord, MemoryRegionRecord, NetworkRecord};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabTelemetryProbe {
    pub probe_name: String,
    pub description: String,
    pub created_at: String,
    pub is_benign_simulation: bool,
    pub target_technique: String,
}

pub struct LabSimulator;

impl LabSimulator {
    /// Generates a benign process injection telemetry probe.
    /// Allocates an isolated, safe memory canary tag to verify that memory scanners
    /// properly detect unbacked executable segments without deploying offensive payloads.
    pub fn simulate_process_injection_telemetry() -> (LabTelemetryProbe, MemoryRegionRecord) {
        let probe = LabTelemetryProbe {
            probe_name: "LAB_SIM_PROCESS_INJECTION_RWX".to_string(),
            description: "Safe canary allocation simulating RWX private memory signature of reflective loaders".to_string(),
            created_at: Utc::now().to_rfc3339(),
            is_benign_simulation: true,
            target_technique: "T1055 - Process Injection".to_string(),
        };

        let simulated_record = MemoryRegionRecord {
            pid: 9999,
            base_address: "0x000002A100000000".to_string(),
            size_bytes: 4096,
            protection: "PAGE_EXECUTE_READWRITE".to_string(),
            allocation_type: "MEM_PRIVATE".to_string(),
            is_unbacked_executable: true,
        };

        (probe, simulated_record)
    }

    /// Generates a benign vulnerable driver load telemetry probe.
    /// Tests BYOVD detection against known catalog hashes without installing kernel drivers.
    pub fn simulate_suspicious_driver_load() -> (LabTelemetryProbe, DriverRecord) {
        let probe = LabTelemetryProbe {
            probe_name: "LAB_SIM_BYOVD_LATEST_CVE".to_string(),
            description: "Synthetic driver load event simulating presence of signed driver with CVE-2018-19320".to_string(),
            created_at: Utc::now().to_rfc3339(),
            is_benign_simulation: true,
            target_technique: "T1068 / T1543.003 - Bring Your Own Vulnerable Driver".to_string(),
        };

        let simulated_record = DriverRecord {
            name: "simulated_gdrv.sys".to_string(),
            base_address: "0xFFFFF80055000000".to_string(),
            file_path: "C:\\Windows\\Temp\\simulated_gdrv.sys".to_string(),
            hash: "sha256:4b2e1b0000000000000000000000000000000000000000000000000000000000".to_string(),
            is_whql: false,
            is_known_vulnerable: true,
            cve_reference: Some("CVE-2018-19320 (GIGABYTE Kernel Arbitrary Read/Write)".to_string()),
        };

        (probe, simulated_record)
    }

    /// Generates a benign TLS SNI / Host mismatch telemetry probe.
    /// Evaluates domain-fronting detection logic safely.
    pub fn simulate_sni_mismatch() -> (LabTelemetryProbe, NetworkRecord) {
        let probe = LabTelemetryProbe {
            probe_name: "LAB_SIM_DOMAIN_FRONTING_MISMATCH".to_string(),
            description: "Synthetic socket record exhibiting TLS SNI divergence from HTTP Host header".to_string(),
            created_at: Utc::now().to_rfc3339(),
            is_benign_simulation: true,
            target_technique: "T1071.001 - Domain Fronting".to_string(),
        };

        let simulated_record = NetworkRecord {
            protocol: "TCP".to_string(),
            local_addr: "127.0.0.1:49152".to_string(),
            remote_addr: "127.0.0.1:9443".to_string(),
            state: "ESTABLISHED".to_string(),
            pid: 9999,
            tls_sni: Some("fronted-cdn.domain.local".to_string()),
            http_host: Some("covert-c2-destination.internal".to_string()),
        };

        (probe, simulated_record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lab_process_injection_probe() {
        let (probe, rec) = LabSimulator::simulate_process_injection_telemetry();
        assert!(probe.is_benign_simulation);
        assert_eq!(probe.target_technique, "T1055 - Process Injection");
        assert!(rec.is_unbacked_executable);
        assert_eq!(rec.protection, "PAGE_EXECUTE_READWRITE");
        assert_eq!(rec.allocation_type, "MEM_PRIVATE");
    }

    #[test]
    fn test_lab_byovd_probe() {
        let (probe, rec) = LabSimulator::simulate_suspicious_driver_load();
        assert!(probe.is_benign_simulation);
        assert_eq!(probe.target_technique, "T1068 / T1543.003 - Bring Your Own Vulnerable Driver");
        assert!(rec.is_known_vulnerable);
        assert_eq!(rec.name, "simulated_gdrv.sys");
    }

    #[test]
    fn test_lab_domain_fronting_probe() {
        let (probe, rec) = LabSimulator::simulate_sni_mismatch();
        assert!(probe.is_benign_simulation);
        assert_eq!(probe.target_technique, "T1071.001 - Domain Fronting");
        assert_ne!(rec.tls_sni, rec.http_host);
    }
}

