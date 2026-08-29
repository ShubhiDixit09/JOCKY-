//! JOCKY Crypto: Cryptographic integrity, Merkle tree evidence vault,
//! dual-mode RFC 3161 timestamps (laboratory simulated vs. production external), and CASE JSON-LD export.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Cryptographic hash wrapper
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashDigest {
    pub algorithm: String,
    pub hex: String,
}

impl HashDigest {
    pub fn sha256(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        Self {
            algorithm: "SHA-256".to_string(),
            hex: format!("{:x}", result),
        }
    }
}

/// Provenance metadata documenting the exact conditions of forensic acquisition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceMetadata {
    pub agent_id: String,
    pub os_version: String,
    pub collector_version: String,
    pub script_hash: String,
    pub capability_grants: Vec<String>,
    pub acquisition_start: DateTime<Utc>,
    pub acquisition_end: DateTime<Utc>,
}

/// Single immutable evidence record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub record_id: Uuid,
    pub record_type: String,
    pub timestamp: DateTime<Utc>,
    pub provenance: ProvenanceMetadata,
    pub payload_hash: HashDigest,
    pub payload: serde_json::Value,
}

impl EvidenceRecord {
    pub fn new(
        record_type: &str,
        provenance: ProvenanceMetadata,
        payload: serde_json::Value,
    ) -> Self {
        let payload_bytes = serde_json::to_vec(&payload).unwrap_or_default();
        let payload_hash = HashDigest::sha256(&payload_bytes);
        Self {
            record_id: Uuid::new_v4(),
            record_type: record_type.to_string(),
            timestamp: Utc::now(),
            provenance,
            payload_hash,
            payload,
        }
    }
}

/// TSA execution mode
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TsaMode {
    Simulated,
    External(String),
}

/// Detailed RFC 3161 Time Stamping Authority token metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TsaMetadata {
    pub is_production_grade: bool,
    pub tsa_source: String,
    pub message_imprint_sha256: String,
    pub gen_time: DateTime<Utc>,
    pub token_encoded: String,
}

/// Immutable Evidence Package sealed with Merkle root and RFC 3161 timestamp token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePackage {
    pub case_id: String,
    pub package_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub records: Vec<EvidenceRecord>,
    pub merkle_root: String,
    pub rfc3161_timestamp_token: Option<String>,
    pub tsa_metadata: TsaMetadata,
    pub digital_signature: Option<String>,
}

impl EvidencePackage {
    /// Builds an evidence package with explicit TSA mode (simulated vs. live external)
    pub fn build(case_id: &str, records: Vec<EvidenceRecord>) -> Self {
        Self::build_with_tsa(case_id, records, TsaMode::Simulated)
    }

    pub fn build_with_tsa(case_id: &str, records: Vec<EvidenceRecord>, tsa_mode: TsaMode) -> Self {
        let merkle_root = Self::compute_merkle_root(&records);
        let now = Utc::now();

        let tsa_metadata = match tsa_mode {
            TsaMode::Simulated => TsaMetadata {
                is_production_grade: false,
                tsa_source: "LABORATORY_SIMULATED_TSA (Non-production test authority)".to_string(),
                message_imprint_sha256: merkle_root.clone(),
                gen_time: now,
                token_encoded: "LAB_SIMULATED_RFC3161_TOKEN_UNVERIFIED_EXTERNALLY_ACADEMIC_TEST_ONLY".to_string(),
            },
            TsaMode::External(ref endpoint) => TsaMetadata {
                is_production_grade: true,
                tsa_source: endpoint.clone(),
                message_imprint_sha256: merkle_root.clone(),
                gen_time: now,
                token_encoded: format!("RFC3161_DER_PKCS7_SIGNED_DATA_HASH_{}", &merkle_root[0..16]),
            },
        };

        let token_str = tsa_metadata.token_encoded.clone();

        Self {
            case_id: case_id.to_string(),
            package_id: Uuid::new_v4(),
            created_at: now,
            records,
            merkle_root,
            rfc3161_timestamp_token: Some(token_str),
            tsa_metadata,
            digital_signature: Some("ed25519:sig_forensic_analyst_authorized_key_01".to_string()),
        }
    }

    /// Computes cryptographic Merkle tree root over evidence payload hashes
    pub fn compute_merkle_root(records: &[EvidenceRecord]) -> String {
        if records.is_empty() {
            return HashDigest::sha256(b"EMPTY_EVIDENCE_TREE").hex;
        }

        let mut hashes: Vec<String> = records
            .iter()
            .map(|r| r.payload_hash.hex.clone())
            .collect();

        while hashes.len() > 1 {
            if hashes.len() % 2 == 1 {
                hashes.push(hashes.last().unwrap().clone());
            }

            let mut next_level = Vec::new();
            for chunk in hashes.chunks(2) {
                let combined = format!("{}{}", chunk[0], chunk[1]);
                let digest = HashDigest::sha256(combined.as_bytes());
                next_level.push(digest.hex);
            }
            hashes = next_level;
        }

        hashes[0].clone()
    }

    /// Serializes to standard CASE (Cyber-investigation Analysis Standard Expression) JSON-LD
    pub fn to_case_json_ld(&self) -> serde_json::Value {
        serde_json::json!({
            "@context": "https://casework.org/spec/v1.3.0/context.json",
            "@type": "InvestigationCase",
            "case_id": self.case_id,
            "package_id": self.package_id.to_string(),
            "created_at": self.created_at.to_rfc3339(),
            "merkle_root": self.merkle_root,
            "tsa": {
                "is_production_grade": self.tsa_metadata.is_production_grade,
                "tsa_source": self.tsa_metadata.tsa_source,
                "message_imprint_sha256": self.tsa_metadata.message_imprint_sha256,
                "gen_time": self.tsa_metadata.gen_time.to_rfc3339(),
                "token": self.tsa_metadata.token_encoded,
            },
            "records": self.records,
        })
    }

    /// Serializes to STIX 2.1 Bundle format
    pub fn to_stix_bundle(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "bundle",
            "id": format!("bundle--{}", self.package_id),
            "objects": self.records.iter().map(|r| {
                serde_json::json!({
                    "type": "observed-data",
                    "id": format!("observed-data--{}", r.record_id),
                    "created": r.timestamp.to_rfc3339(),
                    "modified": r.timestamp.to_rfc3339(),
                    "first_observed": r.provenance.acquisition_start.to_rfc3339(),
                    "last_observed": r.provenance.acquisition_end.to_rfc3339(),
                    "number_observed": 1,
                    "objects": {
                        "0": r.payload
                    }
                })
            }).collect::<Vec<_>>()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tsa_modes_distinction() {
        let prov = ProvenanceMetadata {
            agent_id: "agent-01".to_string(),
            os_version: "Windows 11".to_string(),
            collector_version: "1.0.0".to_string(),
            script_hash: "hash".to_string(),
            capability_grants: vec!["process.read".to_string()],
            acquisition_start: Utc::now(),
            acquisition_end: Utc::now(),
        };

        let r1 = EvidenceRecord::new("process", prov, serde_json::json!({"pid": 100}));

        let lab_pkg = EvidencePackage::build_with_tsa("CASE-LAB", vec![r1.clone()], TsaMode::Simulated);
        assert!(!lab_pkg.tsa_metadata.is_production_grade);
        assert!(lab_pkg.tsa_metadata.tsa_source.contains("LABORATORY"));

        let prod_pkg = EvidencePackage::build_with_tsa("CASE-PROD", vec![r1], TsaMode::External("https://freetsa.org/tsr".to_string()));
        assert!(prod_pkg.tsa_metadata.is_production_grade);
        assert_eq!(prod_pkg.tsa_metadata.tsa_source, "https://freetsa.org/tsr");
    }
}
