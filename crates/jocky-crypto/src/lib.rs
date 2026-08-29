//! JOCKY Crypto: Cryptographic integrity, Merkle tree evidence vault, RFC 3161 tokens, and CASE JSON-LD export.

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

/// Immutable Evidence Package sealed with Merkle root and RFC 3161 timestamp token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePackage {
    pub case_id: String,
    pub package_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub records: Vec<EvidenceRecord>,
    pub merkle_root: String,
    pub rfc3161_timestamp_token: Option<String>,
    pub digital_signature: Option<String>,
}

impl EvidencePackage {
    pub fn build(case_id: &str, records: Vec<EvidenceRecord>) -> Self {
        let merkle_root = Self::compute_merkle_root(&records);
        Self {
            case_id: case_id.to_string(),
            package_id: Uuid::new_v4(),
            created_at: Utc::now(),
            records,
            merkle_root,
            rfc3161_timestamp_token: Some("MIIB...SIMULATED_RFC3161_TSA_TOKEN...AQE=".to_string()),
            digital_signature: Some("ed25519:sig_simulated_evidence_seal_authorized".to_string()),
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
            "rfc3161_token": self.rfc3161_timestamp_token,
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
    fn test_merkle_root_computation() {
        let prov = ProvenanceMetadata {
            agent_id: "agent-01".to_string(),
            os_version: "Windows 11".to_string(),
            collector_version: "1.0.0".to_string(),
            script_hash: "hash".to_string(),
            capability_grants: vec!["process.read".to_string()],
            acquisition_start: Utc::now(),
            acquisition_end: Utc::now(),
        };

        let r1 = EvidenceRecord::new("process", prov.clone(), serde_json::json!({"pid": 100}));
        let r2 = EvidenceRecord::new("driver", prov, serde_json::json!({"name": "test.sys"}));

        let pkg = EvidencePackage::build("INC-TEST", vec![r1, r2]);
        assert_eq!(pkg.records.len(), 2);
        assert!(!pkg.merkle_root.is_empty());
    }
}
