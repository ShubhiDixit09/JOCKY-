#!/usr/bin/env bash
# JOCKY Framework: Automated Research Reproduction Script (POSIX Bash)
set -euo pipefail

echo "============================================================"
echo "  JOCKY: Academic Research & Benchmark Reproduction Pipeline"
echo "============================================================"

# 1. Compile Workspace
echo -e "\n[*] Stage 1: Compiling JOCKY Workspace..."
cargo build --workspace

# 2. Run Test Suite (including Capability Security Proofs Tests A-F)
echo -e "\n[*] Stage 2: Running Unit & Capability Proof Test Suite..."
cargo test --workspace

# 3. Compile JOCKY Script to WebAssembly Bytecode
echo -e "\n[*] Stage 3: Compiling JOCKY DSL to WebAssembly (.wasm & .wat)..."
cargo run --bin jocky -- compile examples/detect_byovd.jky --emit-wat

# 4. Execute End-to-End Investigation Query
echo -e "\n[*] Stage 4: Executing End-to-End Case Investigation..."
cargo run --bin jocky -- run examples/detect_byovd.jky

# 5. Verify Evidence Package
echo -e "\n[*] Stage 5: Cryptographically Auditing Evidence Package..."
cargo run --bin jocky -- verify evidence_INC-BYOVD-001.json

# 6. Execute Detection Benchmark Evaluation across Datasets
echo -e "\n[*] Stage 6: Running Quantitative Detection Benchmark Harness..."
cargo run --bin jocky -- evaluate --dataset-dir datasets

echo "============================================================"
echo "  [SUCCESS] All experimental benchmarks reproduced cleanly."
echo "  Metrics saved to: results/evaluation_metrics.json & .csv"
echo "============================================================"
