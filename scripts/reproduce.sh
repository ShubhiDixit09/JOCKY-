#!/usr/bin/env bash
# JOCKY Framework: Automated Research Reproduction Script (POSIX Bash)
set -euo pipefail

echo "============================================================"
echo "  JOCKY: Academic Research & Benchmark Reproduction Pipeline"
echo "============================================================"

# 1. Compile Workspace
echo -e "\n[*] Stage 1: Compiling JOCKY Workspace..."
cargo build --workspace

# 2. Run Comprehensive Test Suite (Capability Matrix + Property Tests + Invariants)
echo -e "\n[*] Stage 2: Running Unit, Capability Matrix, & Integration Tests..."
cargo test --workspace

# 3. Compile JOCKY Script to WebAssembly Bytecode
echo -e "\n[*] Stage 3: Compiling JOCKY DSL to WebAssembly (.wasm & .wat)..."
cargo run --bin jocky -- compile examples/detect_byovd.jky --emit-wat

# 4. Execute End-to-End Investigation with Deconstructed Microbenchmark Profiling
echo -e "\n[*] Stage 4: Executing End-to-End Case with Latency Profiling..."
cargo run --bin jocky -- run examples/detect_byovd.jky --profile

# 5. Cryptographically Audit Evidence Package (Verifying Merkle Root & Truthful TSA Status)
echo -e "\n[*] Stage 5: Cryptographically Auditing Evidence Package..."
cargo run --bin jocky -- verify evidence_INC-BYOVD-001.json

# 6. Execute Detection Benchmark Evaluation across Multi-Tier Datasets
echo -e "\n[*] Stage 6: Running Multi-Tier Benchmark Harness (Smoke + Adversarial)..."
cargo run --bin jocky -- evaluate --dataset-dir datasets

# 7. Record Git Commit SHA in Reproducibility Manifest
git rev-parse HEAD > results/git_commit.txt

echo "============================================================"
echo "  [SUCCESS] All experimental benchmarks reproduced cleanly."
echo "  Reproducibility Manifests:"
echo "    - results/evaluation_metrics.json & .csv"
echo "    - results/latency_breakdown.json & .csv"
echo "    - results/dataset_hashes.json"
echo "    - results/environment.json & compiler_version.json"
echo "    - results/baseline_comparison.csv"
echo "============================================================"
