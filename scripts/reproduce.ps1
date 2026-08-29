# JOCKY Framework: Automated Research Reproduction Script (Windows PowerShell)
# Re-runs all test suites, capability proofs, Wasm compilation, granular profiling, and multi-tier benchmark evaluation.

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  JOCKY: Academic Research & Benchmark Reproduction Pipeline" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Compile Workspace
Write-Host "`n[*] Stage 1: Compiling JOCKY Workspace..." -ForegroundColor Yellow
cargo build --workspace
if ($LASTEXITCODE -ne 0) { Write-Error "Build failed"; exit 1 }

# 2. Run Comprehensive Test Suite (Capability Matrix + Property Tests + Invariants)
Write-Host "`n[*] Stage 2: Running Unit, Capability Matrix, & Integration Tests..." -ForegroundColor Yellow
cargo test --workspace
if ($LASTEXITCODE -ne 0) { Write-Error "Test suite failed"; exit 1 }

# 3. Compile JOCKY Script to WebAssembly Bytecode
Write-Host "`n[*] Stage 3: Compiling JOCKY DSL to WebAssembly (.wasm & .wat)..." -ForegroundColor Yellow
cargo run --bin jocky -- compile examples/detect_byovd.jky --emit-wat
if ($LASTEXITCODE -ne 0) { Write-Error "Wasm compilation failed"; exit 1 }

# 4. Execute End-to-End Investigation with Deconstructed Microbenchmark Profiling
Write-Host "`n[*] Stage 4: Executing End-to-End Case with Latency Profiling..." -ForegroundColor Yellow
cargo run --bin jocky -- run examples/detect_byovd.jky --profile
if ($LASTEXITCODE -ne 0) { Write-Error "Execution failed"; exit 1 }

# 5. Cryptographically Audit Evidence Package (Verifying Merkle Root & Truthful TSA Status)
Write-Host "`n[*] Stage 5: Cryptographically Auditing Evidence Package..." -ForegroundColor Yellow
cargo run --bin jocky -- verify evidence_INC-BYOVD-001.json
if ($LASTEXITCODE -ne 0) { Write-Error "Evidence audit failed"; exit 1 }

# 6. Execute Detection Benchmark Evaluation across Multi-Tier Datasets
Write-Host "`n[*] Stage 6: Running Multi-Tier Benchmark Harness (Smoke + Adversarial)..." -ForegroundColor Yellow
cargo run --bin jocky -- evaluate --dataset-dir datasets
if ($LASTEXITCODE -ne 0) { Write-Error "Evaluation failed"; exit 1 }

# 7. Record Git Commit SHA in Reproducibility Manifest
git rev-parse HEAD | Out-File -FilePath results/git_commit.txt -Encoding utf8

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host "  [SUCCESS] All experimental benchmarks reproduced cleanly." -ForegroundColor Green
Write-Host "  Reproducibility Manifests:" -ForegroundColor Green
Write-Host "    - results/evaluation_metrics.json & .csv" -ForegroundColor White
Write-Host "    - results/latency_breakdown.json & .csv" -ForegroundColor White
Write-Host "    - results/dataset_hashes.json" -ForegroundColor White
Write-Host "    - results/environment.json & compiler_version.json" -ForegroundColor White
Write-Host "    - results/baseline_comparison.csv" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Green
