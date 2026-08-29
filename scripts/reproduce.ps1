# JOCKY Framework: Automated Research Reproduction Script (Windows PowerShell)
# Re-runs all test suites, capability proofs, Wasm compilation, and quantitative benchmark evaluation.

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  JOCKY: Academic Research & Benchmark Reproduction Pipeline" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Compile Workspace
Write-Host "`n[*] Stage 1: Compiling JOCKY Workspace..." -ForegroundColor Yellow
cargo build --workspace
if ($LASTEXITCODE -ne 0) { Write-Error "Build failed"; exit 1 }

# 2. Run Test Suite (including Capability Security Proofs Tests A-F)
Write-Host "`n[*] Stage 2: Running Unit & Capability Proof Test Suite..." -ForegroundColor Yellow
cargo test --workspace
if ($LASTEXITCODE -ne 0) { Write-Error "Test suite failed"; exit 1 }

# 3. Compile JOCKY Script to WebAssembly Bytecode
Write-Host "`n[*] Stage 3: Compiling JOCKY DSL to WebAssembly (.wasm & .wat)..." -ForegroundColor Yellow
cargo run --bin jocky -- compile examples/detect_byovd.jky --emit-wat
if ($LASTEXITCODE -ne 0) { Write-Error "Wasm compilation failed"; exit 1 }

# 4. Execute End-to-End Investigation Query
Write-Host "`n[*] Stage 4: Executing End-to-End Case Investigation..." -ForegroundColor Yellow
cargo run --bin jocky -- run examples/detect_byovd.jky
if ($LASTEXITCODE -ne 0) { Write-Error "Execution failed"; exit 1 }

# 5. Verify Evidence Package
Write-Host "`n[*] Stage 5: Cryptographically Auditing Evidence Package..." -ForegroundColor Yellow
cargo run --bin jocky -- verify evidence_INC-BYOVD-001.json
if ($LASTEXITCODE -ne 0) { Write-Error "Evidence audit failed"; exit 1 }

# 6. Execute Detection Benchmark Evaluation across Datasets
Write-Host "`n[*] Stage 6: Running Quantitative Detection Benchmark Harness..." -ForegroundColor Yellow
cargo run --bin jocky -- evaluate --dataset-dir datasets
if ($LASTEXITCODE -ne 0) { Write-Error "Evaluation failed"; exit 1 }

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host "  [SUCCESS] All experimental benchmarks reproduced cleanly." -ForegroundColor Green
Write-Host "  Metrics saved to: results/evaluation_metrics.json & .csv" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
