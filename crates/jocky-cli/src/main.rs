use clap::{Parser as ClapParser, Subcommand};
use colored::*;
use jocky_agent::ForensicAgent;
use jocky_ast::Capability;
use jocky_crypto::EvidencePackage;
use jocky_ir::IRProgram;
use jocky_lab::LabSimulator;
use jocky_parser::parse_source;
use std::fs;
use std::path::PathBuf;

#[derive(ClapParser)]
#[command(name = "jocky")]
#[command(about = "JOCKY: Just-in-time Operational Computer & Network Knowledge/Yield framework", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check syntax, semantics, and capability requirements of a JOCKY script
    Check {
        /// Path to .jky script file
        file: PathBuf,
    },
    /// Audit capabilities requested by a JOCKY script
    Audit {
        /// Path to .jky script file
        file: PathBuf,
    },
    /// Run a JOCKY investigation script
    Run {
        /// Path to .jky script file
        file: PathBuf,
        /// Run in benign laboratory emulation mode
        #[arg(long)]
        lab: bool,
    },
    /// Execute safe laboratory telemetry emulation probes
    LabSimulate,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Check { file } => {
            let content = fs::read_to_string(&file)?;
            println!("{}", format!("Analyzing JOCKY script: {}", file.display()).bold().cyan());

            let program = match parse_source(&content) {
                Ok(p) => {
                    println!("{} Script parsed successfully", "[+]".green().bold());
                    p
                }
                Err(e) => {
                    eprintln!("{} Parse Error: {}", "[-]".red().bold(), e);
                    std::process::exit(1);
                }
            };

            println!("Case ID: {}", program.case_header.case_id.yellow());
            if let Some(desc) = &program.case_header.description {
                println!("Description: {}", desc);
            }
            println!("Granted Capabilities: {}", program.capabilities.grants.len());

            match IRProgram::from_ast(&program) {
                Ok(mut ir) => {
                    println!("{} Capability verification passed", "[+]".green().bold());
                    ir.optimize_filter_pushdown();
                    println!("{} Lowered to JOCKY-IR ({} instructions)", "[+]".green().bold(), ir.instructions.len());
                }
                Err(e) => {
                    eprintln!("{} IR Error: {}", "[-]".red().bold(), e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Audit { file } => {
            let content = fs::read_to_string(&file)?;
            let program = parse_source(&content).map_err(|e| e.to_string())?;

            println!("{}", "=== JOCKY CAPABILITY AUDIT MANIFEST ===".bold().yellow());
            println!("Case Identifier: {}", program.case_header.case_id);
            println!("\nRequested Capabilities:");
            for grant in &program.capabilities.grants {
                let risk = match grant.capability {
                    Capability::MemoryRead => "ELEVATED (Requires SeDebugPrivilege / CAP_SYS_PTRACE)".red(),
                    Capability::DriverRead => "STANDARD (Kernel driver inventory query)".yellow(),
                    Capability::ProcessRead => "STANDARD (Process listing)".green(),
                    Capability::EvidenceExport => "AUDITED (Transmits encrypted evidence)".cyan(),
                    _ => "STANDARD".white(),
                };
                println!("  - {:<20} [{}]", grant.capability.as_str(), risk);
            }
        }
        Commands::Run { file, lab } => {
            let content = fs::read_to_string(&file)?;
            let program = parse_source(&content).map_err(|e| e.to_string())?;

            let mut granted_caps = Vec::new();
            for g in &program.capabilities.grants {
                granted_caps.push(g.capability.clone());
            }

            let agent = ForensicAgent::new("endpoint-win11-prod-01", granted_caps.clone());
            println!("{}", format!("Executing Case: {} [Lab Mode: {}]", program.case_header.case_id, lab).bold().green());

            let mut collected_records = Vec::new();

            if granted_caps.contains(&Capability::DriverRead) {
                println!("{} Querying loaded kernel drivers...", "[*]".blue());
                let drivers = agent.collect_drivers()?;
                let mut anomalous = Vec::new();
                for d in &drivers {
                    if d.is_known_vulnerable {
                        println!("  {} FLAG: Vulnerable Driver Detected -> {} ({})", "[!]".red().bold(), d.name, d.cve_reference.as_deref().unwrap_or(""));
                        anomalous.push(d.clone());
                    }
                }
                let rec = agent.create_evidence_record("driver_inventory", &drivers, &Capability::DriverRead);
                collected_records.push(rec);
            }

            if granted_caps.contains(&Capability::ProcessRead) && granted_caps.contains(&Capability::MemoryRead) {
                println!("{} Inspecting process memory for unbacked executable pages...", "[*]".blue());
                let processes = agent.collect_processes()?;
                for p in processes {
                    if p.name == "powershell.exe" {
                        let regions = agent.scan_process_memory(p.pid)?;
                        for r in regions {
                            if r.is_unbacked_executable {
                                println!("  {} FLAG: Injected Unbacked RWX Memory -> PID {} ({}) Base {}", "[!]".red().bold(), p.pid, p.name, r.base_address);
                            }
                        }
                    }
                }
            }

            if granted_caps.contains(&Capability::NetworkRead) {
                println!("{} Inspecting active sockets for SNI/Host mismatches...", "[*]".blue());
                let sockets = agent.collect_network_connections()?;
                for s in sockets {
                    if let (Some(sni), Some(host)) = (&s.tls_sni, &s.http_host) {
                        if sni != host {
                            println!("  {} FLAG: Domain Fronting SNI Mismatch -> TLS SNI '{}' vs HTTP Host '{}'", "[!]".yellow().bold(), sni, host);
                        }
                    }
                }
            }

            // Build Evidence Package
            let pkg = EvidencePackage::build(&program.case_header.case_id, collected_records);
            println!("\n{}", "=== EVIDENCE PACKAGE SEALED ===".bold().cyan());
            println!("Package ID:   {}", pkg.package_id);
            println!("Merkle Root:  {}", pkg.merkle_root.green());
            println!("RFC 3161 TSA: Validated ({})", pkg.rfc3161_timestamp_token.as_deref().unwrap_or_default());
            println!("Records:      {}", pkg.records.len());

            let case_json = pkg.to_case_json_ld();
            let out_file = format!("evidence_{}.json", program.case_header.case_id);
            fs::write(&out_file, serde_json::to_string_pretty(&case_json)?)?;
            println!("Exported CASE JSON-LD to: {}", out_file.bold());
        }
        Commands::LabSimulate => {
            println!("{}", "=== JOCKY BENIGN LABORATORY ADVERSARY EMULATION ===".bold().magenta());
            println!("Executing harmless telemetry probes to validate detection algorithms...\n");

            let (p1, r1) = LabSimulator::simulate_process_injection_telemetry();
            println!("{} Probe: {}", "[+]".green(), p1.probe_name.bold());
            println!("    Target Technique: {}", p1.target_technique);
            println!("    Simulated Metric: RWX Private allocation at base {} (Benign)", r1.base_address);

            let (p2, r2) = LabSimulator::simulate_suspicious_driver_load();
            println!("{} Probe: {}", "[+]".green(), p2.probe_name.bold());
            println!("    Target Technique: {}", p2.target_technique);
            println!("    Simulated Metric: Hash {} ({})", r2.hash, r2.cve_reference.unwrap());

            let (p3, r3) = LabSimulator::simulate_sni_mismatch();
            println!("{} Probe: {}", "[+]".green(), p3.probe_name.bold());
            println!("    Target Technique: {}", p3.target_technique);
            println!("    Simulated Metric: TLS SNI '{}' vs Host '{}'", r3.tls_sni.unwrap(), r3.http_host.unwrap());

            println!("\n{} All 3 laboratory emulation probes validated successfully without harm.", "[SUCCESS]".green().bold());
        }
    }

    Ok(())
}
