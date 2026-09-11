use std::env;
use std::fs;
use std::net::Ipv4Addr;
use std::process::{Command, ExitCode, Stdio};

use _native::ced::{self, TelemetrySample};

fn run_nft(args: &[&str]) -> Result<(), String> {
    let output = Command::new("nft").args(args).stdin(Stdio::null()).output()
        .map_err(|e| format!("unable to execute nft: {e}"))?;
    if output.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&output.stderr).trim().to_string()) }
}

fn ced_mode(args: &[String]) -> ExitCode {
    let Some(pos) = args.iter().position(|a| a == "--ced-telemetry") else { eprintln!("ATIBON: --ced-telemetry requires a JSON file"); return ExitCode::from(2); };
    let Some(path) = args.get(pos + 1) else { eprintln!("ATIBON: --ced-telemetry requires a JSON file"); return ExitCode::from(2); };
    let raw = match fs::read_to_string(path) { Ok(v) => v, Err(e) => { eprintln!("ATIBON: telemetry read failed: {e}"); return ExitCode::from(2); } };
    let samples: Vec<TelemetrySample> = match serde_json::from_str(&raw) { Ok(v) => v, Err(e) => { eprintln!("ATIBON: invalid telemetry JSON: {e}"); return ExitCode::from(2); } };
    let observation = ced::observe(&samples);
    println!("{}", serde_json::to_string_pretty(&observation).unwrap_or_else(|_| "{}".into()));
    if !observation.assessment.suspicious { return ExitCode::SUCCESS; }
    let Some(ip_pos) = args.iter().position(|a| a == "--ced-block-ip") else { return ExitCode::SUCCESS; };
    let Some(ip_text) = args.get(ip_pos + 1) else { eprintln!("ATIBON: --ced-block-ip requires IPv4"); return ExitCode::from(2); };
    let Ok(ip) = ip_text.parse::<Ipv4Addr>() else { eprintln!("ATIBON: invalid IPv4 address"); return ExitCode::from(2); };
    if args.iter().any(|a| a == "--ced-dry-run") { println!("ATIBON CED: would quarantine {ip} (automation_score={:.3})", observation.assessment.automation_score); return ExitCode::SUCCESS; }
    match run_nft(&["add", "element", "inet", "atibon", "ssh_abuse", "{", &ip.to_string(), "timeout", "1h", "}"]) {
        Ok(()) => { println!("ATIBON CED: {ip} quarantined from behavioral signal."); ExitCode::SUCCESS }
        Err(e) => { eprintln!("ATIBON CED: enforcement failed: {e}"); ExitCode::from(1) }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "--health") { println!(r#"{"service":"atibon-agent","status":"ok","enforcement":"nftables","ced":"enabled","pqc":"ML-KEM-768/ML-DSA-65 ready"}"#); return ExitCode::SUCCESS; }
    if args.iter().any(|a| a == "--ced-telemetry") { return ced_mode(&args); }
    if let Some(pos) = args.iter().position(|a| a == "--block-ip") {
        let Some(ip_text) = args.get(pos + 1) else { eprintln!("ATIBON: --block-ip requires an IPv4 address"); return ExitCode::from(2); };
        let Ok(ip) = ip_text.parse::<Ipv4Addr>() else { eprintln!("ATIBON: invalid IPv4 address"); return ExitCode::from(2); };
        match run_nft(&["add", "element", "inet", "atibon", "ssh_abuse", "{", &ip.to_string(), "timeout", "1h", "}"]) { Ok(()) => println!("ATIBON: {ip} added to the abuse set."), Err(e) => { eprintln!("ATIBON: unable to block {ip}: {e}"); return ExitCode::from(1); } }
        return ExitCode::SUCCESS;
    }
    let rules = args.iter().position(|a| a == "--rules").and_then(|i| args.get(i + 1)).cloned().unwrap_or_else(|| "/etc/atibon/atibon.nft".into());
    let validate = args.iter().any(|a| a == "--validate");
    let apply = args.iter().any(|a| a == "--apply");
    if !validate && !apply { eprintln!("usage: atibon-agent --health | --validate [--rules PATH] | --apply [--rules PATH] | --block-ip IPV4 | --ced-telemetry PATH [--ced-block-ip IPV4] [--ced-dry-run]"); return ExitCode::from(2); }
    if fs::metadata(&rules).is_err() { eprintln!("ATIBON: ruleset not readable: {rules}"); return ExitCode::from(2); }
    if let Err(e) = run_nft(&["-c", "-f", rules.as_str()]) { eprintln!("ATIBON: nft validation failed: {e}"); return ExitCode::from(1); }
    if validate { println!("ATIBON: ruleset valid: {rules}"); return ExitCode::SUCCESS; }
    if let Err(e) = run_nft(&["-f", rules.as_str()]) { eprintln!("ATIBON: enforcement failed: {e}"); return ExitCode::from(1); }
    println!("ATIBON: nftables policy applied successfully.");
    ExitCode::SUCCESS
}
