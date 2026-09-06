use std::env;
use std::fs;
use std::process::{Command, ExitCode, Stdio};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "--health") {
        println!(r#"{"service":"atibon-agent","status":"ok","enforcement":"nftables"}"#);
        return ExitCode::SUCCESS;
    }
    let rules = args.iter().position(|a| a == "--rules")
        .and_then(|i| args.get(i + 1)).cloned()
        .unwrap_or_else(|| "/etc/atibon/atibon.nft".into());
    let validate = args.iter().any(|a| a == "--validate");
    let apply = args.iter().any(|a| a == "--apply");
    if !validate && !apply {
        eprintln!("usage: atibon-agent --health | --validate [--rules PATH] | --apply [--rules PATH]");
        return ExitCode::from(2);
    }
    if fs::metadata(&rules).is_err() {
        eprintln!("ATIBON: ruleset not readable: {rules}");
        return ExitCode::from(2);
    }
    let run = |extra: &[&str]| -> Result<(), String> {
        let output = Command::new("nft").args(extra).stdin(Stdio::null()).output()
            .map_err(|e| format!("unable to execute nft: {e}"))?;
        if output.status.success() { Ok(()) } else {
            Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
        }
    };
    if let Err(e) = run(&["-c", "-f", rules.as_str()]) {
        eprintln!("ATIBON: nft validation failed: {e}");
        return ExitCode::from(1);
    }
    if validate {
        println!("ATIBON: ruleset valid: {rules}");
        return ExitCode::SUCCESS;
    }
    if let Err(e) = run(&["-f", rules.as_str()]) {
        eprintln!("ATIBON: enforcement failed: {e}");
        return ExitCode::from(1);
    }
    println!("ATIBON: nftables policy applied successfully.");
    ExitCode::SUCCESS
}
