use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ShadowAction { Allow, Monitor, Shadow, Quarantine, Block }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShadowAssessment { pub action: ShadowAction, pub score: u16, pub reasons: Vec<String>, pub host: String, pub port: u16 }

fn private_v4(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_broadcast() || ip.octets()[0] == 0
}
fn private_v6(ip: Ipv6Addr) -> bool {
    ip.is_loopback() || ip.is_unspecified() || ip.is_unique_local() || ip.is_unicast_link_local()
}

pub fn assess_url(raw: &str) -> Result<ShadowAssessment, String> {
    let (scheme, rest) = raw.split_once("://").ok_or("invalid_url")?;
    if scheme != "http" && scheme != "https" { return Err("unsupported_scheme".into()); }
    let authority = rest.split('/').next().unwrap_or("").rsplit('@').next().unwrap_or("");
    if authority.is_empty() { return Err("missing_host".into()); }
    let (host, port) = if let Some(s) = authority.strip_prefix('[') {
        let end = s.find(']').ok_or("invalid_ipv6")?;
        let h = &s[..end];
        let p = s[end+1..].strip_prefix(':').map(|x| x.parse().map_err(|_|"invalid_port")).transpose()?.unwrap_or(if scheme=="https"{443}else{80});
        (h.to_string(), p)
    } else if let Some((h,p)) = authority.rsplit_once(':') {
        if p.chars().all(|c| c.is_ascii_digit()) { (h.to_string(), p.parse().map_err(|_|"invalid_port")?) } else {(authority.to_string(), if scheme=="https"{443}else{80})}
    } else {(authority.to_string(), if scheme=="https"{443}else{80})};

    let mut score = 0u16;
    let mut reasons = Vec::new();
    if let Ok(ip) = IpAddr::from_str(&host) {
        let private = match ip { IpAddr::V4(v)=>private_v4(v), IpAddr::V6(v)=>private_v6(v) };
        if private { score += 100; reasons.push("private_or_local_destination".into()); }
    }
    let lower = host.to_ascii_lowercase();
    if !lower.contains('.') { score += 25; reasons.push("non_fqdn_host".into()); }
    if lower.ends_with(".local") || lower.ends_with(".internal") || lower.ends_with(".localhost") { score += 80; reasons.push("local_namespace".into()); }
    if [22,23,25,3389,5900].contains(&port) { score += 30; reasons.push("sensitive_service_port".into()); }

    let action = if score >= 100 { ShadowAction::Block } else if score >= 70 { ShadowAction::Quarantine } else if score >= 40 { ShadowAction::Shadow } else if score >= 20 { ShadowAction::Monitor } else { ShadowAction::Allow };
    Ok(ShadowAssessment { action, score, reasons, host, port })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn blocks_loopback() { assert_eq!(assess_url("http://127.0.0.1:8080/").unwrap().action, ShadowAction::Block); }
    #[test] fn allows_https() { assert_eq!(assess_url("https://example.com/").unwrap().action, ShadowAction::Allow); }
    #[test] fn quarantines_local() { assert_eq!(assess_url("https://router.local/").unwrap().action, ShadowAction::Quarantine); }
}
