use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action { Allow, Drop, Reject }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub protocol: Option<u8>,
    pub dst_port: Option<u16>,
    pub action: Action,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Flow { pub protocol: u8, pub dst_port: u16 }

pub fn decide(flow: &Flow, rules: &[Rule]) -> Action {
    for rule in rules {
        if rule.protocol.map(|p| p == flow.protocol).unwrap_or(true)
            && rule.dst_port.map(|p| p == flow.dst_port).unwrap_or(true) {
            return rule.action.clone();
        }
    }
    Action::Drop
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_is_fail_closed() {
        assert!(matches!(decide(&Flow { protocol:6, dst_port:443 }, &[]), Action::Drop));
    }
}
