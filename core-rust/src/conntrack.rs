use std::collections::HashMap;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowKey {
    pub src: String,
    pub dst: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TcpState { New, Established, Closing }

#[derive(Clone, Debug)]
pub struct FlowState { pub state: TcpState, pub last_seen: Instant }

pub struct ConnectionTracker {
    flows: HashMap<FlowKey, FlowState>,
    max_flows: usize,
    idle_timeout: Duration,
}

impl ConnectionTracker {
    pub fn new(max_flows: usize, idle_timeout: Duration) -> Self {
        Self { flows: HashMap::with_capacity(max_flows.min(65_536)), max_flows: max_flows.max(1), idle_timeout }
    }
    pub fn observe(&mut self, key: FlowKey, syn: bool, fin: bool, rst: bool) -> Result<TcpState, &'static str> {
        self.expire();
        if rst { self.flows.remove(&key); return Ok(TcpState::Closing); }
        if let Some(flow) = self.flows.get_mut(&key) {
            flow.last_seen = Instant::now();
            if fin { flow.state = TcpState::Closing; }
            return Ok(flow.state);
        }
        if self.flows.len() >= self.max_flows { return Err("connection tracking capacity exhausted"); }
        let state = if syn { TcpState::New } else { TcpState::Established };
        self.flows.insert(key, FlowState { state, last_seen: Instant::now() });
        Ok(state)
    }
    pub fn len(&self) -> usize { self.flows.len() }
    pub fn expire(&mut self) {
        let now = Instant::now();
        self.flows.retain(|_, f| now.duration_since(f.last_seen) <= self.idle_timeout);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tracks_flow() {
        let key = FlowKey { src:"10.0.0.1".into(), dst:"10.0.0.2".into(), src_port:1234, dst_port:443, protocol:6 };
        let mut t = ConnectionTracker::new(4, Duration::from_secs(60));
        assert_eq!(t.observe(key.clone(), true, false, false).unwrap(), TcpState::New);
        assert_eq!(t.observe(key, false, false, false).unwrap(), TcpState::New);
        assert_eq!(t.len(), 1);
    }
}
