use pyo3::prelude::*;
use parking_lot::RwLock;
use serde::{Deserialize,Serialize};
use std::sync::Arc;
#[derive(Clone,Debug,Serialize,Deserialize)] pub struct Rule{pub id:String,pub priority:u32,pub pattern:Vec<u8>,pub action:u8}
#[pyclass] pub struct FilterEngine{rules:Arc<RwLock<Vec<Rule>>>,max_packet_size:usize}
#[pymethods] impl FilterEngine{#[new] pub fn new(max_packet_size:usize)->Self{Self{rules:Arc::new(RwLock::new(Vec::new())),max_packet_size}}
pub fn add_rule(&self,json:&str)->PyResult<()>{let r:Rule=serde_json::from_str(json).map_err(|e|pyo3::exceptions::PyValueError::new_err(e.to_string()))?;if r.pattern.len()>self.max_packet_size{return Err(pyo3::exceptions::PyValueError::new_err("pattern too large"));}let mut v=self.rules.write();v.push(r);v.sort_by(|a,b|b.priority.cmp(&a.priority));Ok(())}
pub fn analyze_packet(&self,data:&[u8])->PyResult<String>{if data.is_empty()||data.len()>self.max_packet_size{return Err(pyo3::exceptions::PyValueError::new_err("invalid packet size"));}let v=self.rules.read();let mut action=0u8;let mut matched=Vec::new();for r in v.iter(){if !r.pattern.is_empty()&&data.windows(r.pattern.len()).any(|w|w==r.pattern){action=r.action;matched.push(r.id.clone());}}Ok(serde_json::json!({"action":action,"matched_rules":matched,"payload_len":data.len()}).to_string())}}
