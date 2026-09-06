use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize)]
pub struct AuditEvent<'a> {
    pub timestamp: u64,
    pub action: &'a str,
    pub source: &'a str,
    pub reason: &'a str,
}

pub struct AuditLog { writer: Mutex<BufWriter<File>> }

impl AuditLog {
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { writer: Mutex::new(BufWriter::new(file)) })
    }
    pub fn record(&self, action:&str, source:&str, reason:&str) -> std::io::Result<()> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let line = serde_json::to_string(&AuditEvent { timestamp, action, source, reason }).expect("audit serialization");
        let mut writer = self.writer.lock().map_err(|_| std::io::Error::other("audit lock poisoned"))?;
        writeln!(writer, "{line}")?;
        writer.flush()
    }
}
