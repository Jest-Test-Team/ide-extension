//! jest-security analyzer protocol v1: `info` prints an Info object; `analyze` reads one Request on
//! stdin and writes NDJSON messages, ending with a `done` message.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::io::Write;
use std::sync::Mutex;

pub const VERSION: u32 = 1;

#[derive(Deserialize)]
pub struct Extension {
    pub id: String,
    #[allow(dead_code)]
    pub version: String,
    pub path: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub manifest: Map<String, Value>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Options {
    #[serde(default)]
    #[allow(dead_code)]
    pub online: bool,
    #[serde(default)]
    pub max_file_m_b: Option<f64>,
    #[serde(default)]
    pub max_files: Option<usize>,
}

#[derive(Deserialize)]
pub struct Request {
    pub protocol: u32,
    pub extensions: Vec<Extension>,
    pub vectors: Vec<String>,
    #[serde(default)]
    pub options: Options,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Location {
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub col: Option<usize>,
}

impl Location {
    pub fn at(file: &str, line: usize, col: usize) -> Self {
        Location { file: file.to_string(), line: Some(line), col: Some(col) }
    }
    pub fn file(file: &str) -> Self {
        Location { file: file.to_string(), line: None, col: None }
    }
}

/// Writes NDJSON messages; safe to share between threads.
pub struct Emitter<W: Write> {
    out: Mutex<W>,
}

impl<W: Write> Emitter<W> {
    pub fn new(w: W) -> Self {
        Emitter { out: Mutex::new(w) }
    }

    fn write(&self, v: Value) {
        let mut o = self.out.lock().unwrap();
        let _ = serde_json::to_writer(&mut *o, &v);
        let _ = o.write_all(b"\n");
        let _ = o.flush();
    }

    #[allow(clippy::too_many_arguments)]
    pub fn signal(&self, ext: &str, vector: &str, message: &str, locations: &[Location], flow: &[Location], confidence: f64) {
        let mut m = json!({"type": "signal", "ext": ext, "vector": vector, "message": message, "confidence": confidence});
        if !locations.is_empty() {
            m["locations"] = json!(locations);
        }
        if !flow.is_empty() {
            m["flow"] = json!(flow);
        }
        self.write(m);
    }

    pub fn metric(&self, ext: &str, name: &str, value: f64) {
        self.write(json!({"type": "metric", "ext": ext, "name": name, "value": value}));
    }

    pub fn progress(&self, ext: &str, message: &str) {
        self.write(json!({"type": "progress", "ext": ext, "message": message}));
    }

    pub fn done(&self, ran: &[String], skipped: &[(String, String)]) {
        let mut m = json!({"type": "done", "ran": ran});
        if !skipped.is_empty() {
            m["skipped"] = json!(skipped.iter().map(|(id, r)| json!({"id": id, "reason": r})).collect::<Vec<_>>());
        }
        self.write(m);
    }
}
