//! Native binaries (Mach-O, PE, ELF) and WebAssembly shipped inside extensions: format, platform,
//! signatures, imports, packing, entropy and embedded endpoints. Files are parsed, never loaded.

use crate::entropy::shannon;
use goblin::Object;
use goblin::mach::{Mach, MachO, load_command::CommandVariant};
use regex::bytes::Regex;
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub vector: &'static str,
    pub message: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Kind {
    MachO,
    Pe,
    Elf,
    Wasm,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::MachO => "Mach-O",
            Kind::Pe => "PE",
            Kind::Elf => "ELF",
            Kind::Wasm => "WebAssembly",
        }
    }
    fn os(self) -> Option<&'static str> {
        match self {
            Kind::MachO => Some("darwin"),
            Kind::Pe => Some("win32"),
            Kind::Elf => Some("linux"),
            Kind::Wasm => None,
        }
    }
}

/// Recognises a binary by its magic number.
pub fn kind(head: &[u8]) -> Option<Kind> {
    if head.len() < 8 {
        return None;
    }
    let be = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    match be {
        0xfeedface | 0xfeedfacf | 0xcefaedfe | 0xcffaedfe => return Some(Kind::MachO),
        // Fat Mach-O shares 0xcafebabe with Java class files; Java's next field is a version >= 45.
        0xcafebabe => {
            let n = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
            return (n > 0 && n < 20).then_some(Kind::MachO);
        }
        _ => {}
    }
    if head.starts_with(b"\x7fELF") {
        Some(Kind::Elf)
    } else if head.starts_with(b"MZ") {
        Some(Kind::Pe)
    } else if head.starts_with(b"\0asm") {
        Some(Kind::Wasm)
    } else {
        None
    }
}

const NATIVE_EXTS: [&str; 10] = ["", "node", "exe", "dll", "dylib", "so", "bin", "out", "pyd", "wasm"];

const DANGEROUS: [&str; 22] = [
    "ptrace",
    "task_for_pid",
    "mach_vm_write",
    "CGEventTapCreate",
    "CGEventPost",
    "SecKeychainFindGenericPassword",
    "SecKeychainItemCopyContent",
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "GetAsyncKeyState",
    "keybd_event",
    "CreateRemoteThread",
    "CreateRemoteThreadEx",
    "WriteProcessMemory",
    "VirtualAllocEx",
    "NtUnmapViewOfSection",
    "QueueUserAPC",
    "CryptUnprotectData",
    "CredEnumerateW",
    "CredEnumerateA",
    "process_vm_writev",
    "RtlCreateUserThread",
];

/// Hosts that appear in nearly every binary (certificate authorities, toolchains, standards).
const COMMON_HOSTS: [&str; 34] = [
    "apple.com",
    "microsoft.com",
    "windows.com",
    "digicert.com",
    "verisign.com",
    "symantec.com",
    "symcb.com",
    "symcd.com",
    "sectigo.com",
    "comodoca.com",
    "globalsign.com",
    "globalsign.net",
    "letsencrypt.org",
    "usertrust.com",
    "entrust.net",
    "godaddy.com",
    "thawte.com",
    "w3.org",
    "openssl.org",
    "gnu.org",
    "github.com",
    "nodejs.org",
    "mozilla.org",
    "chromium.org",
    "python.org",
    "unicode.org",
    "example.com",
    "example.org",
    "xml.org",
    "ietf.org",
    "iana.org",
    "llvm.org",
    "electronjs.org",
    "npmjs.org",
];

fn url_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?i)\b(?:https?|wss?|ftp)://([a-z0-9](?:[a-z0-9-]{0,62}\.)+[a-z]{2,24}|(?:\d{1,3}\.){3}\d{1,3})(?::\d{2,5})?").unwrap()
    })
}

/// Top-level domains accepted in embedded URLs; strings like `"https://www." + word` in minified
/// JavaScript inside single-file executables would otherwise read as hosts.
const TLDS: [&str; 52] = [
    "com", "net", "org", "io", "dev", "app", "ai", "co", "me", "xyz", "info", "biz", "top", "sh", "gg", "tk", "cc", "us", "uk", "de", "jp",
    "fr", "ru", "cn", "in", "br", "nl", "eu", "edu", "gov", "cloud", "site", "online", "live", "pro", "fun", "link", "onion", "tech",
    "store", "click", "ws", "su", "to", "ly", "pw", "ga", "ml", "cf", "gq", "kr", "tw",
];

fn plausible_host(h: &str) -> bool {
    h.rsplit('.').next().is_some_and(|t| TLDS.contains(&t))
}

fn common_host(h: &str) -> bool {
    COMMON_HOSTS.iter().any(|c| h == *c || h.ends_with(&format!(".{c}"))) || h.starts_with("ocsp.") || h.starts_with("crl")
}

fn public_ip(h: &str) -> bool {
    let p: Vec<u8> = h.split('.').filter_map(|x| x.parse().ok()).collect();
    p.len() == 4
        && !matches!(p[..], [10, ..] | [127, ..] | [0, ..] | [192, 168, ..] | [169, 254, ..])
        && !(p[0] == 172 && (16..32).contains(&p[1]))
}

struct Section {
    name: String,
    exec: bool,
    entropy: f64,
    size: usize,
}

struct Parsed {
    arch: Vec<String>,
    imports: Vec<String>,
    sections: Vec<Section>,
    /// None: format has no signature concept here (ELF); Some(false) unsigned; Some(true) signed.
    signed: Option<bool>,
    adhoc: bool,
}

fn section(name: String, exec: bool, data: &[u8]) -> Section {
    Section { name, exec, entropy: shannon(data), size: data.len() }
}

fn slice(bytes: &[u8], off: u64, size: u64) -> &[u8] {
    let (o, s) = (off as usize, size as usize);
    if o >= bytes.len() { &[] } else { &bytes[o..(o + s).min(bytes.len())] }
}

/// Reads the code-signature superblob: (signed, ad-hoc only).
fn macho_signature(m: &MachO, bytes: &[u8]) -> (bool, bool) {
    for lc in &m.load_commands {
        if let CommandVariant::CodeSignature(cs) = &lc.command {
            let blob = slice(bytes, cs.dataoff as u64, cs.datasize as u64);
            let be = |o: usize| blob.get(o..o + 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]])).unwrap_or(0);
            if be(0) != 0xfade0cc0 {
                return (true, true);
            }
            let count = be(8) as usize;
            let mut adhoc = false;
            let mut cms = false;
            for i in 0..count.min(64) {
                let off = be(12 + i * 8 + 4) as usize;
                match be(off) {
                    0xfade0c02 => adhoc |= be(off + 12) & 0x2 != 0,
                    0xfade0b01 => cms |= be(off + 4) > 8,
                    _ => {}
                }
            }
            return (true, adhoc || !cms);
        }
    }
    (false, false)
}

fn macho_arch(cpu: u32) -> String {
    match cpu {
        0x0100_0007 => "x64".into(),
        0x0100_000c => "arm64".into(),
        7 => "ia32".into(),
        12 => "arm".into(),
        c => format!("cpu {c:#x}"),
    }
}

fn parse_macho(m: &MachO, bytes: &[u8], out: &mut Parsed) {
    out.arch.push(macho_arch(m.header.cputype));
    if let Ok(imps) = m.imports() {
        out.imports.extend(imps.iter().map(|i| i.name.trim_start_matches('_').to_string()));
    }
    for seg in &m.segments {
        if let Ok(secs) = seg.sections() {
            for (s, data) in secs {
                let name = s.name().unwrap_or("").to_string();
                out.sections.push(section(name.clone(), name == "__text" || s.flags & 0x8000_0000 != 0, data));
            }
        }
    }
    let (signed, adhoc) = macho_signature(m, bytes);
    out.signed = Some(out.signed.unwrap_or(true) && signed);
    out.adhoc |= adhoc;
}

fn parse(bytes: &[u8]) -> Option<Parsed> {
    let mut out = Parsed { arch: vec![], imports: vec![], sections: vec![], signed: None, adhoc: false };
    match Object::parse(bytes).ok()? {
        Object::Mach(Mach::Binary(m)) => parse_macho(&m, bytes, &mut out),
        Object::Mach(Mach::Fat(fat)) => {
            for a in fat.iter_arches().flatten() {
                let sl = slice(bytes, a.offset as u64, a.size as u64);
                if let Ok(m) = MachO::parse(sl, 0) {
                    parse_macho(&m, sl, &mut out);
                }
            }
        }
        Object::PE(pe) => {
            out.arch.push(match pe.header.coff_header.machine {
                0x8664 => "x64".into(),
                0xaa64 => "arm64".into(),
                0x14c => "ia32".into(),
                m => format!("machine {m:#x}"),
            });
            out.imports.extend(pe.imports.iter().map(|i| i.name.to_string()));
            for s in &pe.sections {
                let data = slice(bytes, s.pointer_to_raw_data as u64, s.size_of_raw_data as u64);
                out.sections.push(section(s.name().unwrap_or("").to_string(), s.characteristics & 0x2000_0000 != 0, data));
            }
            let cert = pe.header.optional_header.and_then(|oh| oh.data_directories.get_certificate_table().copied());
            out.signed = Some(cert.is_some_and(|c| c.size > 0));
        }
        Object::Elf(elf) => {
            out.arch.push(match elf.header.e_machine {
                62 => "x64".into(),
                183 => "arm64".into(),
                40 => "armhf".into(),
                3 => "ia32".into(),
                m => format!("machine {m}"),
            });
            for sym in elf.dynsyms.iter() {
                if sym.st_shndx == 0
                    && let Some(n) = elf.dynstrtab.get_at(sym.st_name)
                    && !n.is_empty()
                {
                    out.imports.push(n.to_string());
                }
            }
            for sh in &elf.section_headers {
                if sh.sh_type == goblin::elf::section_header::SHT_NOBITS {
                    continue;
                }
                let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
                out.sections.push(section(
                    name,
                    sh.sh_flags & goblin::elf::section_header::SHF_EXECINSTR as u64 != 0,
                    slice(bytes, sh.sh_offset, sh.sh_size),
                ));
            }
        }
        _ => return None,
    }
    Some(out)
}

/// WASI imports grouped as file-system / socket / process capabilities.
pub fn wasm_capabilities(bytes: &[u8]) -> Vec<String> {
    let mut caps = std::collections::BTreeSet::new();
    for payload in wasmparser::Parser::new(0).parse_all(bytes) {
        let Ok(payload) = payload else { break };
        if let wasmparser::Payload::ImportSection(reader) = payload {
            for imp in reader.into_imports().flatten() {
                if !imp.module.starts_with("wasi") {
                    continue;
                }
                let n = imp.name;
                if n.starts_with("path_") || n == "fd_readdir" {
                    caps.insert("file system");
                } else if n.starts_with("sock_") {
                    caps.insert("sockets");
                } else if n == "proc_exec" || n.starts_with("proc_spawn") {
                    caps.insert("process spawning");
                }
            }
        }
    }
    caps.into_iter().map(String::from).collect()
}

fn ext_of(rel: &str) -> String {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    if name.contains(".so.") {
        return "so".into();
    }
    name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default()
}

/// Inspects one binary. `target` is the VSIX target platform (e.g. `darwin-arm64`), if any.
pub fn inspect(rel: &str, bytes: &[u8], target: Option<&str>) -> Vec<Finding> {
    let Some(k) = kind(bytes) else { return vec![] };
    let mut f = vec![];
    let push = |f: &mut Vec<Finding>, vector, message: String, confidence| f.push(Finding { vector, message, confidence });
    let ext = ext_of(rel);
    if !NATIVE_EXTS.contains(&ext.as_str()) {
        push(&mut f, "ext/binary-unexpected-path", format!("{rel} is a {} binary with a misleading `.{ext}` name", k.name()), 0.9);
    }
    if k == Kind::Wasm {
        let caps = wasm_capabilities(bytes);
        if !caps.is_empty() {
            push(&mut f, "ext/wasm-capabilities", format!("{rel} imports WASI {}", caps.join(", ")), 0.6);
        }
        return f;
    }
    if let (Some(t), Some(os)) = (target, k.os()) {
        let tos = t.split('-').next().unwrap_or(t);
        let tos = if tos == "alpine" { "linux" } else { tos };
        if tos != os && tos != "web" {
            push(&mut f, "ext/foreign-arch", format!("{rel} is a {os} binary in a package built for {t}"), 0.8);
        }
    }
    if bytes.len() >= 4096 && bytes[..4096].windows(4).any(|w| w == b"UPX!") {
        push(&mut f, "ext/packed-binary", format!("{rel} is UPX-packed"), 0.9);
    }
    let Some(p) = parse(bytes) else { return f };
    match p.signed {
        Some(false) => push(&mut f, "ext/unsigned-binary", format!("{rel} ({} {}) has no code signature", k.name(), p.arch.join("+")), 0.8),
        Some(true) if p.adhoc && k == Kind::MachO => {
            push(&mut f, "ext/unsigned-binary", format!("{rel} is only ad-hoc / linker signed (no Developer ID)"), 0.4)
        }
        _ => {}
    }
    let mut bad: Vec<&str> = DANGEROUS.iter().copied().filter(|d| p.imports.iter().any(|i| i == d)).collect();
    bad.dedup();
    if !bad.is_empty() {
        push(&mut f, "ext/binary-dangerous-imports", format!("{rel} imports {}", bad.join(", ")), 0.8);
    }
    if !f.iter().any(|x| x.vector == "ext/packed-binary") {
        if let Some(s) = p.sections.iter().find(|s| s.name.to_ascii_uppercase().starts_with("UPX")) {
            push(&mut f, "ext/packed-binary", format!("{rel} has packer section `{}`", s.name), 0.9);
        } else if let Some(s) = p.sections.iter().find(|s| s.exec && s.size > 16 * 1024 && s.entropy > 7.2) {
            push(
                &mut f,
                "ext/packed-binary",
                format!("{rel}: code section `{}` has {:.2} bits/byte entropy (compressed or encrypted code)", s.name, s.entropy),
                0.7,
            );
        }
    }
    if let Some(s) =
        p.sections.iter().find(|s| !s.exec && s.size > 64 * 1024 && s.entropy > 7.9 && !matches!(s.name.as_str(), ".rsrc" | "__LINKEDIT"))
    {
        push(
            &mut f,
            "ext/binary-entropy",
            format!("{rel}: section `{}` ({} KB) is near-random ({:.2} bits/byte)", s.name, s.size / 1024, s.entropy),
            0.5,
        );
    }
    let mut hosts: Vec<String> = vec![];
    for m in url_re().captures_iter(&bytes[..bytes.len().min(64 << 20)]) {
        let h = String::from_utf8_lossy(&m[1]).to_ascii_lowercase();
        let ip = h.chars().all(|c| c.is_ascii_digit() || c == '.');
        if ((ip && public_ip(&h)) || (!ip && plausible_host(&h) && !common_host(&h))) && !hosts.contains(&h) {
            hosts.push(h);
        }
    }
    if !hosts.is_empty() {
        let more = if hosts.len() > 5 { format!(", … ({})", hosts.len()) } else { String::new() };
        push(&mut f, "ext/binary-network-strings", format!("{rel} embeds endpoints {}{more}", hosts[..hosts.len().min(5)].join(", ")), 0.5);
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic() {
        assert_eq!(kind(b"\x7fELF\x02\x01\x01\0\0\0"), Some(Kind::Elf));
        assert_eq!(kind(b"\xcf\xfa\xed\xfe\x07\0\0\x01"), Some(Kind::MachO));
        assert_eq!(kind(b"\xca\xfe\xba\xbe\0\0\0\x02"), Some(Kind::MachO));
        assert_eq!(kind(b"\xca\xfe\xba\xbe\0\0\0\x34"), None, "Java class file");
        assert_eq!(kind(b"\0asm\x01\0\0\0"), Some(Kind::Wasm));
        assert_eq!(kind(b"// js file"), None);
    }

    #[test]
    fn misleading_name_upx_and_strings() {
        let mut fake = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0".to_vec();
        fake.extend(b"UPX!");
        fake.extend(vec![0u8; 5000]);
        fake.extend(
            b" http://45.13.22.7:8080/c https://collector.badhost.net/x https://www.apple.com/certificateauthority https://www.years ",
        );
        let f = inspect("media/logo.png", &fake, Some("darwin-arm64"));
        let v: Vec<_> = f.iter().map(|x| x.vector).collect();
        assert!(v.contains(&"ext/binary-unexpected-path"));
        assert!(v.contains(&"ext/packed-binary"));
        assert!(v.contains(&"ext/foreign-arch"));
        let net = f.iter().find(|x| x.vector == "ext/binary-network-strings").expect("endpoints");
        assert!(
            net.message.contains("45.13.22.7")
                && net.message.contains("collector.badhost.net")
                && !net.message.contains("apple")
                && !net.message.contains("years")
        );
        assert!(
            inspect("bin/tool", &fake, Some("linux-x64"))
                .iter()
                .all(|x| x.vector != "ext/foreign-arch" && x.vector != "ext/binary-unexpected-path")
        );
    }

    #[test]
    fn wasm_wasi_imports() {
        // (module (import "wasi_snapshot_preview1" "path_open" (func)) (import "wasi_snapshot_preview1" "sock_accept" (func)))
        let mut m = b"\0asm\x01\0\0\0".to_vec();
        m.extend([0x01, 0x04, 0x01, 0x60, 0x00, 0x00]); // type section: one func type () -> ()
        let mut imports = vec![0x02u8];
        for name in ["path_open", "sock_accept"] {
            imports.push(22);
            imports.extend(b"wasi_snapshot_preview1");
            imports.push(name.len() as u8);
            imports.extend(name.as_bytes());
            imports.extend([0x00, 0x00]);
        }
        m.push(0x02);
        m.push(imports.len() as u8);
        m.extend(imports);
        assert_eq!(wasm_capabilities(&m), vec!["file system", "sockets"]);
        assert!(inspect("lib/x.wasm", &m, None).iter().any(|f| f.vector == "ext/wasm-capabilities"));
    }

    #[test]
    fn real_binary_parses() {
        // Whatever native binary the test machine has; checks parsing does not panic and finds an arch.
        for p in ["/bin/ls", "/usr/bin/true", "C:\\Windows\\System32\\cmd.exe"] {
            if let Ok(b) = std::fs::read(p) {
                let parsed = parse(&b).expect("parses");
                assert!(!parsed.arch.is_empty());
                let _ = inspect("bin/ls", &b, None);
            }
        }
    }
}
