"""AST checks for Python files shipped inside extensions."""

from __future__ import annotations

import ast
import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

EXEC_CALLS = {
    "subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
    "subprocess.getoutput", "subprocess.getstatusoutput", "os.system", "os.popen", "os.execv", "os.execve", "os.execl",
    "os.execlp", "os.execvp", "os.execvpe", "os.spawnl", "os.spawnv", "os.spawnve", "os.startfile", "pty.spawn",
    "commands.getoutput",
}
CODE_BUILTINS = {"eval", "exec", "compile", "__import__"}
NETWORK_CALLS = {
    "urllib.request.urlopen", "urllib.request.Request", "urllib.request.urlretrieve", "urllib2.urlopen",
    "requests.get", "requests.post", "requests.put", "requests.request", "requests.Session",
    "http.client.HTTPConnection", "http.client.HTTPSConnection", "httpx.get", "httpx.post", "socket.create_connection",
}
DESERIALIZE_CALLS = {
    "pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load", "marshal.loads", "marshal.load", "dill.loads",
    "dill.load", "jsonpickle.decode", "yaml.unsafe_load", "yaml.full_load", "shelve.open", "pandas.read_pickle",
}
SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader"}
EXFIL_HOSTS = re.compile(
    r"(discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|pastebin\.com|transfer\.sh|webhook\.site|ngrok(-free)?\.(io|app|dev)"
    r"|trycloudflare\.com|pipedream\.net|requestcatcher\.com|interact\.sh|oast\.(pro|live|fun|me|site|online)|\.onion\b)",
    re.I,
)


@dataclass
class Hit:
    vector: str
    message: str
    line: int
    col: int
    confidence: float


@dataclass
class FileResult:
    hits: list[Hit] = field(default_factory=list)
    error: str | None = None


def _public_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


def suspicious_target(value: str) -> str | None:
    """Why a URL / host literal is suspicious, or None."""
    if EXFIL_HOSTS.search(value):
        return "an exfiltration / tunnelling service"
    host = urlparse(value).hostname if "://" in value else value.split(":")[0]
    if host and _public_ip(host):
        return "a literal public IP address"
    return None


class _Visitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.aliases: dict[str, str] = {}
        self.hits: list[Hit] = []

    # import tracking: local name -> qualified name
    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            self.aliases[(a.asname or a.name).split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            if a.asname:
                self.aliases[a.asname] = a.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module and node.level == 0:
            for a in node.names:
                self.aliases[a.asname or a.name] = f"{node.module}.{a.name}"

    def qualname(self, fn: ast.expr) -> str | None:
        parts: list[str] = []
        while isinstance(fn, ast.Attribute):
            parts.append(fn.attr)
            fn = fn.value
        if not isinstance(fn, ast.Name):
            return None
        head = self.aliases.get(fn.id, fn.id)
        return ".".join([head, *reversed(parts)])

    def add(self, node: ast.AST, vector: str, message: str, confidence: float) -> None:
        self.hits.append(Hit(vector, message, getattr(node, "lineno", 1), getattr(node, "col_offset", 0) + 1, confidence))

    def visit_Call(self, node: ast.Call) -> None:
        name = self.qualname(node.func)
        if name:
            self.check_call(node, name)
        self.generic_visit(node)

    def check_call(self, node: ast.Call, name: str) -> None:
        literal = [a.value for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
        if name in EXEC_CALLS:
            shell = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords)
            dynamic = not node.args or not isinstance(node.args[0], (ast.Constant, ast.List, ast.Tuple))
            what = f"`{name}(…)`" + (" with shell=True" if shell else "")
            self.add(node, "ext/python-exec", f"{what} runs an external program.", 0.9 if shell or dynamic else 0.6)
        elif name in CODE_BUILTINS and node.args and not isinstance(node.args[0], ast.Constant):
            self.add(node, "ext/python-exec", f"`{name}(…)` runs code built at run time.", 0.9)
        elif name in DESERIALIZE_CALLS:
            self.add(node, "ext/python-deserialize", f"`{name}(…)` can execute code hidden in the data it reads.", 0.8)
        elif name == "yaml.load":
            loader = next((k.value for k in node.keywords if k.arg == "Loader"), node.args[1] if len(node.args) > 1 else None)
            loader_name = loader.attr if isinstance(loader, ast.Attribute) else loader.id if isinstance(loader, ast.Name) else None
            if loader_name not in SAFE_YAML_LOADERS:
                self.add(node, "ext/python-deserialize", "`yaml.load(…)` without a safe loader can build arbitrary objects.", 0.8)
        if name in NETWORK_CALLS or name.endswith(".connect") or name.endswith(".sendto"):
            targets = literal + [
                f"{e.elts[0].value}" for e in node.args if isinstance(e, ast.Tuple) and e.elts and isinstance(e.elts[0], ast.Constant) and isinstance(e.elts[0].value, str)
            ]
            for t in targets:
                why = suspicious_target(t)
                if why:
                    self.add(node, "ext/python-network", f"`{name}(…)` contacts {why} (`{t[:80]}`).", 0.9)
                    break


def check_source(text: str, filename: str = "<file>") -> FileResult:
    try:
        tree = ast.parse(text, filename=filename)
    except (SyntaxError, ValueError) as e:
        return FileResult(error=f"{filename}: {e.__class__.__name__}")
    v = _Visitor()
    v.visit(tree)
    return FileResult(hits=v.hits)
