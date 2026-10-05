"""jest-ext-py: `info` | `analyze` (one JSON request on stdin → NDJSON on stdout) | `version`."""

from __future__ import annotations

import json
import os
import sys
from collections import defaultdict
from pathlib import Path

from . import __version__
from .pycheck import check_source

PROTOCOL = 1
AST_VECTORS = ["ext/python-exec", "ext/python-network", "ext/python-deserialize"]
MODEL_VECTORS = ["ext/ml-anomaly"]
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "site-packages"}
MAX_LOCATIONS = 20


def out(msg: dict) -> None:
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def model_path() -> Path | None:
    p = os.environ.get("JEST_EXT_PY_MODEL")
    return Path(p) if p and Path(p).is_file() else None


def python_files(root: Path, max_files: int, max_bytes: int) -> list[Path]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in filenames:
            if f.endswith((".py", ".pyw")):
                p = Path(dirpath) / f
                try:
                    if p.is_symlink() or p.stat().st_size > max_bytes:
                        continue
                except OSError:
                    continue
                files.append(p)
                if len(files) >= max_files:
                    return files
    return files


def analyze(req: dict) -> None:
    want = set(req.get("vectors", []))
    opts = req.get("options", {})
    max_files = int(opts.get("maxFiles") or 5000)
    max_bytes = int(float(opts.get("maxFileMB") or 10) * 1024 * 1024)
    ran = [v for v in AST_VECTORS if v in want]
    skipped = [{"id": v, "reason": "no trained model (set JEST_EXT_PY_MODEL; built by tools/corpus)"} for v in MODEL_VECTORS if v in want and not model_path()]
    for ext in req.get("extensions", []):
        out({"type": "progress", "ext": ext["id"], "message": "python files"})
        root = Path(ext["path"])
        files = python_files(root, max_files, max_bytes)
        out({"type": "metric", "ext": ext["id"], "name": "python.files", "value": len(files)})
        by_vector: dict[str, list] = defaultdict(list)
        for f in files:
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            res = check_source(text, str(f))
            for h in res.hits:
                if h.vector in want:
                    by_vector[h.vector].append((f, h))
        for vector, hits in sorted(by_vector.items()):
            first = hits[0][1]
            nfiles = len({f for f, _ in hits})
            locations = [{"file": str(f.relative_to(root)).replace(os.sep, "/"), "line": h.line, "col": h.col} for f, h in hits[:MAX_LOCATIONS]]
            out({
                "type": "signal", "ext": ext["id"], "vector": vector,
                "message": f"{first.message} ({len(hits)} hit{'s' if len(hits) != 1 else ''} in {nfiles} Python file{'s' if nfiles != 1 else ''})",
                "locations": locations, "confidence": max(h.confidence for _, h in hits),
            })
    out({"type": "done", "ran": ran, **({"skipped": skipped} if skipped else {})})


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    cmd = argv[0] if argv else ""
    if cmd == "info":
        vectors = AST_VECTORS + (MODEL_VECTORS if model_path() else [])
        out({"name": "jest-ext-py", "version": __version__, "protocol": PROTOCOL, "vectors": vectors})
        return 0
    if cmd in ("version", "--version"):
        print(__version__)
        return 0
    if cmd == "analyze":
        try:
            req = json.load(sys.stdin)
        except json.JSONDecodeError as e:
            print(f"invalid request: {e}", file=sys.stderr)
            return 2
        if req.get("protocol") != PROTOCOL:
            print(f"unsupported protocol {req.get('protocol')} (want {PROTOCOL})", file=sys.stderr)
            return 2
        analyze(req)
        return 0
    print("usage: jest-ext-py info | analyze < request.json | version", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
