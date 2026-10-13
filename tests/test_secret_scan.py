import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import secret_scan  # noqa: E402

# Built from parts so this file never contains a scannable secret itself.
AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
PW_LINE = 'db_password = "' + "hunter2hunter2" + '"'


class ScanText(unittest.TestCase):
    def test_detects_known_shapes(self):
        cases = {
            "AWS access key id": f"key: {AWS}",
            "private key block": "-----BEGIN RSA PRIVATE KEY-----",
            "password in URL": "url = postgres://user:s3cretpw@db.host/app",
            "secret assignment": PW_LINE,
            "JWT": "t = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop",
        }
        for kind, line in cases.items():
            with self.subTest(kind=kind):
                self.assertEqual([k for _, k in secret_scan.scan_text(line)], [kind])

    def test_reports_line_numbers(self):
        hits = secret_scan.scan_text(f"ok\nok\n{PW_LINE}\n")
        self.assertEqual([n for n, _ in hits], [3])

    def test_placeholders_are_ignored(self):
        for line in ('password = "changeme-please"', 'api_key = "your-api-key-here"', 'token = "<token-value>"'):
            with self.subTest(line=line):
                self.assertEqual(secret_scan.scan_text(line), [])

    def test_result_never_contains_the_match(self):
        hits = secret_scan.scan_text(f"{PW_LINE}\nkey: {AWS}")
        flat = repr(hits)
        self.assertNotIn("hunter2", flat)
        self.assertNotIn(AWS, flat)


class Cli(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(ROOT / "scripts/secret_scan.py"), *args], capture_output=True, text=True
        )

    def test_cli_prints_location_and_kind_but_not_the_value(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "a.txt").write_text(f"x\n{PW_LINE}\n")
            r = self.run_cli(td)
        self.assertEqual(r.returncode, 1)
        self.assertIn("a.txt:2", r.stdout)
        self.assertIn("secret assignment", r.stdout)
        self.assertNotIn("hunter2", r.stdout + r.stderr)

    def test_clean_tree_exits_zero(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "a.txt").write_text("nothing here\n")
            self.assertEqual(self.run_cli(td).returncode, 0)

    def test_skips_binary_and_vendor_dirs(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "node_modules").mkdir()
            (Path(td) / "node_modules/x.js").write_text(PW_LINE)
            (Path(td) / "bin.dat").write_bytes(b"\x00" + PW_LINE.encode())
            self.assertEqual(self.run_cli(td).returncode, 0)

    def test_usage_error(self):
        self.assertEqual(self.run_cli().returncode, 2)


if __name__ == "__main__":
    unittest.main()
