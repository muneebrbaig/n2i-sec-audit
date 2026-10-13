import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCAN = str(ROOT / "scripts/scan.py")

SECRET_VALUE = "hunter2" + "hunter2"
SECRET_LINE = 'db_password = "' + SECRET_VALUE + '"\n'


def git(cwd, *args):
    subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True)


def make_repo(files, ignore=None):
    td = tempfile.TemporaryDirectory()
    root = Path(td.name)
    git(root, "init", "-q")
    git(root, "config", "user.email", "t@t")
    git(root, "config", "user.name", "t")
    if ignore:
        (root / ".gitignore").write_text(ignore)
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    git(root, "add", "-A")
    git(root, "commit", "-qm", "init")
    return td, root


def scan(root, *args, env=None):
    e = dict(os.environ)
    if env:
        e.update(env)
    return subprocess.run(
        [sys.executable, SCAN, str(root), "--offline", *args], capture_output=True, text=True, env=e
    )


def lines_for(out, check_id):
    return [ln for ln in out.splitlines() if ln.startswith(check_id)]


def path_without_gitleaks():
    parts = [p for p in os.environ.get("PATH", "").split(os.pathsep) if not os.path.exists(os.path.join(p, "gitleaks"))]
    return os.pathsep.join(parts)


class Heuristics(unittest.TestCase):
    def test_clean_repo_passes_everything(self):
        td, root = make_repo({"src/app.ts": "export const x = 1;\n"})
        with td:
            r = scan(root, env={"PATH": path_without_gitleaks()})
            self.assertEqual(r.returncode, 0, r.stdout)
            for cid in ("A1", "C3", "D1", "D3", "C5"):
                self.assertTrue(any("PASS" in ln for ln in lines_for(r.stdout, cid)), (cid, r.stdout))

    def test_token_storage_is_flagged_with_location_only(self):
        src = "login(u) { localStorage.setItem('user', JSON.stringify(u)); }\n"
        td, root = make_repo({"src/login.ts": src})
        with td:
            r = scan(root)
            self.assertTrue(any("WARN" in ln for ln in lines_for(r.stdout, "C3")), r.stdout)
            self.assertIn("src/login.ts:1", r.stdout)
            self.assertNotIn("JSON.stringify", r.stdout)

    def test_wildcard_cors_is_flagged(self):
        td, root = make_repo({"api/main.py": "CORS_ALLOW_ALL_ORIGINS = True\n"})
        with td:
            self.assertTrue(any("WARN" in ln for ln in lines_for(scan(root).stdout, "D1")))

    def test_raw_sql_candidates_are_flagged(self):
        files = {
            "a.cs": 'db.Users.FromSqlRaw("select * from u where n=" + name);\n',
            "b.py": 'cur.execute(f"SELECT * FROM t WHERE id={uid}")\n',
        }
        td, root = make_repo(files)
        with td:
            out = scan(root).stdout
            self.assertTrue(any("WARN" in ln for ln in lines_for(out, "A1")), out)
            self.assertIn("a.cs:1", out)
            self.assertIn("b.py:1", out)

    def test_source_maps_in_build_output_are_flagged(self):
        td, root = make_repo({"src/a.ts": "x\n"})
        with td:
            (root / "dist").mkdir()
            (root / "dist/main.js.map").write_text("{}")
            out = scan(root).stdout
            self.assertTrue(any("WARN" in ln for ln in lines_for(out, "D3")), out)
            self.assertIn("dist/main.js.map", out)

    def test_maps_outside_build_dirs_are_ignored(self):
        td, root = make_repo({"docs/a.map": "{}\n"})
        with td:
            self.assertTrue(any("PASS" in ln for ln in lines_for(scan(root).stdout, "D3")))


class Secrets(unittest.TestCase):
    def test_tracked_env_file_fails_and_content_is_not_read(self):
        td, root = make_repo({".env": "SOMETHING=value-" + SECRET_VALUE + "\n", "a.txt": "x\n"})
        with td:
            r = scan(root, env={"PATH": path_without_gitleaks()})
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertTrue(any("FAIL" in ln for ln in lines_for(r.stdout, "C5")))
            self.assertIn(".env", r.stdout)
            self.assertNotIn(SECRET_VALUE, r.stdout + r.stderr)

    def test_untracked_unignored_env_file_warns(self):
        td, root = make_repo({"a.txt": "x\n"})
        with td:
            (root / ".env.local").write_text("A=b\n")
            out = scan(root, env={"PATH": path_without_gitleaks()}).stdout
            self.assertTrue(any("WARN" in ln and "NOT git-ignored" in ln for ln in lines_for(out, "C5")), out)

    def test_ignored_env_file_is_not_reported(self):
        td, root = make_repo({"a.txt": "x\n"}, ignore=".env*\n")
        with td:
            (root / ".env.creds.bak").write_text("A=b\n")
            out = scan(root, env={"PATH": path_without_gitleaks()}).stdout
            self.assertNotIn(".env.creds.bak", out)

    def test_example_env_files_are_allowed(self):
        td, root = make_repo({".env.example": "A=\n"})
        with td:
            out = scan(root, env={"PATH": path_without_gitleaks()}).stdout
            self.assertNotIn(".env.example", out)

    def test_fallback_scan_fails_on_secret_shaped_string_without_printing_it(self):
        td, root = make_repo({"src/conf.py": SECRET_LINE})
        with td:
            r = scan(root, env={"PATH": path_without_gitleaks()})
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn("src/conf.py:1", r.stdout)
            self.assertIn("git history NOT scanned", r.stdout)
            self.assertNotIn(SECRET_VALUE, r.stdout + r.stderr)

    def test_fail_on_none_never_exits_one(self):
        td, root = make_repo({"src/conf.py": SECRET_LINE})
        with td:
            r = scan(root, "--fail-on", "none", env={"PATH": path_without_gitleaks()})
            self.assertEqual(r.returncode, 0)
            self.assertIn("FAIL", r.stdout)

    def test_gitleaks_is_used_when_present_and_its_secret_field_is_never_printed(self):
        td, root = make_repo({"src/a.py": "x = 1\n"})
        with td, tempfile.TemporaryDirectory() as bindir:
            fake = Path(bindir) / "gitleaks"
            fake.write_text(
                "#!/bin/sh\n"
                'while [ $# -gt 0 ]; do [ "$1" = "--report-path" ] && OUT="$2"; shift; done\n'
                'cat > "$OUT" <<EOF\n'
                '[{"RuleID":"aws-access-token","File":"src/a.py","StartLine":7,"Secret":"' + SECRET_VALUE + '","Match":"' + SECRET_VALUE + '"}]\n'
                "EOF\n"
                "exit 0\n"
            )
            fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
            r = scan(root, env={"PATH": bindir + os.pathsep + os.environ["PATH"]})
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn("gitleaks", r.stdout)
            self.assertIn("src/a.py:7", r.stdout)
            self.assertIn("aws-access-token", r.stdout)
            self.assertNotIn(SECRET_VALUE, r.stdout + r.stderr)

    def test_gitleaks_clean_result_passes(self):
        td, root = make_repo({"src/a.py": "x = 1\n"})
        with td, tempfile.TemporaryDirectory() as bindir:
            fake = Path(bindir) / "gitleaks"
            fake.write_text(
                "#!/bin/sh\n"
                'while [ $# -gt 0 ]; do [ "$1" = "--report-path" ] && OUT="$2"; shift; done\n'
                'echo "[]" > "$OUT"\nexit 0\n'
            )
            fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
            r = scan(root, env={"PATH": bindir + os.pathsep + os.environ["PATH"]})
            self.assertTrue(any("PASS" in ln and "gitleaks" in ln for ln in lines_for(r.stdout, "C5")), r.stdout)


class Output(unittest.TestCase):
    def test_json_output_parses(self):
        td, root = make_repo({"a.txt": "x\n"})
        with td:
            r = scan(root, "--json", env={"PATH": path_without_gitleaks()})
            data = json.loads(r.stdout)
            self.assertTrue(all({"id", "status", "detail", "evidence"} <= set(d) for d in data))

    def test_offline_marks_dependency_audit_skipped(self):
        td, root = make_repo({"a.txt": "x\n"})
        with td:
            out = scan(root).stdout
            self.assertTrue(any("SKIP" in ln and "offline" in ln for ln in lines_for(out, "D5")), out)

    def test_not_a_directory_is_a_usage_error(self):
        r = subprocess.run([sys.executable, SCAN, "/no/such/dir"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)

    def test_works_outside_a_git_repo(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "a.ts").write_text("localStorage.setItem('authToken', t)\n")
            (Path(td) / ".env").write_text("A=b\n")
            out = scan(td, env={"PATH": path_without_gitleaks()}).stdout
            self.assertIn("a.ts:1", out)
            self.assertIn("git status unknown", out)


class Ignoring(unittest.TestCase):
    def test_ignore_file_hides_listed_checks_and_reports_what_it_hid(self):
        files = {
            "api/main.py": "CORS_ALLOW_ALL_ORIGINS = True\n",
            ".secauditignore": "# fixtures\napi/main.py D1\n",
        }
        td, root = make_repo(files)
        with td:
            out = scan(root).stdout
            self.assertTrue(any("PASS" in ln for ln in lines_for(out, "D1")), out)
            self.assertTrue(any("INFO" in ln and "left out" in ln for ln in lines_for(out, "--")), out)
            self.assertIn("api/main.py", out)

    def test_rule_with_ids_leaves_other_checks_active(self):
        files = {
            "src/conf.py": SECRET_LINE + "CORS_ALLOW_ALL_ORIGINS = True\n",
            ".secauditignore": "src/conf.py D1\n",
        }
        td, root = make_repo(files)
        with td:
            r = scan(root, env={"PATH": path_without_gitleaks()})
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn("src/conf.py:1", r.stdout)

    def test_star_matches_across_directories(self):
        files = {"a/b/c/conf.py": "CORS_ALLOW_ALL_ORIGINS = True\n", ".secauditignore": "a/*\n"}
        td, root = make_repo(files)
        with td:
            self.assertTrue(any("PASS" in ln for ln in lines_for(scan(root).stdout, "D1")))

    def test_exclude_flag_hides_a_file_from_every_check(self):
        td, root = make_repo({"src/conf.py": SECRET_LINE})
        with td:
            r = scan(root, "--exclude", "src/*", env={"PATH": path_without_gitleaks()})
            self.assertEqual(r.returncode, 0, r.stdout)
            self.assertIn("left out", r.stdout)

    def test_inline_marker_skips_one_line_only(self):
        src = "CORS_ALLOW_ALL_ORIGINS = True  # n2i-sec-audit: ignore\nCORS_ALLOW_ALL_ORIGINS = True\n"
        td, root = make_repo({"api/main.py": src})
        with td:
            out = scan(root).stdout
            self.assertIn("api/main.py:2", out)
            self.assertNotIn("api/main.py:1", out)

    def test_inline_marker_also_skips_the_fallback_secret_scan(self):
        td, root = make_repo({"src/conf.py": SECRET_LINE.rstrip() + "  # n2i-sec-audit: ignore\n"})
        with td:
            r = scan(root, env={"PATH": path_without_gitleaks()})
            self.assertEqual(r.returncode, 0, r.stdout)

    def test_ignore_rules_apply_to_gitleaks_results(self):
        td, root = make_repo({"src/a.py": "x = 1\n", ".secauditignore": "src/a.py C5\n"})
        with td, tempfile.TemporaryDirectory() as bindir:
            fake = Path(bindir) / "gitleaks"
            fake.write_text(
                "#!/bin/sh\n"
                'while [ $# -gt 0 ]; do [ "$1" = "--report-path" ] && OUT="$2"; shift; done\n'
                'echo \'[{"RuleID":"x","File":"src/a.py","StartLine":1}]\' > "$OUT"\nexit 0\n'
            )
            fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
            r = scan(root, env={"PATH": bindir + os.pathsep + os.environ["PATH"]})
            self.assertEqual(r.returncode, 0, r.stdout)

    def test_this_repo_scans_clean_with_its_own_ignore_file(self):
        r = subprocess.run([sys.executable, SCAN, str(ROOT), "--offline"], capture_output=True, text=True,
                           env={**os.environ, "PATH": path_without_gitleaks()})
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertNotIn("WARN", r.stdout)


class Handler(BaseHTTPRequestHandler):
    good = False

    def do_GET(self):
        self.send_response(200)
        if Handler.good:
            self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Set-Cookie", "sid=1; Path=/; HttpOnly; SameSite=Lax")
        else:
            self.send_header("Server", "Kestrel/9.0")
            self.send_header("Set-Cookie", "sid=1; Path=/")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


class Headers(unittest.TestCase):
    def serve(self, good):
        Handler.good = good
        srv = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        self.addCleanup(srv.server_close)
        return f"http://127.0.0.1:{srv.server_address[1]}/"

    def test_missing_headers_and_weak_cookie_are_flagged(self):
        url = self.serve(False)
        td, root = make_repo({"a.txt": "x\n"})
        with td:
            out = scan(root, "--url", url).stdout
            d6 = "\n".join(lines_for(out, "D6"))
            self.assertIn("WARN", d6)
            self.assertIn("Content-Security-Policy", out)
            self.assertTrue(any("WARN" in ln for ln in lines_for(out, "D7")), out)
            self.assertTrue(any("WARN" in ln for ln in lines_for(out, "B7")), out)
            self.assertIn("HttpOnly", out)

    def test_good_headers_pass(self):
        url = self.serve(True)
        td, root = make_repo({"a.txt": "x\n"})
        with td:
            out = scan(root, "--url", url).stdout
            self.assertTrue(any("PASS" in ln for ln in lines_for(out, "D6")), out)
            self.assertEqual(lines_for(out, "B7"), [])

    def test_remote_url_needs_allow_remote(self):
        td, root = make_repo({"a.txt": "x\n"})
        with td:
            r = scan(root, "--url", "https://example.org/")
            self.assertEqual(r.returncode, 2)
            self.assertIn("--allow-remote", r.stderr)

    def test_unreachable_target_is_skipped_not_failed(self):
        td, root = make_repo({"a.txt": "x\n"})
        with td:
            r = scan(root, "--url", "http://127.0.0.1:9/")
            self.assertTrue(any("SKIP" in ln for ln in lines_for(r.stdout, "D6")), r.stdout)


if __name__ == "__main__":
    unittest.main()
