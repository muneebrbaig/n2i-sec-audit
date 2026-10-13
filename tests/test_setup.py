import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SETUP = str(ROOT / "scripts/setup.py")
sys.path.insert(0, str(ROOT / "scripts"))
import setup as setup_mod  # noqa: E402

SECRET_VALUE = "hunter2" + "hunter2"
SECRET_LINE = 'db_password = "' + SECRET_VALUE + '"\n'


def git(cwd, *args):
    subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True)


def make_repo(files):
    td = tempfile.TemporaryDirectory()
    root = Path(td.name)
    git(root, "init", "-q")
    git(root, "config", "user.email", "t@t")
    git(root, "config", "user.name", "t")
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    git(root, "add", "-A")
    git(root, "commit", "-qm", "init")
    return td, root


def run_setup(*args):
    env = dict(os.environ)
    parts = [p for p in env.get("PATH", "").split(os.pathsep) if not os.path.exists(os.path.join(p, "gitleaks"))]
    env["PATH"] = os.pathsep.join(parts)
    return subprocess.run([sys.executable, SETUP, *args], capture_output=True, text=True, env=env)


def config_items(root):
    r = run_setup("config", str(root), "--json")
    assert r.returncode == 0, r.stderr
    return {i["key"]: i for i in json.loads(r.stdout)}


class ConfigProposal(unittest.TestCase):
    def test_detects_stacks_and_scope_dirs(self):
        td, root = make_repo({"backend/App.sln": "", "frontend/angular.json": "{}", "frontend/package.json": "{}"})
        with td:
            items = config_items(root)
            self.assertEqual(items["STACKS"]["value"], "dotnet angular node")
            self.assertEqual(items["SCOPE_DIRS"]["value"], "backend frontend")
            self.assertTrue(items["STACKS"]["active"] and items["SCOPE_DIRS"]["active"])

    def test_manifest_at_the_root_means_whole_repo(self):
        td, root = make_repo({"package.json": "{}", "src/a.ts": "x\n"})
        with td:
            items = config_items(root)
            self.assertEqual(items["STACKS"]["value"], "node")
            self.assertFalse(items["SCOPE_DIRS"]["active"])

    def test_legacy_directories_are_left_out_of_scope(self):
        td, root = make_repo({"app/App.sln": "", "old/Legacy.sln": ""})
        with td:
            self.assertEqual(config_items(root)["SCOPE_DIRS"]["value"], "app")

    def test_unknown_stack_falls_back_to_defaults(self):
        td, root = make_repo({"README.md": "hi\n"})
        with td:
            items = config_items(root)
            self.assertFalse(items["STACKS"]["active"])
            self.assertEqual(items["STACKS"]["default"], "auto")
            self.assertIn("generic", items["STACKS"]["reason"])

    def test_scan_url_comes_from_launch_json(self):
        launch = json.dumps({"configurations": [{"name": "x", "port": 5050}]})
        td, root = make_repo({".claude/launch.json": launch})
        with td:
            self.assertEqual(config_items(root)["SCAN_URL"]["value"], "http://localhost:5050")

    def test_every_known_key_is_proposed_with_a_default_and_a_reason(self):
        td, root = make_repo({"a.txt": "x\n"})
        with td:
            items = config_items(root)
            self.assertEqual(set(items), set(setup_mod.KNOWN_KEYS))
            for key, it in items.items():
                with self.subTest(key=key):
                    self.assertTrue(it["default"])
                    self.assertTrue(it["reason"])


class ConfigWrite(unittest.TestCase):
    def test_write_creates_the_file_with_active_values_and_commented_defaults(self):
        td, root = make_repo({"package.json": "{}"})
        with td:
            r = run_setup("config", str(root), "--write")
            self.assertEqual(r.returncode, 0, r.stderr)
            text = (root / ".n2i-sec-audit/config").read_text()
            self.assertIn("\nSTACKS=node\n", text)
            self.assertIn("# FAIL_ON=critical", text)
            self.assertIn("# NEXT_STEP=ask", text)

    def test_write_refuses_to_overwrite_without_force(self):
        td, root = make_repo({"package.json": "{}"})
        with td:
            run_setup("config", str(root), "--write")
            (root / ".n2i-sec-audit/config").write_text("KEEP=me\n")
            r = run_setup("config", str(root), "--write")
            self.assertEqual(r.returncode, 1)
            self.assertEqual((root / ".n2i-sec-audit/config").read_text(), "KEEP=me\n")
            self.assertEqual(run_setup("config", str(root), "--write", "--force").returncode, 0)
            self.assertIn("STACKS=node", (root / ".n2i-sec-audit/config").read_text())

    def test_set_overrides_a_proposed_value(self):
        td, root = make_repo({"package.json": "{}"})
        with td:
            run_setup("config", str(root), "--write", "--set", "FAIL_ON=high", "--set", "REPORT_DIR=security")
            text = (root / ".n2i-sec-audit/config").read_text()
            self.assertIn("\nFAIL_ON=high\n", text)
            self.assertIn("\nREPORT_DIR=security\n", text)

    def test_set_rejects_unknown_keys(self):
        td, root = make_repo({"package.json": "{}"})
        with td:
            r = run_setup("config", str(root), "--set", "NOPE=1")
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("known key", r.stderr)

    def test_written_config_is_readable_by_the_shell(self):
        td, root = make_repo({"backend/App.sln": ""})
        with td:
            run_setup("config", str(root), "--write")
            out = subprocess.run(
                ["bash", "-c", f'. "{root}/.n2i-sec-audit/config"; echo "$STACKS|$SCOPE_DIRS|${{FAIL_ON:-unset}}"'],
                capture_output=True, text=True)
            self.assertEqual(out.stdout.strip(), "dotnet|backend|unset")

    def test_reminds_about_gitignore_only_when_missing(self):
        td, root = make_repo({"a.txt": "x\n"})
        with td:
            self.assertIn(".gitignore", run_setup("config", str(root), "--write").stdout)
            (root / ".n2i-sec-audit/config").unlink()
            (root / ".gitignore").write_text(".n2i-sec-audit/\n")
            self.assertNotIn(".gitignore", run_setup("config", str(root), "--write").stdout)
            self.assertFalse((root / ".gitignore").read_text().count(".n2i-sec-audit/") > 1)


class Classify(unittest.TestCase):
    def test_known_and_review_classes(self):
        cases = {
            "frontend/dist/test-out/abc/a.js.map": ("frontend/dist/test-out/*", "known"),
            "backend/UnitTests/A.cs": ("backend/UnitTests/*", "known"),
            "tests/conf.py": ("tests/*", "known"),
            "backend/WebApi/wwwroot/main.js.map": ("backend/WebApi/wwwroot/*", "review"),
            "dist/main.js.map": ("dist/*", "review"),
            "old/app/x.ts": ("old/*", "review"),
        }
        for rel, (glob, conf) in cases.items():
            with self.subTest(rel=rel):
                got = setup_mod.classify(rel)
                self.assertEqual((got[0], got[2]), (glob, conf))

    def test_test_files_next_to_the_code_get_a_file_pattern_rule(self):
        cases = {
            "frontend/src/app/account.service.spec.ts": "*.spec.ts",
            "src/Button.test.tsx": "*.test.tsx",
            "backend/Features/UserServiceTests.cs": "*Tests.cs",
            "backend/Features/UserServiceTest.cs": "*Test.cs",
            "pkg/test_user.py": "test_*.py",
            "pkg/user_test.go": "*_test.go",
        }
        for rel, glob in cases.items():
            with self.subTest(rel=rel):
                got = setup_mod.classify(rel)
                self.assertEqual((got[0], got[2]), (glob, "known"))

    def test_a_test_folder_rule_wins_over_a_file_pattern_rule(self):
        self.assertEqual(setup_mod.classify("backend/UnitTests/UserServiceTests.cs")[0], "backend/UnitTests/*")

    def test_file_pattern_globs_match_files_in_any_folder(self):
        import fnmatch
        self.assertTrue(fnmatch.fnmatch("frontend/src/a/b.spec.ts", "*.spec.ts"))
        self.assertFalse(fnmatch.fnmatch("frontend/src/a/b.ts", "*.spec.ts"))

    def test_ordinary_source_is_not_noise(self):
        for rel in ("src/app.ts", "backend/Features/User/UserService.cs", "README.md"):
            with self.subTest(rel=rel):
                self.assertIsNone(setup_mod.classify(rel))


FIXTURE = {
    "src/app.ts": "export const a = 1;\n",
    "tests/conf.py": SECRET_LINE,
    "frontend/dist/test-out/u1/a.js.map": "{}",
    "backend/WebApi/wwwroot/main.js.map": "{}",
    "old/legacy/c.py": "CORS_ALLOW_ALL_ORIGINS = True\n",
    ".env": "A=value-" + SECRET_VALUE + "\n",
}


def suggestions(root):
    r = run_setup("ignores", str(root), "--json")
    assert r.returncode == 0, r.stderr
    return {g["glob"]: g for g in json.loads(r.stdout)}


class IgnoreSuggestions(unittest.TestCase):
    def test_suggestions_are_graded_and_protect_secret_files(self):
        td, root = make_repo(FIXTURE)
        with td:
            sug = suggestions(root)
            self.assertEqual(sug["tests/*"]["confidence"], "known")
            self.assertIn("C5", sug["tests/*"]["ids"])
            self.assertEqual(sug["frontend/dist/test-out/*"]["confidence"], "known")
            self.assertEqual(sug["frontend/dist/test-out/*"]["ids"], ["D3"])
            self.assertEqual(sug["backend/WebApi/wwwroot/*"]["confidence"], "review")
            self.assertEqual(sug["old/*"]["confidence"], "review")
            for g in sug.values():
                self.assertNotIn(".env", g["glob"])

    def test_known_suggestions_come_first(self):
        td, root = make_repo(FIXTURE)
        with td:
            r = run_setup("ignores", str(root), "--json")
            confs = [g["confidence"] for g in json.loads(r.stdout)]
            self.assertEqual(confs, sorted(confs, key=lambda c: c != "known"))

    def test_text_output_explains_each_rule_and_never_prints_a_secret(self):
        td, root = make_repo(FIXTURE)
        with td:
            r = run_setup("ignores", str(root))
            self.assertIn("known", r.stdout)
            self.assertIn("review", r.stdout)
            self.assertIn("never suggested", r.stdout)
            self.assertNotIn(SECRET_VALUE, r.stdout + r.stderr)

    def test_nothing_noisy_means_no_suggestions(self):
        td, root = make_repo({"src/app.ts": "export const a = 1;\n"})
        with td:
            self.assertIn("no ignore suggestions", run_setup("ignores", str(root)).stdout)

    def test_write_known_adds_only_known_rules_with_reasons(self):
        td, root = make_repo(FIXTURE)
        with td:
            r = run_setup("ignores", str(root), "--write", "--accept", "known")
            self.assertEqual(r.returncode, 0, r.stderr)
            text = (root / ".secauditignore").read_text()
            self.assertIn("tests/*  ", text)
            self.assertIn("frontend/dist/test-out/*  D3  # test or cache output", text)
            self.assertNotIn("wwwroot", text)
            self.assertNotIn("old/*", text)
            self.assertTrue(text.startswith("# n2i-sec-audit ignore rules"))

    def test_rules_take_effect_and_review_items_stay_visible(self):
        td, root = make_repo(FIXTURE)
        with td:
            run_setup("ignores", str(root), "--write", "--accept", "known")
            after = suggestions(root)
            self.assertNotIn("tests/*", after)
            self.assertNotIn("frontend/dist/test-out/*", after)
            self.assertIn("backend/WebApi/wwwroot/*", after)
            scan_out = subprocess.run([sys.executable, str(ROOT / "scripts/scan.py"), str(root), "--offline"],
                                      capture_output=True, text=True).stdout
            self.assertIn("backend/WebApi/wwwroot/main.js.map", scan_out)
            self.assertIn("left out", scan_out)

    def test_write_is_idempotent(self):
        td, root = make_repo(FIXTURE)
        with td:
            run_setup("ignores", str(root), "--write", "--accept", "known")
            first = (root / ".secauditignore").read_text()
            run_setup("ignores", str(root), "--write", "--accept", "known")
            self.assertEqual((root / ".secauditignore").read_text(), first)

    def test_accept_by_number_and_all(self):
        td, root = make_repo(FIXTURE)
        with td:
            run_setup("ignores", str(root), "--write", "--accept", "all")
            text = (root / ".secauditignore").read_text()
            for glob in ("tests/*", "frontend/dist/test-out/*", "backend/WebApi/wwwroot/*", "old/*"):
                self.assertIn(glob, text)
        td2, root2 = make_repo(FIXTURE)
        with td2:
            first = json.loads(run_setup("ignores", str(root2), "--json").stdout)[0]
            run_setup("ignores", str(root2), "--write", "--accept", "1")
            self.assertIn(first["glob"], (root2 / ".secauditignore").read_text())

    def test_tracked_secret_files_still_fail_after_accepting_everything(self):
        td, root = make_repo(FIXTURE)
        with td:
            run_setup("ignores", str(root), "--write", "--accept", "all")
            out = subprocess.run([sys.executable, str(ROOT / "scripts/scan.py"), str(root), "--offline"],
                                 capture_output=True, text=True)
            self.assertEqual(out.returncode, 1)
            self.assertIn("tracked secret-shaped file", out.stdout)

    def test_write_without_accept_is_a_usage_error(self):
        td, root = make_repo(FIXTURE)
        with td:
            r = run_setup("ignores", str(root), "--write")
            self.assertEqual(r.returncode, 2)
            self.assertFalse((root / ".secauditignore").exists())

    def test_unknown_suggestion_number_is_rejected(self):
        td, root = make_repo(FIXTURE)
        with td:
            r = run_setup("ignores", str(root), "--write", "--accept", "99")
            self.assertNotEqual(r.returncode, 0)
            self.assertFalse((root / ".secauditignore").exists())


if __name__ == "__main__":
    unittest.main()
