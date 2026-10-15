import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def sh(*args, cwd=None, env=None):
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run(list(args), cwd=cwd, env=e, capture_output=True, text=True)


class InstallAgents(unittest.TestCase):
    def test_links_all_agents_and_is_rerunnable(self):
        with tempfile.TemporaryDirectory() as home:
            for _ in range(2):
                r = sh("bash", str(ROOT / "scripts/install-agents.sh"), env={"HOME": home})
                self.assertEqual(r.returncode, 0, r.stderr)
            linked = sorted(p.name for p in (Path(home) / ".claude/agents").glob("n2i-sec-*.md"))
            self.assertEqual(linked, sorted(p.name for p in (ROOT / "agents").glob("n2i-sec-*.md")))
            for p in (Path(home) / ".claude/agents").glob("n2i-sec-*.md"):
                self.assertTrue(p.is_symlink() and p.exists())

    def test_removes_dangling_links(self):
        with tempfile.TemporaryDirectory() as home:
            agents = Path(home) / ".claude/agents"
            agents.mkdir(parents=True)
            (agents / "n2i-sec-gone.md").symlink_to("/no/such/target")
            sh("bash", str(ROOT / "scripts/install-agents.sh"), env={"HOME": home})
            self.assertFalse((agents / "n2i-sec-gone.md").is_symlink())

    def test_does_not_touch_other_skills_agents(self):
        with tempfile.TemporaryDirectory() as home:
            agents = Path(home) / ".claude/agents"
            agents.mkdir(parents=True)
            (agents / "n2i-unit-runner.md").symlink_to("/no/such/target")
            sh("bash", str(ROOT / "scripts/install-agents.sh"), env={"HOME": home})
            self.assertTrue((agents / "n2i-unit-runner.md").is_symlink())


class ProjectSync(unittest.TestCase):
    def test_syntax(self):
        self.assertEqual(sh("bash", "-n", str(ROOT / "scripts/project-sync.sh")).returncode, 0)

    def test_links_agents_from_every_n2i_skill_and_cleans_dangling(self):
        with tempfile.TemporaryDirectory() as proj:
            p = Path(proj)
            sh("git", "init", "-q", cwd=proj)
            for skill, agent in (("n2i-sec-audit", "n2i-sec-scanner"), ("n2i-dev-cycle", "n2i-unit-runner")):
                d = p / ".claude/skills" / skill / "agents"
                d.mkdir(parents=True)
                (d / f"{agent}.md").write_text("x")
            (p / ".claude/agents").mkdir(parents=True)
            (p / ".claude/agents/n2i-old.md").symlink_to("/no/such/target")
            r = sh("bash", str(ROOT / "scripts/project-sync.sh"), env={"CLAUDE_PROJECT_DIR": proj})
            self.assertEqual(r.returncode, 0)
            self.assertTrue((p / ".claude/agents/n2i-sec-scanner.md").exists())
            self.assertTrue((p / ".claude/agents/n2i-unit-runner.md").exists())
            self.assertFalse((p / ".claude/agents/n2i-old.md").is_symlink())

    def test_never_fails_outside_a_repo(self):
        with tempfile.TemporaryDirectory() as proj:
            r = sh("bash", str(ROOT / "scripts/project-sync.sh"), env={"CLAUDE_PROJECT_DIR": proj})
            self.assertEqual(r.returncode, 0)
            self.assertEqual(r.stdout + r.stderr, "")


def preamble(label):
    line = next(l for l in (ROOT / "SKILL.md").read_text().splitlines() if l.startswith(f"- {label}: !`"))
    return line[line.index("!`") + 2 : line.rindex("`")]


@unittest.skipUnless(shutil.which("zsh"), "zsh not installed")
class PreambleUnderZsh(unittest.TestCase):
    def run_zsh(self, cmd, cwd, home):
        r = sh("zsh", "-c", cmd, cwd=cwd, env={"HOME": home})
        self.assertEqual(r.stderr, "")
        return r.stdout.strip()

    def test_every_command_runs_clean_in_an_empty_project(self):
        cmds = re.findall(r"!`([^`]*)`", (ROOT / "SKILL.md").read_text())
        self.assertTrue(cmds)
        with tempfile.TemporaryDirectory() as proj, tempfile.TemporaryDirectory() as home:
            for cmd in cmds:
                self.run_zsh(cmd, proj, home)

    def test_agents_reports_missing_then_ok(self):
        with tempfile.TemporaryDirectory() as proj, tempfile.TemporaryDirectory() as home:
            agents = Path(proj) / ".claude/skills/n2i-sec-audit/agents"
            agents.mkdir(parents=True)
            (agents / "n2i-sec-one.md").write_text("x")
            self.assertEqual(self.run_zsh(preamble("Agents"), proj, home), "AGENTS=missing: n2i-sec-one")
            (Path(proj) / ".claude/agents").mkdir(parents=True)
            (Path(proj) / ".claude/agents/n2i-sec-one.md").write_text("x")
            self.assertEqual(self.run_zsh(preamble("Agents"), proj, home), "AGENTS=ok")

    def test_previous_report_picks_newest_match(self):
        with tempfile.TemporaryDirectory() as proj, tempfile.TemporaryDirectory() as home:
            docs = Path(proj) / "docs"
            docs.mkdir()
            old, new = docs / "2026-01-security-review.md", docs / "2026-02-security-review.md"
            old.write_text("x")
            new.write_text("x")
            os.utime(old, (1, 1))
            self.assertEqual(
                self.run_zsh(preamble("Previous report"), proj, home),
                "PREVIOUS_REPORT=docs/2026-02-security-review.md",
            )


if __name__ == "__main__":
    unittest.main()
