import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKLIST = (ROOT / "references/checklist.md").read_text()
ITEM = re.compile(r"^### ([A-D]\d+) (.+)$", re.M)
FIELDS = ("**Core:**", "**Look for:**", "**Pass when:**", "**Severity if failing:**", "**Maps to:**")
ID_TOKEN = re.compile(r"(?<![\w.-])([A-D]\d+)(?![\w.-])")


def items():
    """Return {id: body} for each checklist item."""
    out = {}
    matches = list(ITEM.finditer(CHECKLIST))
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(CHECKLIST)
        out[m.group(1)] = CHECKLIST[m.end():end]
    return out


class Checklist(unittest.TestCase):
    def test_ids_are_unique_and_sequential_per_category(self):
        ids = [m.group(1) for m in ITEM.finditer(CHECKLIST)]
        self.assertEqual(len(ids), len(set(ids)))
        for cat in "ABCD":
            nums = [int(i[1:]) for i in ids if i[0] == cat]
            self.assertEqual(nums, list(range(1, len(nums) + 1)), cat)

    def test_every_item_has_all_fields(self):
        for cid, body in items().items():
            for f in FIELDS:
                with self.subTest(item=cid, field=f):
                    self.assertIn(f, body)

    def test_every_item_maps_to_owasp_and_cwe(self):
        for cid, body in items().items():
            line = next(ln for ln in body.splitlines() if ln.startswith("- **Maps to:**"))
            with self.subTest(item=cid):
                self.assertRegex(line, r"OWASP (A\d{2}:2021|API\d+:2023)")
                self.assertRegex(line, r"CWE-\d+")

    def test_core_flag_is_yes_or_no(self):
        for cid, body in items().items():
            with self.subTest(item=cid):
                self.assertRegex(body, r"\*\*Core:\*\* (yes|no)\b")

    def test_baseline_covers_the_twenty_original_checks(self):
        core = [cid for cid, body in items().items() if "**Core:** yes" in body]
        self.assertGreaterEqual(len(core), 20)


class Consistency(unittest.TestCase):
    def test_scan_ids_exist_in_checklist(self):
        scan = (ROOT / "scripts/scan.py").read_text()
        used = set(re.findall(r'Finding\("([A-D]\d+)"', scan))
        self.assertTrue(used)
        self.assertLessEqual(used, set(items()))

    def test_checklist_scan_notes_match_scan_py(self):
        scan = (ROOT / "scripts/scan.py").read_text()
        used = set(re.findall(r'Finding\("([A-D]\d+)"', scan))
        for cid, body in items().items():
            if "scan.py" in body:
                with self.subTest(item=cid):
                    self.assertIn(cid, used)

    def test_adapter_ids_exist_in_checklist(self):
        known = set(items())
        for adapter in (ROOT / "references/stacks").glob("*.md"):
            for tok in re.findall(r"\*\*([A-D]\d+)(?:[ /][^*]*)?\*\*", adapter.read_text()):
                with self.subTest(adapter=adapter.name, id=tok):
                    self.assertIn(tok, known)

    def test_every_adapter_names_the_main_categories(self):
        for adapter in (ROOT / "references/stacks").glob("*.md"):
            self.assertTrue(adapter.read_text().strip(), adapter.name)

    def test_report_template_mentions_required_sections(self):
        text = (ROOT / "references/report-template.md").read_text()
        for needle in ("Already covered", "Gaps and recommendations", "Not verified", "Open questions", "Out of scope"):
            with self.subTest(section=needle):
                self.assertIn(needle, text)


class SkillFile(unittest.TestCase):
    skill = (ROOT / "SKILL.md").read_text()

    def test_frontmatter(self):
        m = re.match(r"---\n(.*?)\n---\n", self.skill, re.S)
        self.assertTrue(m)
        fm = dict(line.split(": ", 1) for line in m.group(1).splitlines())
        self.assertEqual(fm["name"], "n2i-sec-audit")
        self.assertTrue(fm["description"].strip())
        self.assertNotIn("WebFetch", fm["allowed-tools"])

    def test_referenced_files_exist(self):
        for rel in set(re.findall(r"`((?:references|scripts|agents)/[\w./-]+\.(?:md|py|sh))`", self.skill)):
            with self.subTest(path=rel):
                self.assertTrue((ROOT / rel).exists(), rel)

    def test_safety_rules_present(self):
        for needle in ("Never print a secret value", "No attack traffic", "No installs without asking", "Read-only on the project"):
            with self.subTest(rule=needle):
                self.assertIn(needle, self.skill)

    def test_next_step_options_are_offered_not_assumed(self):
        self.assertIn("Never start a plan, ticket, branch, or fix on your own", self.skill)
        for needle in ("phased plan", "Draft tickets", "n2i-dev-cycle", "Stop"):
            with self.subTest(option=needle):
                self.assertIn(needle, self.skill)

    def test_first_run_flows_are_documented_and_ask_before_writing(self):
        self.assertTrue((ROOT / "scripts/setup.py").exists())
        for needle in (
            "scripts/setup.py config",
            "scripts/setup.py ignores",
            "accept all, or name the keys to change",
            "Tracked secret-shaped files are never suggested",
            "Do not edit `.gitignore` yourself",
            "`known` rules",
            "`review` rules",
            "ask once",
        ):
            with self.subTest(needle=needle):
                self.assertIn(needle, self.skill)

    def test_safety_rule_lists_every_file_the_skill_may_write(self):
        rule = next(ln for ln in self.skill.splitlines() if ln.startswith("1. **Read-only on the project.**"))
        for needle in (".n2i-sec-audit/", ".secauditignore", "does not edit source"):
            with self.subTest(needle=needle):
                self.assertIn(needle, rule)

    def test_every_config_key_has_a_proposal_and_an_example_entry(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import setup as setup_mod
        example = (ROOT / "n2i-sec-audit.config.example").read_text()
        for key in setup_mod.KNOWN_KEYS:
            with self.subTest(key=key):
                self.assertIn(f"{key}=", example)
                self.assertIn(key, (ROOT / "README.md").read_text())

    def test_agent_fallback_ladder_is_documented(self):
        for needle in (
            "**Agent fallback.**",
            "`general-purpose`",
            "Read-only: do not create, edit, or delete any file",
            "adjacent tier",
            "If subagents are unavailable, do the work inline",
        ):
            with self.subTest(needle=needle):
                self.assertIn(needle, self.skill)

    def test_every_dispatch_step_points_at_the_fallback(self):
        for agent in ("n2i-sec-scanner", "n2i-sec-category-auditor", "n2i-sec-skeptic"):
            sections = [sec for sec in self.skill.split("\n## ")
                        if any(agent in ln and ("dispatch" in ln.lower() or "Delegate" in ln)
                               for ln in sec.splitlines())]
            with self.subTest(agent=agent):
                self.assertTrue(sections, agent)
                self.assertTrue(all("agent fallback" in sec for sec in sections), agent)

    def test_fallback_source_files_have_a_model_and_a_body(self):
        for path in (ROOT / "agents").glob("n2i-sec-*.md"):
            m = re.match(r"---\n(.*?)\n---\n(.+)", path.read_text(), re.S)
            with self.subTest(agent=path.stem):
                self.assertTrue(m)
                self.assertIn("model:", m.group(1))
                self.assertTrue(m.group(2).strip())

    def test_no_project_specific_names_leak_into_the_repo(self):
        banned = re.compile(r"koolhub|koolnext|safetrip|kooldown|P@kistan", re.I)
        for path in ROOT.rglob("*"):
            if path.is_file() and ".git" not in path.parts and path.suffix in {".md", ".py", ".sh", ".yml", ".example"}:
                if path.name == "test_references.py":
                    continue
                with self.subTest(file=str(path.relative_to(ROOT))):
                    self.assertIsNone(banned.search(path.read_text()))


if __name__ == "__main__":
    unittest.main()
