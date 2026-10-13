import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENTS = sorted((ROOT / "agents").glob("n2i-sec-*.md"))
MODELS = {"haiku", "sonnet", "opus"}
EXPECTED = {"n2i-sec-scanner": "haiku", "n2i-sec-category-auditor": "sonnet", "n2i-sec-skeptic": "sonnet"}
WRITE_TOOLS = {"Edit", "Write", "NotebookEdit"}
DOCS = [ROOT / "SKILL.md", ROOT / "README.md"]


def frontmatter(path):
    m = re.match(r"---\n(.*?)\n---\n", path.read_text(), re.S)
    assert m, f"{path.name}: no frontmatter"
    return dict(line.split(": ", 1) for line in m.group(1).splitlines())


class AgentFiles(unittest.TestCase):
    def test_expected_agents_exist(self):
        self.assertEqual({p.stem for p in AGENTS}, set(EXPECTED))

    def test_frontmatter_valid_and_models_match(self):
        for p in AGENTS:
            fm = frontmatter(p)
            with self.subTest(agent=p.stem):
                self.assertEqual(fm["name"], p.stem)
                self.assertIn(fm["model"], MODELS)
                self.assertEqual(fm["model"], EXPECTED[p.stem])
                self.assertTrue(fm["description"].strip())

    def test_no_agent_can_edit_files(self):
        for p in AGENTS:
            tools = {t.strip() for t in frontmatter(p)["tools"].split(",")}
            with self.subTest(agent=p.stem):
                self.assertFalse(tools & WRITE_TOOLS)

    def test_every_agent_forbids_printing_secrets(self):
        for p in AGENTS:
            with self.subTest(agent=p.stem):
                self.assertIn("secret value", p.read_text().lower())

    def test_agents_are_referenced_in_docs(self):
        for p in AGENTS:
            for doc in DOCS:
                with self.subTest(agent=p.stem, doc=doc.name):
                    self.assertIn(p.stem, doc.read_text())

    def test_every_agent_token_in_docs_is_real(self):
        names = {p.stem for p in AGENTS}
        for doc in DOCS:
            for tok in re.findall(r"(?<![.\w-])n2i-sec-[a-z0-9-]+", doc.read_text()):
                if tok == "n2i-sec-audit":
                    continue
                with self.subTest(doc=doc.name, token=tok):
                    self.assertIn(tok, names)


if __name__ == "__main__":
    unittest.main()
