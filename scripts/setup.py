#!/usr/bin/env python3
"""First-run setup helpers for n2i-sec-audit. Read-only unless --write is given.

  setup.py config  [PATH] [--set KEY=VALUE ...] [--write [--force]] [--json]
      Propose the per-repo config with every value pre-filled from what the repo shows
      (stacks, scope directories, a local URL) or from the default. --write saves it to
      <PATH>/.n2i-sec-audit/config. It refuses to overwrite an existing file without --force.

  setup.py ignores [PATH] [--write --accept LIST] [--json]
      Run the scan and suggest `.secauditignore` rules for the noise it finds: test code,
      non-shipped build output, legacy trees. Each suggestion shows its hit count and a
      confidence: `known` (a pattern that is almost always noise) or `review` (could hide a
      real problem; accept only after you checked). Findings about secret-shaped files are
      never suggested. --accept takes numbers (1,3), `known`, or `all`, and appends the
      chosen rules, with a reason comment, to <PATH>/.secauditignore.

Nothing here edits source files, .gitignore, or anything outside the two files named above.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scan  # noqa: E402

CONFIG_DIR = ".n2i-sec-audit"
CONFIG_FILE = "config"
LEGACY = {"old", "legacy", "deprecated", "archive", "archived", "third_party", "thirdparty"}
TEST_DIRS = {"test", "tests", "__tests__", "unittests", "integrationtests", "spec", "specs", "e2e",
             "fixtures", "mocks", "testing", "testdata"}
NON_SHIPPED_BUILD = {"test-out", "coverage", ".angular", "cache", "tmp", "__snapshots__"}
STACK_MANIFESTS = {
    "dotnet": {"suffixes": (".sln", ".slnx", ".csproj")},
    "angular": {"names": {"angular.json"}},
    "node": {"names": {"package.json"}},
    "python": {"names": {"requirements.txt", "pyproject.toml"}},
}
KNOWN_KEYS = ["REPORT_DIR", "REPORT_GLOB", "ACCEPTED_RISKS", "STACKS", "SCOPE_DIRS", "EXCLUDE_DIRS",
              "CHECK_SKIP", "SCAN_URL", "FAIL_ON", "NEXT_STEP"]


# ---------- config ----------

def find_manifests(root, spec):
    return scan.walk_for(root, names=spec.get("names"), suffixes=spec.get("suffixes", ()), max_depth=3)


def detect_stacks(root):
    stacks = {}
    for name, spec in STACK_MANIFESTS.items():
        found = find_manifests(root, spec)
        if found:
            stacks[name] = found
    return stacks


def detect_scope_dirs(root, stacks):
    """Top-level directories that hold a manifest. A manifest at the repo root means 'whole repo'."""
    dirs = set()
    for found in stacks.values():
        for path in found:
            rel = os.path.relpath(os.path.dirname(path), root)
            if rel == ".":
                return []
            top = rel.split(os.sep)[0]
            if top.lower() not in LEGACY:
                dirs.add(top)
    return sorted(dirs)


def detect_url(root):
    path = os.path.join(root, ".claude", "launch.json")
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    for cfg in data.get("configurations", []) if isinstance(data, dict) else []:
        port = cfg.get("port") if isinstance(cfg, dict) else None
        if isinstance(port, int):
            return f"http://localhost:{port}"
    return None


def propose_config(root):
    stacks = detect_stacks(root)
    scope = detect_scope_dirs(root, stacks)
    url = detect_url(root)
    has_docs = os.path.isdir(os.path.join(root, "docs"))
    items = [
        ("STACKS", " ".join(stacks) if stacks else None, "auto",
         f"detected from manifests: {', '.join(stacks)}" if stacks else "nothing detected; the audit will use the generic adapter"),
        ("REPORT_DIR", "docs", "docs", "docs/ exists" if has_docs else "default; the folder is created on the first report"),
        ("REPORT_GLOB", None, "*security-review*.md", "how a re-audit finds the previous report"),
        ("ACCEPTED_RISKS", None, "docs/security-accepted-risks.md", "shared file for accepted risks"),
        ("SCOPE_DIRS", " ".join(scope) if scope else None, "(whole repo)",
         f"directories holding a manifest: {', '.join(scope)}" if scope else "manifest at the repo root or none found: audit everything"),
        ("EXCLUDE_DIRS", None, "(none)", "local-only exclusions; put shared rules in .secauditignore instead"),
        ("CHECK_SKIP", None, "(none)", "checklist IDs to skip, with the reason in notes.md"),
        ("SCAN_URL", url, "(unset)",
         "port found in .claude/launch.json" if url else "no local URL found; set one to enable the header and cookie check"),
        ("FAIL_ON", None, "critical", "dependency severity that counts as FAIL: critical | high | none"),
        ("NEXT_STEP", None, "ask", "after the findings: ask | none"),
    ]
    return [{"key": k, "value": v, "default": d, "reason": r, "active": v is not None} for k, v, d, r in items]


def apply_overrides(items, sets):
    by_key = {i["key"]: i for i in items}
    for raw in sets:
        key, sep, value = raw.partition("=")
        key = key.strip().upper()
        if not sep or key not in by_key:
            raise SystemExit(f"error: --set needs KEY=VALUE with a known key ({', '.join(KNOWN_KEYS)}): {raw}")
        by_key[key].update(value=value.strip(), active=bool(value.strip()))
    return items


def render_config(items):
    lines = [
        "# n2i-sec-audit config for this repo. Written by setup.py; edit freely.",
        "# Keep this folder out of git (add `.n2i-sec-audit/` to .gitignore) and keep secrets out of it.",
        "",
    ]
    for it in items:
        lines.append(f"# {it['reason']}")
        lines.append(f"{it['key']}={it['value']}" if it["active"] else f"# {it['key']}={it['default']}")
        lines.append("")
    return "\n".join(lines)


def cmd_config(args):
    root = os.path.abspath(args.path)
    items = apply_overrides(propose_config(root), args.set)
    if args.json:
        print(json.dumps(items, indent=2))
    else:
        for it in items:
            shown = it["value"] if it["active"] else f"{it['default']}  (default)"
            print(f"{it['key']:<15} {shown:<42} # {it['reason']}")
    if not args.write:
        return 0
    target = os.path.join(root, CONFIG_DIR, CONFIG_FILE)
    if os.path.exists(target) and not args.force:
        print(f"error: {target} exists; pass --force to overwrite", file=sys.stderr)
        return 1
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "w", encoding="utf-8") as fh:
        fh.write(render_config(items))
    print(f"wrote {os.path.relpath(target, root)}")
    ignore = os.path.join(root, ".gitignore")
    try:
        with open(ignore, encoding="utf-8") as fh:
            covered = any(ln.strip() in (f"{CONFIG_DIR}/", CONFIG_DIR) for ln in fh)
    except OSError:
        covered = False
    if not covered:
        print(f"note: add `{CONFIG_DIR}/` to .gitignore (this script does not edit it)")
    return 0


# ---------- ignore suggestions ----------

def classify(rel):
    """Return (glob, reason, confidence) for a path that looks like noise, else None."""
    parts = rel.split("/")
    if len(parts) > 1 and parts[0].lower() in LEGACY:
        return f"{parts[0]}/*", "legacy tree; hide it only if this code does not ship", "review"
    for i, part in enumerate(parts[:-1]):
        if part.lower() in TEST_DIRS:
            return "/".join(parts[:i + 1]) + "/*", "test code often holds fake secrets and permissive samples", "known"
    for i, part in enumerate(parts[:-1]):
        if scan.is_build_dir(part) or part in NON_SHIPPED_BUILD:
            end = min(i + 2, len(parts) - 1)
            glob = "/".join(parts[:end]) + "/*"
            if any(p in NON_SHIPPED_BUILD for p in parts[:end]):
                return glob, "test or cache output that does not ship", "known"
            return glob, "build output; it may ship, so check before hiding", "review"
    return None


def suggest_ignores(findings):
    groups = {}
    for f in findings:
        if f.protected or not f.hits or f.status not in ("WARN", "FAIL"):
            continue
        for rel in f.hits:
            hit = classify(rel)
            if not hit:
                continue
            glob, reason, confidence = hit
            g = groups.setdefault(glob, {"glob": glob, "ids": set(), "count": 0, "reason": reason,
                                         "confidence": confidence})
            g["ids"].add(f.id)
            g["count"] += 1
            if confidence == "review":
                g["confidence"], g["reason"] = "review", reason
    out = sorted(groups.values(), key=lambda g: (g["confidence"] != "known", -g["count"], g["glob"]))
    for n, g in enumerate(out, 1):
        g["n"] = n
        g["ids"] = sorted(g["ids"])
    return out


def rule_line(g):
    return f"{g['glob']}  {','.join(g['ids'])}  # {g['reason']} ({g['count']} hits when added)"


def pick(suggestions, accept):
    wanted = [a.strip().lower() for a in accept.split(",") if a.strip()]
    if wanted == ["all"]:
        return list(suggestions)
    if wanted == ["known"]:
        return [g for g in suggestions if g["confidence"] == "known"]
    try:
        nums = {int(w) for w in wanted}
    except ValueError:
        raise SystemExit("error: --accept takes numbers (1,3), `known`, or `all`")
    unknown = nums - {g["n"] for g in suggestions}
    if unknown:
        raise SystemExit(f"error: no suggestion numbered {sorted(unknown)}")
    return [g for g in suggestions if g["n"] in nums]


def existing_rules(path):
    keys = set()
    try:
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                parts = raw.split("#", 1)[0].split()
                if parts:
                    ids = tuple(sorted(i.upper() for i in ",".join(parts[1:]).split(",") if i))
                    keys.add((parts[0], ids))
    except OSError:
        pass
    return keys


def cmd_ignores(args):
    root = os.path.abspath(args.path)
    ns = argparse.Namespace(path=root, exclude=[], offline=True, url=None, fail_on="critical")
    suggestions = suggest_ignores(scan.collect(ns))
    if args.json:
        print(json.dumps(suggestions, indent=2))
    elif not suggestions:
        print("no ignore suggestions: nothing noisy found outside what the scanner already skips")
    else:
        print(f"{'#':<3} {'confidence':<10} {'rule':<44} {'checks':<12} hits  why")
        for g in suggestions:
            print(f"{g['n']:<3} {g['confidence']:<10} {g['glob']:<44} {','.join(g['ids']):<12} {g['count']:<5} {g['reason']}")
        print("\nThe scanner already skips vendor and build folders for code checks "
              f"({', '.join(sorted(scan.VENDOR_DIRS | scan.BUILD_DIRS))}, and any folder ending in -output).")
        print("Tracked secret-shaped files are never suggested. `review` rules can hide a real problem.")
    if not args.write:
        return 0
    if not args.accept:
        print("error: --write needs --accept (numbers, `known`, or `all`)", file=sys.stderr)
        return 2
    chosen = pick(suggestions, args.accept)
    target = os.path.join(root, scan.IGNORE_FILE)
    have = existing_rules(target)
    new = [g for g in chosen if (g["glob"], tuple(g["ids"])) not in have]
    if not new:
        print("nothing to add: the chosen rules already exist")
        return 0
    header = ""
    if not os.path.exists(target):
        header = ("# n2i-sec-audit ignore rules. One rule per line: glob [ID,ID]  # reason\n"
                  "# `*` matches across directories. Every rule hides something, so review them each audit.\n")
    with open(target, "a", encoding="utf-8") as fh:
        fh.write(header + "\n".join(rule_line(g) for g in new) + "\n")
    print(f"added {len(new)} rule(s) to {scan.IGNORE_FILE}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="First-run setup helpers for n2i-sec-audit.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("config", help="propose or write .n2i-sec-audit/config")
    c.add_argument("path", nargs="?", default=".")
    c.add_argument("--set", action="append", default=[], metavar="KEY=VALUE", help="override a proposed value")
    c.add_argument("--write", action="store_true")
    c.add_argument("--force", action="store_true")
    c.add_argument("--json", action="store_true")
    i = sub.add_parser("ignores", help="suggest or add .secauditignore rules")
    i.add_argument("path", nargs="?", default=".")
    i.add_argument("--write", action="store_true")
    i.add_argument("--accept", help="numbers (1,3), `known`, or `all`")
    i.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    if not os.path.isdir(args.path):
        print(f"error: {args.path} is not a directory", file=sys.stderr)
        return 2
    return cmd_config(args) if args.cmd == "config" else cmd_ignores(args)


if __name__ == "__main__":
    sys.exit(main())
