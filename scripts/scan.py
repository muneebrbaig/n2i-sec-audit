#!/usr/bin/env python3
"""Deterministic security checks for n2i-sec-audit. Read-only, standard library only.

Each check prints one line per finding: ID, STATUS, detail. IDs are the checklist IDs in
references/checklist.md. A scan hit is a lead for the auditor, not a verdict.

Safety rules baked in:
  * Never prints a secret value. Locations and kinds only.
  * Never reads the contents of credential files to report on them (existence and
    git-ignore status only).
  * --url targets must be local (localhost, 127.0.0.1, ::1, *.localhost, *.test) unless
    --allow-remote asserts you own the target. No attack traffic is sent: one GET.

Suppressing known false positives (the output always says what was left out):
  * `.secauditignore` at the repo root: one rule per line, `glob [ID,ID]`, `#` starts a comment.
    `*` matches across directories. Without IDs the rule hides the file from every check.
  * `--exclude GLOB` on the command line, same meaning, repeatable.
  * A line containing `n2i-sec-audit: ignore` is skipped by the line-based checks.

Usage: scan.py [PATH] [--url URL] [--allow-remote] [--offline] [--json]
               [--exclude GLOB] [--fail-on critical|high|none]
Exit:  0 no FAIL, 1 at least one FAIL, 2 usage error
"""
import argparse
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secret_scan  # noqa: E402

# Never inspected: dependencies, caches, and test-run artifacts.
VENDOR_DIRS = {".git", "node_modules", "bin", "obj", "__pycache__", ".venv", "venv", "vendor", ".angular",
               "test-results", "TestResults", "playwright-report", ".pytest_cache", ".mypy_cache", ".gradle"}
# Generated output: skipped by the code checks, but D3 looks inside for source maps because it can ship.
# Any folder whose name ends in `-output` counts too (see is_build_dir).
BUILD_DIRS = {"dist", "build", "out", "output", "target", "artifacts", "wwwroot", "coverage", ".output", ".next"}
CODE_EXT = {
    ".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".html", ".cs", ".py", ".java", ".kt",
    ".go", ".rb", ".php", ".rs",
}
FRONTEND_EXT = {".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".html"}
SENSITIVE_FILE = re.compile(
    r"(^|/)(\.env(\.[\w.-]+)?|[^/]*\.(pem|key|p12|pfx|jks)|id_rsa|id_ed25519|[^/]*credentials[^/]*)$", re.I
)
SENSITIVE_OK = re.compile(r"\.(example|sample|template|dist)$|\.pub$", re.I)
MAX_LIST = 8
IGNORE_FILE = ".secauditignore"

TOKEN_STORE = re.compile(
    r"""(?ix)(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(
        (?:\s*['"`][^'"`]*(?:token|jwt|auth|refresh|session|user|credential)[^'"`]*['"`]
        |[^)]*(?:token|jwt|refresh))"""
)
CORS_WILDCARD = re.compile(
    r"""(?ix)AllowAnyOrigin\b
        |Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*
        |origin\s*:\s*(?:true|['"]\*['"])
        |allow_origins\s*=\s*\[\s*['"]\*['"]
        |CORS_ALLOW_ALL_ORIGINS\s*=\s*True
        |\bcors\(\s*\)"""
)
RAW_SQL = [
    re.compile(r"\b(FromSqlRaw|ExecuteSqlRaw|SqlQueryRaw|queryRawUnsafe|executeRawUnsafe)\s*\(", re.I),
    re.compile(r"""(?i)['"]\s*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^'"\n]*['"]\s*\+"""),
    re.compile(r"""(?i)\b(?:f|\$)['"]\s*(?:SELECT|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b[^'"\n]*\{"""),
    re.compile(r"(?i)`\s*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^`]*\$\{"),
]


@dataclass
class Finding:
    id: str
    status: str  # PASS | WARN | FAIL | SKIP | INFO
    detail: str
    evidence: list = field(default_factory=list)
    hits: list = field(default_factory=list)  # every file that triggered it, one entry per hit (setup.py reads this)
    protected: bool = False  # setup.py never suggests an ignore rule for a protected finding


def file_of(hit):
    """Return the file part of an evidence string like `path:12` or `path:12  kind`."""
    m = re.match(r"(.+?):\d+(?:\s|$)", hit)
    return m.group(1) if m else hit


class Ignores:
    """Path rules from .secauditignore and --exclude. A rule is `glob [ID,ID]`; `*` matches across
    directories. Every skipped file is recorded so the output can say what was left out."""

    def __init__(self, root, extra=()):
        self.rules = []
        self.skipped = set()
        try:
            with open(os.path.join(root, IGNORE_FILE), encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        except OSError:
            lines = []
        for raw in lines:
            parts = raw.split("#", 1)[0].split()
            if parts:
                ids = {i.upper() for i in ",".join(parts[1:]).split(",") if i}
                self.rules.append((parts[0], ids or None))
        self.rules += [(g, None) for g in extra]

    def hides(self, rel, check_id):
        for glob, ids in self.rules:
            if fnmatch.fnmatch(rel, glob) and (ids is None or check_id in ids):
                self.skipped.add(rel)
                return True
        return False

    def filter(self, rels, check_id):
        return [r for r in rels if not self.hides(r, check_id)]


# ---------- helpers ----------

def run(cmd, cwd=None, timeout=120):
    """Return (returncode, stdout) or None when the tool is missing or times out."""
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    return p.returncode, p.stdout


def git_lines(root, *args):
    r = run(["git", "-C", root, *args], timeout=30)
    if r is None or r[0] != 0:
        return None
    return r[1].splitlines()


def is_build_dir(name):
    return name in BUILD_DIRS or name.endswith("-output")


def under_skipped(rel, dirs, build=False):
    """True when any parent folder of `rel` is in `dirs`, or (with build=True) is a build folder."""
    return any(part in dirs or (build and is_build_dir(part)) for part in rel.split("/")[:-1])


def list_files(root):
    """Return (tracked, untracked_not_ignored, is_git)."""
    tracked = git_lines(root, "ls-files")
    if tracked is not None:
        return tracked, git_lines(root, "ls-files", "-o", "--exclude-standard") or [], True
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in VENDOR_DIRS]
        for name in filenames:
            found.append(os.path.relpath(os.path.join(dirpath, name), root).replace(os.sep, "/"))
    return [], found, False


def skipped_for_content(rel, tracked_set):
    """Dependency, cache, and test-run folders are never scanned. Build folders are skipped only for
    files git does not track: a committed file is source by the owner's choice, so it stays in scope."""
    if under_skipped(rel, VENDOR_DIRS):
        return True
    return rel not in tracked_set and under_skipped(rel, BUILD_DIRS, build=True)


def skipped_tracked(tracked):
    """Count tracked files hidden by the dependency/cache rule, grouped by folder, so the output can say so."""
    counts = {}
    for rel in tracked:
        parts = rel.split("/")
        for i, part in enumerate(parts[:-1]):
            if part in VENDOR_DIRS:
                key = "/".join(parts[:i + 1])
                counts[key] = counts.get(key, 0) + 1
                break
    return counts


def code_files(root, tracked, untracked, exts):
    tracked_set = set(tracked)
    for rel in tracked + untracked:
        if skipped_for_content(rel, tracked_set):
            continue
        if os.path.splitext(rel)[1].lower() in exts:
            yield rel


def grep_files(root, rels, patterns):
    """Return ['rel:line', ...] for lines matching any pattern. Never includes the line text."""
    hits = []
    for rel in rels:
        text = secret_scan.read_text(os.path.join(root, rel))
        if text is None:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if secret_scan.INLINE_IGNORE not in line and any(p.search(line) for p in patterns):
                hits.append(f"{rel}:{lineno}")
    return hits


def walk_for(root, names=None, suffixes=(), max_depth=4, skip=VENDOR_DIRS | BUILD_DIRS):
    out = []
    base_depth = root.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root):
        if dirpath.count(os.sep) - base_depth >= max_depth:
            dirnames[:] = []
        dirnames[:] = [d for d in dirnames if d not in skip and not d.endswith("-output")]
        for name in filenames:
            if (names and name in names) or (suffixes and name.endswith(suffixes)):
                out.append(os.path.join(dirpath, name))
    return sorted(out, key=lambda p: (p.count(os.sep), p))


def more(items):
    shown = items[:MAX_LIST]
    if len(items) > MAX_LIST:
        shown.append(f"(+{len(items) - MAX_LIST} more)")
    return shown


# ---------- checks ----------

def check_raw_sql(root, files, ig):
    hits = grep_files(root, ig.filter(files, "A1"), RAW_SQL)
    if hits:
        return [Finding("A1", "WARN", f"{len(hits)} raw-SQL candidate(s); review each for parameterization",
                        more(hits), [file_of(h) for h in hits])]
    return [Finding("A1", "PASS", "no raw-SQL candidates found (heuristic; does not prove absence)")]


def check_token_storage(root, files, ig):
    rels = [f for f in ig.filter(files, "C3") if os.path.splitext(f)[1].lower() in FRONTEND_EXT]
    hits = grep_files(root, rels, [TOKEN_STORE])
    if hits:
        return [Finding("C3", "WARN", f"{len(hits)} browser-storage write(s) that may hold tokens or user objects",
                        more(hits), [file_of(h) for h in hits])]
    return [Finding("C3", "PASS", "no token-shaped browser storage writes found")]


def check_cors(root, files, ig):
    hits = grep_files(root, ig.filter(files, "D1"), [CORS_WILDCARD])
    if hits:
        return [Finding("D1", "WARN", f"{len(hits)} permissive CORS pattern(s)", more(hits),
                        [file_of(h) for h in hits])]
    return [Finding("D1", "PASS", "no wildcard CORS patterns found")]


def check_source_maps(root, ig):
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in VENDOR_DIRS]
        rel_parts = os.path.relpath(dirpath, root).split(os.sep)
        if not any(is_build_dir(p) for p in rel_parts):
            continue
        found += [os.path.relpath(os.path.join(dirpath, n), root) for n in filenames if n.endswith(".map")]
    found = ig.filter(found, "D3")
    if found:
        return [Finding("D3", "WARN", f"{len(found)} source map file(s) in build output", more(sorted(found)),
                        list(found))]
    return [Finding("D3", "PASS", "no .map files in build output directories")]


def check_sensitive_files(tracked, untracked, is_git, ig):
    tracked, untracked = ig.filter(tracked, "C5"), ig.filter(untracked, "C5")
    out = []
    bad = [f for f in tracked if SENSITIVE_FILE.search(f) and not SENSITIVE_OK.search(f)
           and not under_skipped(f, {"node_modules", ".git"})]
    if bad:
        out.append(Finding("C5", "FAIL", f"{len(bad)} tracked secret-shaped file(s); rotate anything they hold",
                           more(bad), list(bad), protected=True))
    loose = [f for f in untracked if SENSITIVE_FILE.search(f) and not SENSITIVE_OK.search(f)
             and not under_skipped(f, {"node_modules", ".git"})]
    if loose:
        note = "present and NOT git-ignored" if is_git else "present (git status unknown)"
        out.append(Finding("C5", "WARN", f"{len(loose)} secret-shaped file(s) {note}", more(loose),
                           list(loose), protected=True))
    if not out:
        out.append(Finding("C5", "PASS", "no tracked or loose secret-shaped files"))
    return out


def run_gitleaks(root, is_git):
    exe = shutil.which("gitleaks")
    if not exe:
        return None
    with tempfile.TemporaryDirectory() as td:
        report = os.path.join(td, "report.json")
        cmd = [exe, "detect", "--source", root, "--no-banner", "--redact",
               "--report-format", "json", "--report-path", report, "--exit-code", "0"]
        if not is_git:
            cmd.append("--no-git")
        if run(cmd, timeout=300) is None:
            return None
        try:
            with open(report, encoding="utf-8") as fh:
                data = json.load(fh) or []
        except (OSError, ValueError):
            return None
    return [(d.get("File", "?"), d.get("StartLine", "?"), d.get("RuleID", "secret")) for d in data]


def check_secrets(root, tracked, untracked, is_git, ig):
    leaks = run_gitleaks(root, is_git)
    if leaks is not None:
        leaks = [f"{f}:{n}  {rule}" for f, n, rule in leaks if not ig.hides(f, "C5")]
        if leaks:
            return [Finding("C5", "FAIL", f"gitleaks: {len(leaks)} finding(s), history included; rotate them",
                            more(leaks), [file_of(h) for h in leaks])]
        return [Finding("C5", "PASS", "gitleaks: no findings (working tree and history)")]
    hits = []
    tracked_set = set(tracked)
    for rel in ig.filter(tracked + untracked, "C5"):
        if skipped_for_content(rel, tracked_set) or SENSITIVE_OK.search(rel):
            continue
        for lineno, kind in secret_scan.scan_file(os.path.join(root, rel)):
            hits.append(f"{rel}:{lineno}  {kind}")
    note = "fallback pattern scan; gitleaks not installed, git history NOT scanned"
    if hits:
        return [Finding("C5", "FAIL", f"{len(hits)} secret-shaped string(s) ({note}); rotate them", more(hits),
                        [file_of(h) for h in hits])]
    return [Finding("C5", "PASS", f"no secret-shaped strings in the working tree ({note})")]


def dep_status(counts, fail_on):
    crit, high = counts.get("critical", 0), counts.get("high", 0)
    if crit and fail_on in ("critical", "high"):
        return "FAIL"
    if high and fail_on == "high":
        return "FAIL"
    if crit or high or counts.get("moderate", 0) or counts.get("low", 0):
        return "WARN"
    return "PASS"


def fmt_counts(counts):
    parts = [f"{counts.get(k, 0)} {k}" for k in ("critical", "high", "moderate", "low") if counts.get(k, 0)]
    return ", ".join(parts) if parts else "none"


def audit_npm(root, fail_on):
    out = []
    for lock in walk_for(root, names={"package-lock.json"}):
        d = os.path.dirname(lock)
        label = os.path.relpath(d, root) or "."
        r = run(["npm", "audit", "--omit=dev", "--json"], cwd=d, timeout=180)
        if r is None:
            out.append(Finding("D5", "SKIP", f"npm ({label}): npm not available or timed out"))
            continue
        try:
            counts = json.loads(r[1]).get("metadata", {}).get("vulnerabilities", {})
        except ValueError:
            out.append(Finding("D5", "SKIP", f"npm ({label}): audit returned no JSON (offline or registry error)"))
            continue
        out.append(Finding("D5", dep_status(counts, fail_on), f"npm ({label}): {fmt_counts(counts)}"))
    return out


def audit_dotnet(root, fail_on):
    targets = walk_for(root, suffixes=(".slnx", ".sln"))
    if not targets:
        targets = walk_for(root, suffixes=(".csproj",))[:3]
    if not targets:
        return []
    if not shutil.which("dotnet"):
        return [Finding("D5", "SKIP", "dotnet: SDK not available")]
    out = []
    for target in targets[:1] if targets[0].endswith((".sln", ".slnx")) else targets:
        r = run(["dotnet", "list", target, "package", "--vulnerable", "--include-transitive"], timeout=300)
        label = os.path.relpath(target, root)
        if r is None:
            out.append(Finding("D5", "SKIP", f"dotnet ({label}): timed out"))
            continue
        counts = {}
        for line in r[1].splitlines():
            m = re.match(r"\s+>\s+\S+.*\b(Critical|High|Moderate|Low)\b", line)
            if m:
                key = m.group(1).lower()
                counts[key] = counts.get(key, 0) + 1
        if not counts and "no vulnerable packages" not in r[1]:
            out.append(Finding("D5", "SKIP", f"dotnet ({label}): could not read advisory data (offline or restore needed)"))
            continue
        out.append(Finding("D5", dep_status(counts, fail_on), f"dotnet ({label}): {fmt_counts(counts)}"))
    return out


def audit_python(root):
    reqs = walk_for(root, names={"requirements.txt"})
    if not reqs:
        return []
    exe = shutil.which("pip-audit")
    if not exe:
        return [Finding("D5", "SKIP", "python: pip-audit not installed; run it manually or install it")]
    out = []
    for req in reqs[:3]:
        label = os.path.relpath(req, root)
        r = run([exe, "-r", req, "--progress-spinner", "off"], timeout=300)
        if r is None:
            out.append(Finding("D5", "SKIP", f"python ({label}): pip-audit failed to run"))
        elif r[0] == 0:
            out.append(Finding("D5", "PASS", f"python ({label}): no known vulnerabilities"))
        else:
            out.append(Finding("D5", "WARN", f"python ({label}): pip-audit reported vulnerabilities; run it for details"))
    return out


def is_local(host):
    return host in ("localhost", "127.0.0.1", "::1") or host.endswith((".localhost", ".test"))


def fetch_headers(url):
    req = urllib.request.Request(url, headers={"User-Agent": "n2i-sec-audit"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.headers
    except urllib.error.HTTPError as err:
        return err.headers
    except (urllib.error.URLError, OSError):
        return None


def check_headers(url):
    headers = fetch_headers(url)
    if headers is None:
        return [Finding("D6", "SKIP", f"could not reach {url}")]
    https = urlparse(url).scheme == "https"
    out, missing = [], []
    csp = headers.get("Content-Security-Policy")
    if not csp:
        missing.append("Content-Security-Policy")
    if (headers.get("X-Content-Type-Options") or "").lower() != "nosniff":
        missing.append("X-Content-Type-Options: nosniff")
    if not headers.get("Referrer-Policy"):
        missing.append("Referrer-Policy")
    if not (headers.get("X-Frame-Options") or (csp and "frame-ancestors" in csp.lower())):
        missing.append("frame protection (X-Frame-Options or CSP frame-ancestors)")
    if https and not headers.get("Strict-Transport-Security"):
        missing.append("Strict-Transport-Security")
    leaks = [h for h in ("X-Powered-By", "Server") if re.search(r"\d", headers.get(h) or "")]
    if missing:
        out.append(Finding("D6", "WARN", f"{len(missing)} security header(s) missing", missing))
    else:
        out.append(Finding("D6", "PASS", "expected security headers present"))
    if leaks:
        out.append(Finding("D7", "WARN", "version banner header(s) exposed", leaks))
    weak = []
    for cookie in headers.get_all("Set-Cookie") or []:
        name = cookie.split("=", 1)[0].strip()
        low = cookie.lower()
        lacks = [flag for flag, ok in (
            ("HttpOnly", "httponly" in low),
            ("Secure", "secure" in low or not https),
            ("SameSite", "samesite" in low),
        ) if not ok]
        if lacks:
            weak.append(f"{name}: missing {', '.join(lacks)}")
    if weak:
        out.append(Finding("B7", "WARN", f"{len(weak)} cookie(s) with weak flags", more(weak)))
    return out


# ---------- driver ----------

def collect(args):
    root = os.path.abspath(args.path)
    tracked, untracked, is_git = list_files(root)
    ig = Ignores(root, args.exclude)
    files = list(code_files(root, tracked, untracked, CODE_EXT))
    findings = []
    findings += check_raw_sql(root, files, ig)
    findings += check_token_storage(root, files, ig)
    findings += check_cors(root, files, ig)
    findings += check_source_maps(root, ig)
    findings += check_sensitive_files(tracked, untracked, is_git, ig)
    findings += check_secrets(root, tracked, untracked, is_git, ig)
    if args.offline:
        findings.append(Finding("D5", "SKIP", "dependency audits skipped (--offline)"))
    else:
        found = audit_npm(root, args.fail_on) + audit_dotnet(root, args.fail_on) + audit_python(root)
        findings += found or [Finding("D5", "SKIP", "no supported dependency manifests found")]
    if args.url:
        findings += check_headers(args.url)
    hidden = skipped_tracked(tracked)
    if hidden:
        top = sorted(hidden.items(), key=lambda kv: (-kv[1], kv[0]))
        findings.append(Finding("--", "INFO", f"{sum(hidden.values())} tracked file(s) under dependency or cache "
                                "folders were not scanned (committed vendor code, for example)",
                                more([f"{d} ({n} files)" for d, n in top])))
    if ig.skipped:
        findings.append(Finding("--", "INFO", f"{len(ig.skipped)} file(s) left out by {IGNORE_FILE} or --exclude; "
                                "review those rules before trusting a clean result", more(sorted(ig.skipped))))
    return findings


def render(findings):
    lines = []
    for f in findings:
        lines.append(f"{f.id:<4}{f.status:<5} {f.detail}")
        lines += [f"        {e}" for e in f.evidence]
    counts = {s: sum(1 for f in findings if f.status == s) for s in ("PASS", "WARN", "FAIL", "SKIP")}
    lines.append(f"SUMMARY pass={counts['PASS']} warn={counts['WARN']} fail={counts['FAIL']} skip={counts['SKIP']}")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Deterministic security checks (read-only).")
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--url", help="local or owned target; one GET to read response headers")
    ap.add_argument("--allow-remote", action="store_true", help="assert you own a non-local --url target")
    ap.add_argument("--offline", action="store_true", help="skip dependency audits (they need network)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                    help="skip files matching GLOB in every check (repeatable); see also .secauditignore")
    ap.add_argument("--fail-on", choices=["critical", "high", "none"], default="critical",
                    help="dependency severity that counts as FAIL; 'none' never exits 1")
    args = ap.parse_args(argv)

    if not os.path.isdir(args.path):
        print(f"error: {args.path} is not a directory", file=sys.stderr)
        return 2
    if args.url:
        host = urlparse(args.url).hostname or ""
        if not is_local(host) and not args.allow_remote:
            print(f"error: {host or args.url} is not a local target; pass --allow-remote only if you own it",
                  file=sys.stderr)
            return 2

    findings = collect(args)
    if args.json:
        print(json.dumps([{k: v for k, v in f.__dict__.items() if k not in ("hits", "protected")}
                          for f in findings], indent=2))
    else:
        print(render(findings))
    if args.fail_on != "none" and any(f.status == "FAIL" for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
