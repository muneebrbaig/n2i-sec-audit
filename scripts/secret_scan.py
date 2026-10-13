#!/usr/bin/env python3
"""Fallback secret-shape scanner for n2i-sec-audit (used when gitleaks is not installed).

Reports `line number + kind` only. It never returns or prints the matched text, so a
report built from its output cannot leak the secret. Scans the working tree, not git
history; gitleaks covers history.

Usage: secret_scan.py PATH [PATH ...]   (files or directories)
Exit:  0 no hits, 1 hits, 2 usage error
"""
import os
import re
import sys

PATTERNS = [
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("private key block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("password in URL", re.compile(r"://[^/\s:@]+:[^/\s:@]{3,}@")),
    (
        "secret assignment",
        re.compile(
            r"""(?ix)(api[_-]?key|secret|token|passwd|password)[\w-]*['"]?\s*[:=]\s*['"][^'"\s]{8,}['"]"""
        ),
    ),
]

# Placeholders that look like the pattern but are not real secrets.
ALLOW = re.compile(r"(?i)(example|dummy|placeholder|your[_-]?|<[^>]+>|xxx+|\.\.\.|changeme|redacted)")

INLINE_IGNORE = "n2i-sec-audit: ignore"
MAX_BYTES = 1_000_000
SKIP_DIRS = {".git", "node_modules", "bin", "obj", "__pycache__", ".venv", "venv", "vendor", ".angular"}


def scan_text(text):
    """Return [(line_number, kind)] for lines shaped like a secret. Never returns the match."""
    hits = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if INLINE_IGNORE in line or ALLOW.search(line):
            continue
        for kind, rx in PATTERNS:
            if rx.search(line):
                hits.append((lineno, kind))
                break
    return hits


def read_text(path):
    """Return file text, or None for unreadable, oversized, or binary files."""
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return None
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    if b"\x00" in data:
        return None
    return data.decode("utf-8", errors="ignore")


def scan_file(path):
    text = read_text(path)
    return scan_text(text) if text is not None else []


def iter_files(paths):
    for p in paths:
        if os.path.isfile(p):
            yield p
        elif os.path.isdir(p):
            for dirpath, dirnames, filenames in os.walk(p):
                dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
                for name in filenames:
                    yield os.path.join(dirpath, name)


def main(argv):
    if len(argv) < 2:
        print("usage: secret_scan.py PATH [PATH ...]", file=sys.stderr)
        return 2
    total = 0
    for path in iter_files(argv[1:]):
        for lineno, kind in scan_file(path):
            print(f"{path}:{lineno}  {kind}")
            total += 1
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
