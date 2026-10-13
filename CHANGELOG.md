# Changelog

## 0.1.0 (unreleased draft)

First draft.

- Added the skill with four modes (audit, re-audit, verify, scan) and a six-step flow: orient, scan, audit, challenge, report, next step.
- Added a 27-item checklist in four categories. The 20 baseline checks plus secrets-in-repo are core, and the rest are extended. Each item maps to the OWASP Top 10 2021, the OWASP API Top 10 2023, and CWE.
- Added stack adapters for .NET and Angular, Node and Python, and a generic fallback.
- Added a report template that puts "Already covered" in its own section. Plans, estimates, and tickets appear only on request.
- Added `scripts/scan.py`, a standard-library scanner for raw-SQL candidates, browser token storage, wildcard CORS, source maps, secret-shaped files and strings, and dependency advisories (npm, .NET, Python). With `--url` it reads response headers and cookie flags on a local or owned target.
- Added `.secauditignore`, `--exclude`, and an inline `n2i-sec-audit: ignore` marker for known false positives. The scanner reports every file the rules leave out.
- Added `scripts/setup.py` for the first run. `config` proposes every setting with a value pre-filled from the repo (stacks, scope directories, a local URL) or the default, and writes `.n2i-sec-audit/config` after you accept. `ignores` groups scan noise into suggested `.secauditignore` rules, graded `known` or `review`, and appends the ones you accept. It never suggests rules for tracked secret-shaped files.
- Changed the default skip rules so they never hide committed source. Dependency, cache, and test-run folders (`node_modules`, `vendor`, `test-results`, `playwright-report`, and similar) are never scanned, and the scan output counts the tracked files that left out. Build folders (`dist`, `build`, `out`, `output`, `target`, `wwwroot`, any `*-output` folder) are skipped only for files git does not track.
- A folder ignore rule such as `old/*` hides everything under it, including secret-shaped files such as `.env.production`. The scan prints an `INFO` line under C5 that names each secret-shaped file the rules hid, so the hidden files stay visible to anyone who reads the output or the report.
- Added optional gitleaks support. The skill uses it when installed and covers git history. Otherwise a built-in pattern scan runs and the report says history was not scanned.
- Added three read-only agents: `n2i-sec-scanner` (haiku), `n2i-sec-category-auditor` (sonnet), and `n2i-sec-skeptic` (sonnet).
- Added `scripts/project-sync.sh`, a SessionStart hook template that syncs every `n2i-*` skill submodule in a project.
- Added sample scheduled-scan jobs for GitLab CI and GitHub Actions.
- Added tests for the scanners, checklist, agents, and install scripts, plus draft eval scenarios.
