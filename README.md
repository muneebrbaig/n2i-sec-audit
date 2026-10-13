# n2i-sec-audit

A [Claude Code](https://claude.com/claude-code) skill that audits a codebase for security gaps and writes a report your team can act on. The report lists what already works, what is missing, and the evidence for both. A plan, tickets, or a hand-off to a build skill come after you have read the findings, and only if you ask for them.

[Null2Infinity](https://null2infinity.com) (N2I) built it as a companion to [n2i-dev-cycle](https://github.com/muneebrbaig/n2i-dev-cycle). This skill finds problems. `n2i-dev-cycle` fixes them.

## What an audit does

| Step | What happens |
|---|---|
| **1. Orient** | Detects your stacks, reads the project guide and config, loads the checklist and the matching stack adapters, and confirms scope with you. |
| **2. Scan** | Runs `scripts/scan.py` for raw-SQL candidates, browser token storage, wildcard CORS, source maps in build output, secret-shaped files and strings, and dependency advisories. It can also check response headers on a local or owned URL. |
| **3. Audit** | Walks every checklist item and assigns a status: `covered`, `partial`, `gap`, `n/a`, or `not-verified`. Each status carries `file:line` evidence. On large repos, one read-only agent takes each category. |
| **4. Challenge** | A separate agent tries to disprove every "covered" and "n/a" claim before the report goes out. |
| **5. Report** | Writes `docs/<date>-security-review.md` with a summary, an **Already covered** section, the gaps, the items nobody could verify, and open questions. A re-audit adds a **Changes since last review** section. |
| **6. Next step** | Asks what you want: a phased plan with estimates, ticket drafts, a hand-off to `n2i-dev-cycle`, or nothing. |

Other modes: `re-audit` compares against the last report, `verify <ID>` checks that a fix landed, and `scan` runs the scanner and stops.

## The checklist

The checklist has 27 items in four categories. Each item has a stable ID, pass criteria, a severity range, and mappings to the OWASP Top 10 (2021), the OWASP API Security Top 10 (2023), and CWE. Reports, re-audits, and tickets all refer to items by ID.

| Category | Items |
|---|---|
| **A. Injection and input** | SQL injection, XSS, CSRF, file uploads, SSRF, unsafe deserialization and mass assignment |
| **B. Authentication and access** | Object-level authorization, rate limiting, password storage, MFA, server-side permissions with default-deny, database-level isolation (RLS), session and token lifetime |
| **C. Secrets and tokens** | Signing keys, API secrets kept server-side, tokens out of browser storage, default and shared credentials, secrets in the repo and its history |
| **D. Config and hygiene** | CORS, webhook verification, source maps and debug surfaces, sensitive data in logs, vulnerable dependencies, security headers and CSP, error leakage, audit logging, CI and supply chain |

The first 21 items are core: the 20 baseline checks plus secrets in the repo. The rest are extended, and `CHECK_SKIP` turns any of them off.

## Install

### Single user

```bash
git clone https://github.com/muneebrbaig/n2i-sec-audit.git ~/projects/skills/n2i-sec-audit
ln -s ~/projects/skills/n2i-sec-audit ~/.claude/skills/n2i-sec-audit
~/projects/skills/n2i-sec-audit/scripts/install-agents.sh
```

Run `install-agents.sh` again after each `git pull`, because a release can add agents.

### Bundled into a project

[PROJECT-INSTALL.md](PROJECT-INSTALL.md) shows how to add the skill as a git submodule with a SessionStart hook that keeps it current. It works the same way as `n2i-dev-cycle`.

## First run

On the first audit in a repo the skill asks two questions, and fills in the answers for you.

1. **Config.** `scripts/setup.py config` proposes every setting with a value already filled in. It reads the stacks and scope directories from your manifests, picks up a local URL from `.claude/launch.json`, and uses the default for everything else. Each line carries a reason. You accept all of it or name the keys to change, and the skill writes `.n2i-sec-audit/config`.
2. **Ignore rules.** After the first scan, `scripts/setup.py ignores` groups the noise it found into suggested `.secauditignore` rules, with hit counts. The scanner needs no rule for some folders. It never scans dependency, cache, and test-run folders (`node_modules`, `vendor`, `test-results`, `playwright-report`, and similar) and reports how many tracked files that left out. It skips build folders (`dist`, `build`, `out`, `output`, `wwwroot`, any `*-output` folder, and similar) only for files git does not track, because a committed file is source. The suggestions cover what is left. D3 still looks inside build folders for source maps, because they can ship. `known` rules cover patterns that are almost always noise: test code, and build output that does not ship. `review` rules could hide a real problem, such as a `wwwroot` folder that ships or a legacy tree that still runs, so the skill recommends them only after it checks. Tracked secret-shaped files are never suggested. You pick the rules, the skill appends them with a reason, and the scan runs again.

Later runs skip both questions. You can run either script yourself:

```bash
python3 scripts/setup.py config .                              # preview the proposed config
python3 scripts/setup.py config . --write --set FAIL_ON=high   # save it, with a change
python3 scripts/setup.py ignores .                             # preview the suggested rules
python3 scripts/setup.py ignores . --write --accept known      # add the "known" rules
```

## Configure

Per-repo settings live in `<repo>/.n2i-sec-audit/config`. The first run writes it, and `n2i-sec-audit.config.example` documents every key. Add `.n2i-sec-audit/` to the repo's `.gitignore`: the folder holds local state (config, optional notes, the step ledger, the last scan output). The report goes in the repo, under `docs/` by default, so the team can review and commit it.

Keys: `REPORT_DIR`, `REPORT_GLOB`, `ACCEPTED_RISKS`, `STACKS`, `SCOPE_DIRS`, `EXCLUDE_DIRS`, `CHECK_SKIP`, `SCAN_URL`, `FAIL_ON`, `NEXT_STEP`. All are optional.

## Run the scanner

```bash
python3 scripts/scan.py <repo> [--url http://localhost:5000] [--offline] [--json] \
  [--exclude GLOB] [--fail-on critical|high|none]
```

The scanner uses the Python 3 standard library and prints one line per finding: a checklist ID, a status (`PASS`, `WARN`, `FAIL`, `SKIP`), and `file:line` evidence. It exits 1 when any check fails, so a CI job can use it as a gate.

- **Dependency audits** call `npm audit`, `dotnet list package --vulnerable`, and `pip-audit` if you have it. They need network access. `--offline` skips them.
- **Header and cookie check** (`--url`) sends one `GET` to a local or owned target and reads the response headers. A non-local target needs `--allow-remote` as proof you own it. The scanner sends no attack traffic.
- **A hit is a lead.** The audit reads the code before it calls anything a gap.

### Silence a known false positive

Put a `.secauditignore` file at the repo root. Each line holds a glob and, optionally, the check IDs it applies to:

```text
# fixtures hold fake secrets on purpose
tests/*        A1,C3,C5,D1
scripts/scan.py   D1
```

`*` matches across directories. A rule without IDs hides the file from every check. A folder rule such as `old/*` hides everything under it, secret-shaped files included. The scan output then lists each secret-shaped file the rules hid (an `INFO` line under C5), and the report repeats the list, so the people who read it can judge the rule. `--exclude GLOB` does the same from the command line. To skip one line, add `n2i-sec-audit: ignore` to it as a comment. The scanner always prints how many files the rules left out, and the audit reports the ignore file in the method section so a reader can judge it.

### Optional: gitleaks

[gitleaks](https://github.com/gitleaks/gitleaks) is an open-source secret scanner that also searches git history. It finds a secret that someone committed and deleted two years ago, which a scan of the current files misses. The skill uses it when it is on your `PATH`:

- **With gitleaks:** check C5 runs `gitleaks detect --redact`, covers history, and reports the file, line, and rule.
- **Without gitleaks:** check C5 scans the working tree with built-in patterns, and the report says history was not scanned.

The skill never installs it. On macOS, `brew install gitleaks` adds a small single binary.

## Run it on a schedule

A skill cannot start itself, so use two layers:

1. **A monthly CI job runs the scanner.** It uses no LLM and costs a few CI minutes. [`ci/`](ci) has samples for GitLab CI and GitHub Actions. The job fails when the scanner reports a `FAIL`.
2. **A quarterly run of the full audit.** Use a scheduled Claude Code routine or a calendar reminder to run `/n2i-sec-audit`. It produces a draft report and stops. A person reads the report and decides what happens next.

## Stack adapters

The checklist applies to any stack. Each adapter in `references/stacks/` lists the APIs to search, the config keys to read, and the commands to run for one stack:

- `dotnet-angular.md` covers ASP.NET Core, EF Core, and Angular.
- `node-python.md` covers Express, Fastify, Nest, Next, Django, Flask, and FastAPI.
- `generic.md` gives the approach for any other stack and explains how to write a new adapter.

Without a matching adapter the audit still runs, but it leans on judgment and the report says so. Adapters for Java/Spring, Go, Rails, Laravel, and mobile clients would help.

## Agents

All three are read-only, and `scripts/install-agents.sh` links them:

| Agent | Model | Job |
|---|---|---|
| `n2i-sec-scanner` | haiku | Runs the scan and returns a short result, so the log stays out of the main context. |
| `n2i-sec-category-auditor` | sonnet | Audits one checklist category. The skill runs one per category in parallel on large repos. |
| `n2i-sec-skeptic` | sonnet | Tries to disprove "covered" and "n/a" claims before the report is written. |

If an agent is missing, the skill does that work inline.

## Safety rules

- The skill changes nothing in your project except the report and its own `.n2i-sec-audit/` folder. It does not commit or push.
- It never prints a secret value. Reports give a location and a kind. It also skips reading credential files and checks only that they exist and whether git ignores them.
- It sends no attack traffic. The one network check is a single `GET` for headers against a local or owned target. It does no fuzzing, brute force, or exploitation. Dynamic scanners such as OWASP ZAP sit outside this skill.
- It asks before installing anything.
- It marks an item `covered` only with evidence from the current run.

## Working with n2i-dev-cycle

This skill produces findings and, on request, a plan or ticket drafts. `n2i-dev-cycle` takes a ticket and ships the fix through its own approval gate, test-first loop, and review. When you choose "hand off" at step 6, the skill names the items and their order, and the fixes follow that process.

## Tests

```bash
python3 -m unittest discover -s tests
```

The tests cover the scanner and the fallback secret scan (with a fake `gitleaks` and a local HTTP server for the header check), the checklist structure and mappings, adapter consistency, the agent definitions, the install scripts, and a guard that keeps project-specific names out of this repo. [`evals/scenarios.md`](evals/scenarios.md) lists behavior checks to run against the skill in a live session.

## License

MIT. See [LICENSE](LICENSE).
