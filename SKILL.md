---
name: n2i-sec-audit
description: Audits a codebase against a stack-agnostic security checklist (injection, auth and access, secrets and tokens, config and hygiene) and writes a findings report with an "already covered" section. Use when the user asks for a security review or audit, wants to know the security gaps, runs a periodic re-audit, or wants to verify security fixes landed. Read-only; offers a plan, ticket drafts, or a hand-off only after the findings.
argument-hint: "[audit | re-audit | verify <ID or phase> | scan] [path or focus]"
allowed-tools: Bash, Read, Write, Edit, Agent, Grep, Glob
---

# N2I Security Audit

Whole-codebase security audit. Static review plus deterministic scans, a findings report in the repo, and a choice of what happens next. Stack-agnostic checklist, with per-stack adapters for the search patterns.

## Contents

- Dynamic Context
- Input Parsing
- Safety rules
- Step 1: Orient
- Step 2: Scan
- Step 3: Audit
- Step 4: Challenge
- Step 5: Report
- Step 6: Next step
- Verify mode
- Cross-Cutting Mechanics

## Dynamic Context

- Stacks: !`S=""; find . -maxdepth 3 \( -name '*.sln' -o -name '*.slnx' -o -name '*.csproj' \) -not -path '*/node_modules/*' 2>/dev/null | grep -q . && S="$S dotnet"; find . -maxdepth 3 -name angular.json -not -path '*/node_modules/*' 2>/dev/null | grep -q . && S="$S angular"; find . -maxdepth 3 -name package.json -not -path '*/node_modules/*' 2>/dev/null | grep -q . && S="$S node"; find . -maxdepth 3 \( -name requirements.txt -o -name pyproject.toml \) -not -path '*/node_modules/*' 2>/dev/null | grep -q . && S="$S python"; echo "STACKS=${S:- unknown}"`
- Skill dir: !`D=.claude/skills/n2i-sec-audit; [ -d "$D" ] || D="$HOME/.claude/skills/n2i-sec-audit"; echo "SKILL_DIR=$D"`
- Current branch: !`git branch --show-current 2>/dev/null || echo "not-a-repo"`
- Config: !`f=$(find . -maxdepth 3 -path '*/.n2i-sec-audit/config' -not -path '*/node_modules/*' 2>/dev/null | head -1); if [ -n "$f" ]; then . "$f" 2>/dev/null; echo "CONFIG=$f; REPORT_DIR=${REPORT_DIR:-docs}; STACKS_OVERRIDE=${STACKS:-auto}; SCOPE_DIRS=${SCOPE_DIRS:-all}; CHECK_SKIP=${CHECK_SKIP:-none}; SCAN_URL=${SCAN_URL:-unset}; FAIL_ON=${FAIL_ON:-critical}; NEXT_STEP=${NEXT_STEP:-ask}"; else echo "CONFIG=none (see n2i-sec-audit.config.example)"; fi`
- Previous report: !`f=$(find . -maxdepth 3 -path '*/.n2i-sec-audit/config' -not -path '*/node_modules/*' 2>/dev/null | head -1); [ -n "$f" ] && . "$f" 2>/dev/null; R=$(ls -t "${REPORT_DIR:-docs}"/${REPORT_GLOB:-*security-review*.md} 2>/dev/null | head -1); echo "PREVIOUS_REPORT=${R:-none}"`
- Secret scanner: !`command -v gitleaks >/dev/null 2>&1 && echo "GITLEAKS=available (history is scanned)" || echo "GITLEAKS=absent (fallback pattern scan; git history is NOT scanned)"`
- Agents: !`D="$HOME/.claude/agents"; M=""; for f in "$HOME"/.claude/skills/n2i-sec-audit/agents/n2i-sec-*.md .claude/skills/n2i-sec-audit/agents/n2i-sec-*.md; do [ -e "$f" ] || continue; [ -e "$D/$(basename "$f")" ] || [ -e ".claude/agents/$(basename "$f")" ] || M="$M $(basename "$f" .md)"; done; if [ -z "$M" ]; then echo "AGENTS=ok"; else echo "AGENTS=missing:$M"; fi`

> **Note:** the values above are detected context. The shell does not export them. In later Bash steps, substitute the literal path or value. If `AGENTS=missing:` lists agents, tell the user once: "n2i-sec-audit agents aren't linked (<names>); run `<SKILL_DIR>/scripts/install-agents.sh`. Until then the skill follows the agent fallback below." Don't run it unasked; it writes to `~/.claude`.

## Input Parsing

The text after the skill name sets the mode:

| Input | Mode | Action |
|---|---|---|
| empty, `audit`, or a focus phrase ("security review of the API") | **Audit** | Steps 1 to 6. If a previous report exists, run as a re-audit (see Step 5). |
| `re-audit` | **Re-audit** | Audit, and require the previous report. Output includes "Changes since last review". |
| `verify <ID or phase>` | **Verify** | Check that named fixes landed. See "Verify mode". |
| `scan` | **Scan** | Step 2 only. Report the scan result and stop. |
| a path | scope | Audit only that directory. |

If the input is ambiguous, ask once.

## Safety rules

These hold in every mode and override convenience.

1. **Read-only on the project.** The only files this skill writes are the report (and, when asked, the accepted-risks file) under the configured report directory, its own `.n2i-sec-audit/` folder (including the config the user approved), and the `.secauditignore` rules the user accepted. It does not edit source, other config, `.gitignore`, or dependencies. It does not commit or push.
2. **Never print a secret value.** Not in chat, not in the report, not in the ledger. Cite the location and the kind. Do not read credential files (`.env*`, `*.bak` credential files, keys, certificates) to report on them; check that they exist and whether `git check-ignore` covers them. If a tool result shows a secret anyway, say so once, treat it as exposed, and recommend rotation without repeating the value.
3. **No attack traffic.** The only network check is one `GET` for response headers (`scan.py --url`), against a local or owned target. Remote targets need `--allow-remote` and the user's confirmation that they own the target. Never point it at production without the user saying so. No fuzzing, brute force, or exploitation. A dynamic scanner is out of scope for this skill.
4. **No installs without asking.** Name the package, why it is needed, approximate size, and approximate install time. `gitleaks` is optional: use it if present, otherwise use the built-in fallback and say history was not scanned.
5. **Evidence or `not-verified`.** Never assert a control works without evidence you saw this session.
6. **Authorization.** Audit only code the user owns or is authorized to review. If the repo looks like someone else's, ask first.

## Step 1: Orient

1. Read the repo's `CLAUDE.md`/`README`, the config (if any), and `.n2i-sec-audit/notes.md` (if present). Scan `notes.md` for credential shapes (a password in a URL, `Bearer ` tokens, PEM headers, long `key=`/`secret=` literals) and warn if found; it flows into the ledger and reports.
2. Confirm `.n2i-sec-audit/` is in the repo's `.gitignore`. If missing, tell the user to add it (the only tracked file this skill would ever touch, and it won't touch it).
3. First run (`CONFIG=none`): set up the config.
   - Run `python3 <SKILL_DIR>/scripts/setup.py config <repo>`. It proposes every config key with a value already filled in, taken from the repo (stacks, scope directories, a local URL from `.claude/launch.json`) or from the default, with a reason for each.
   - Show that list. Ask once: accept all, or name the keys to change.
   - Run the command again with `--write`, adding `--set KEY=VALUE` for each change. It writes `<root>/.n2i-sec-audit/config` and refuses to overwrite an existing file.
   - If the output says `.gitignore` lacks `.n2i-sec-audit/`, tell the user. Do not edit `.gitignore` yourself.
   - If the user declines, carry the proposed values in memory for this run.
4. Load the references:
   - `<SKILL_DIR>/references/checklist.md`
   - the adapter for each detected stack: `references/stacks/dotnet-angular.md` for `dotnet`/`angular`, `references/stacks/node-python.md` for `node`/`python`, and `references/stacks/generic.md` for anything else (or alongside, for mixed repos). Tell the user which adapters are driving the audit. With only the generic adapter, say the audit is thinner.
5. Confirm scope in one short message: directories, stacks, whether production-like environments exist, and whether the user wants the optional header check (needs a local/owned URL). Ask at most one clarifying question. Useful ones: what data or tenants matter most, and which environments exist.
6. If `PREVIOUS_REPORT` is set, read it. This is a re-audit. Note its finding IDs and statuses.
7. Start the ledger `.n2i-sec-audit/progress.md`: first line `# security audit <date>: <scope>`, then one `Step N: <what landed>` line per step.

## Step 2: Scan

Run the deterministic scan. Delegate to `n2i-sec-scanner` (haiku) so the log stays out of the main context. If the agent is missing, follow the agent fallback; with no subagents at all, run the scan inline and read only the summary and FAIL/WARN lines.

```bash
python3 <SKILL_DIR>/scripts/scan.py <repo> [--url <local-or-owned-url>] [--offline] [--exclude <glob> ...] --fail-on <FAIL_ON>
```

- Pass each `EXCLUDE_DIRS` entry as `--exclude`. The scanner also reads `.secauditignore` at the repo root. Read that file yourself, because every rule in it hides something from the scan. List the rules in the report's method line, and flag any that hide a whole directory or a check without a stated reason.

- Dependency audits need network access. If the user is offline, pass `--offline` and mark D5 `not-verified` unless a lockfile review covers it.
- C5 uses `gitleaks` when installed (history included), otherwise a pattern scan of the working tree only. The report must say which ran.
- Read the code behind every WARN before you call it a finding. Treat every FAIL as likely, and confirm it by reading before you report it.
- If any output shows a secret value, follow safety rule 2.

**First run, or a scan drowned in noise.** When no `.secauditignore` exists, run `python3 <SKILL_DIR>/scripts/setup.py ignores <repo>` after the scan.
- It groups the noise it found (test code, build output that does not ship, legacy trees) into suggested rules with hit counts and a reason each.
- `known` rules match patterns that are almost always noise. `review` rules could hide a real problem (for example a `wwwroot` folder that ships, or a legacy tree that still runs). Recommend a `review` rule only after you have checked the folder.
- Tracked secret-shaped files are never suggested.
- Show the list, say which rules you would accept and why, and ask once. Write the accepted rules with `--write --accept <numbers or known>`, then re-run the scan.
- Tell the user what the scanner skips by default. Dependency, cache, and test-run folders are never scanned (`node_modules`, `bin`, `obj`, `venv`, `vendor`, `test-results`, `playwright-report`, and similar), and the scan output reports how many tracked files that left out. Build folders (`dist`, `build`, `out`, `output`, `target`, `wwwroot`, `coverage`, and any folder ending in `-output`) are skipped only for files git does not track, so committed files stay in scope. D3 still looks inside build folders for source maps, because they can ship.
- On later runs, ask again only when a new noisy folder dominates the output.

Append `Step 2: scan <summary line>` to the ledger.

## Step 3: Audit

Walk every checklist item (skipping `CHECK_SKIP`) using the adapter's search patterns and the scan leads. For each item reach one status (`covered`, `partial`, `gap`, `n/a`, or `not-verified`) with evidence, following the rules at the top of `checklist.md`.

- **Small and medium repos:** do this inline.
- **Large repos** (several services, or more than about 300 source files in scope): dispatch `n2i-sec-category-auditor` (sonnet), one per category A, B, C, D, in parallel. Give each the category letter, the checklist path, the adapter path(s), the repo path, and the scan output. Reconcile their results yourself; severity calls stay with you. If the agent is missing, follow the agent fallback; with no subagents at all, audit the four categories yourself, one at a time.
- Read the code behind every claimed gap before you keep it. A false gap costs the team time.
- For a multi-tenant or multi-user system, spend the most effort on B1, B5, and B6. They hide the worst failures.
- Anything the checklist missed but you saw (a real weakness with no matching item) becomes `X1`, `X2`, … with a note on what item the checklist should gain.

Append `Step 3: audit complete (<n> covered, <n> gaps, <n> partial, <n> not-verified, <n> n/a)`.

## Step 4: Challenge

Reassurance is the risk. Before writing the report, dispatch `n2i-sec-skeptic` (sonnet) with every `covered` and `n/a` claim (ID, status, evidence cited). It tries to disprove each. Apply the result:

- `overturned`: change the status and rewrite the finding.
- `weakened`: downgrade to `partial` and state the gap.
- `holds`: keep it.

If the agent is missing, follow the agent fallback. With no subagents at all, do a lighter pass yourself on the claims that matter most (B1, B5, C3, C5, D5) and note in the report's method line that the independent challenge did not run.

## Step 5: Report

Load `<SKILL_DIR>/references/report-template.md`. Write the report to `<REPORT_DIR>/<YYYY-MM-DD>-security-review.md` (create the directory if needed; if a file with that name exists, ask before overwriting).

- The default report has: header, summary, **Already covered** (its own section, before the gaps), **Gaps and recommendations**, **Not verified**, **Open questions**, **Out of scope**. No plan, estimates, or tickets yet.
- Re-audit: add **Changes since last review** (closed, regressed, still open, new). List regressions first.
- Key every row by checklist ID. Include evidence for every row.
- Apply `stop-slop` rules to prose if that skill is installed. US English. No secret values.
- Check accepted risks in `ACCEPTED_RISKS` and list expired ones.

Append `Step 5: report <path>`. Tell the user the path and the headline: counts by status, and the top two or three findings. Do not commit; tell them the file is uncommitted.

## Step 6: Next step

After the findings, ask what the user wants. Do this even when `NEXT_STEP` is unset; skip only when it is `none`. Offer these, and wait:

1. **Add a phased plan** with estimates and recommendations. Load `references/estimating.md` and append the plan sections to the report.
2. **Draft tickets**, one per phase or architectural change, in product-facing prose. Show them in chat or in a file the user names. Do not file them.
3. **Hand off to `n2i-dev-cycle`** to build specific fixes. Name the items and the order. The fixes then follow that skill's own gate.
4. **Stop** with the report as is.

Never start a plan, ticket, branch, or fix on your own. "Looks urgent" is not approval. One answer can combine options (for example 1 then 3).

Append `Step 6: user chose <option>` to the ledger. When the user is done, archive the ledger to `.n2i-sec-audit/archive/progress.<date>.md`.

## Verify mode

`verify <ID or phase>`: confirm that named fixes landed.

1. Read the latest report. Resolve the IDs (a phase name maps to the IDs it lists).
2. For each ID, re-run the relevant scan and read the code. Demand fresh evidence: a command run now, a test result, a `file:line` that shows the control.
3. Report per ID: `verified`, `partially verified`, or `not fixed`, with evidence. Update statuses in the report only if the user asks, and list the change in "Changes since last review".
4. A fix is not verified by the claim that it was made. If a runtime check is needed and you cannot do it, say `not-verified` and what is needed.

## Cross-Cutting Mechanics

- **Model selection:** scanning on `haiku`, per-category auditing and the skeptic on `sonnet`. Severity judgment, the report, and the next-step conversation stay in the main agent.
- **Named agents:** `n2i-sec-scanner` (haiku), `n2i-sec-category-auditor` (sonnet), `n2i-sec-skeptic` (sonnet). All are read-only. Prefer them.
- **Agent fallback.** Check `AGENTS` in the Dynamic Context before you dispatch. When a named agent is missing, or a dispatch fails with an unknown agent type, work down this ladder and record which rung you used in the report's method line:
  1. Read `<SKILL_DIR>/agents/<name>.md`. Dispatch `general-purpose` with `model` set to the value in that file's frontmatter and the file's body as the prompt. Add this line to the prompt: "Read-only: do not create, edit, or delete any file, and do not run commands that change state." The `general-purpose` agent has write tools, and that line keeps it read-only. The scanner may still write `.n2i-sec-audit/last-scan.txt`.
  2. If that model is unavailable, use the adjacent tier, then omit `model`.
  3. If subagents are unavailable, do the work inline: run the scan and read its summary, audit the categories one at a time, and make the lighter challenge pass described in Step 4.
- **Ledger:** `.n2i-sec-audit/progress.md`, one line per step as it lands. On skill start, if the ledger names the same audit, resume at the first incomplete step. After compaction the ledger and the report outrank recollection.
- **Scheduling:** audits can run on a schedule (CI for the scan, a scheduled routine for the full audit). See the README. A scheduled run produces a draft report and stops at Step 5; it never starts Step 6 on its own.
- **Hand-off:** this skill finds and reports. `n2i-dev-cycle` builds. Keep the boundary.
- **Repo conventions win.** If the project's `CLAUDE.md` sets report location, naming, or tone, follow it.
