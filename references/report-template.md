# Report template

Load when you write or update the report. The report is a team-shared document: it lives in the repo (default `docs/<date>-security-review.md`) and is committed by a person, never by the skill.

Writing rules: US English. Outcome first, plain sentences, no filler. Apply the `stop-slop` rules if that skill is installed. Never include a secret value, and never name a credential's contents. Say where it lives and what kind it is.

## Default output: findings only

The default report has no plan, no estimates, and no tickets. Those come only after the user chooses them (see "Next step" in `SKILL.md`). Sections, in order:

1. **Header**: title, date, status (Draft), scope, method.
2. **Summary**: three to six sentences. The overall posture, the two or three findings that matter most, and the counts by status.
3. **Already covered**: its own section, before the gaps. A table of items with status `covered`, what is in place, and the evidence (`file:line` or command). Include `n/a` items here with how the absence was confirmed.
4. **Gaps and recommendations**: a table of `gap` and `partial` items, most severe first.
5. **Not verified**: items that need runtime access, a deployed environment, or a decision. Say what is needed to verify each.
6. **Open questions**: decisions that belong to the owners (scope, timing, who can act).
7. **Out of scope**: what this review did not cover.

Optional sections, added only when the user asks:
- **Phased plan** (see `references/estimating.md`)
- **Effort summary**
- **Ticket drafts**

### Header block

```markdown
# Security Review

**Date:** YYYY-MM-DD
**Status:** Draft for review
**Scope:** <directories and stacks reviewed>
**Method:** Static read of the code plus <scan commands run>. Nothing was tested dynamically unless stated. Scanner: <gitleaks or fallback; history scanned or not>. Ignore rules: <rules from .secauditignore and --exclude, or none>.
**Skill:** n2i-sec-audit <version>
```

### Already covered table

```markdown
| ID | Item | What is in place | Evidence |
|---|---|---|---|
| A1 | SQL injection | All request-path queries are parameterized. | `src/db/query.ts:40` |
```

### Gaps table

```markdown
| ID | Item | Severity | Finding | Recommendation |
|---|---|---|---|---|
| C3 | Tokens in browser storage | High | The login response is saved to `localStorage`... | Keep the access token in memory... |
```

Use the checklist ID as the row key. A finding with no checklist item takes `X1`, `X2`, … and explains why the checklist missed it (propose the new item in the final message).

## Severity rubric

Severity is likelihood times impact for this product.

| Severity | Typical meaning |
|---|---|
| Critical | Exploitable now with little effort, and the impact is full compromise or cross-tenant data exposure. |
| High | Exploitable with moderate effort or one extra condition, with serious impact. |
| Medium | Needs a precondition, or the impact is limited. Worth scheduling. |
| Low | Hardening. Real but small. |
| Info | No action needed. Context for the reader. |

State the reasoning in one clause when a finding sits above or below its checklist default.

## Re-audit report

When a previous report exists, add a **Changes since last review** section before "Already covered":

```markdown
| ID | Previous | Now | Note |
|---|---|---|---|
| D5 | gap (High) | covered | Angular and Capacitor upgraded; `npm audit` clean. |
```

Statuses: `closed` (gap to covered), `regressed` (covered to gap/partial), `still open`, `new`, `unchanged`. List regressions first. Link the previous report by path and date.

## Accepted risks

If the user accepts a risk, record it in the shared accepted-risks file (`ACCEPTED_RISKS` in config, default `docs/security-accepted-risks.md`) with the item ID, who accepted it, the date, and a review-by date. Later audits list accepted items as `accepted` with the review-by date and flag any that have expired. Never mark a risk accepted on the user's behalf.
