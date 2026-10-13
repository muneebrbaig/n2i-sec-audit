# Estimating and phasing

Load only when the user asks for a plan, phases, or estimates. The default audit report has none of this.

## Principles

- Estimates are **ranges of engineer-days** for one developer. They include tests and review. They exclude waiting on decisions, access, and deploy windows.
- Name the big unknowns instead of padding the range. A major framework upgrade or a token-flow rewrite has a wide range for a reason; say what drives it.
- Phase by risk reduced per day of work, then by dependency. A control that other work relies on (for example a cross-tenant test suite) comes before the work it protects.
- Group bounded changes into one phase. Give each architectural change (new subsystem, changed public contract) its own phase and its own design doc before code.
- Every phase has an **outcome** (what is true afterward, in plain terms) and a **done when** (something checkable).
- Call out compatibility constraints: installed clients that update on their own schedule, live customers, additive-only schema changes.

## Sizing guide

Starting points. Adjust for the codebase and say so.

| Work | Typical range |
|---|---|
| Rotate credentials, move secrets to a secret manager | 0.5 to 1 day per environment set (needs access) |
| Add security headers middleware, CSP in report-only | 1 to 2 days, plus an observation window |
| Enforce CSP | 0.5 day after the window |
| Default-deny authorization plus a route-policy test | 1 to 2 days |
| General rate limiter | 0.5 to 1 day |
| Log redaction plus a test | 0.5 to 1 day |
| Minor dependency updates | 0.5 to 1 day |
| Major framework or platform upgrade | 3 to 8 days (wide; depends on breakage) |
| Cross-tenant/ownership test suite over all routes | 3 to 5 days for a mid-size API |
| Global tenant filter plus fixes the suite finds | 2 to 4 days |
| RLS pilot on one table | 1 to 3 days; wider rollout is its own phase |
| Move tokens out of browser storage (cookie refresh, CSRF, hub/socket ticket) | 6 to 10 days, plus a compatibility window |
| TOTP MFA with recovery codes | 4 to 7 days |
| Consolidate duplicate token validators, pin algorithms | 1 to 3 days |
| Add dependency and secret scanning to CI | 0.5 to 1 day |

## Plan format

```markdown
### Phase N: <name> (<low> to <high> days)

**Outcome:** <what is true afterward>

- <ID>: <task>. (<estimate>, <driver of uncertainty if any>)

**Constraints:** <compatibility, live data, deploy windows>

**Done when:** <checkable statement>
```

Close with an effort table (phase, focus, estimate, total) and a recommended order that says what runs first and why.

## Ticket drafts

If the user asks for tickets, write one per phase (or per architectural change) in product-facing prose: problem, proposed direction, scope check (covered versus adjacent-but-excluded), out of scope. Link finding IDs. Do not file them; show the drafts and let the user decide where they go.
