# Stack adapter: generic fallback

Load when no other adapter matches the project, or alongside one when the project mixes stacks. The audit still runs. The report must say that judgment and generic search drove the checks, with no stack adapter behind them.

## Approach

1. **Find the entry points.** Locate the HTTP routing layer, background job triggers, message consumers, and any CLI that takes untrusted input. Find where authentication and authorization are decided.
2. **Find the data layer.** Locate how queries are built and which tenant or owner column scopes rows.
3. **Find the configuration.** Locate environment files, config loaders, secret sources, and anything served to browsers or shipped in mobile packages.
4. **Walk the checklist.** For each item in `references/checklist.md`, search for the technique's tell-tale API in this language. Use the language's own names for the same concept: "raw query", "html sink", "deserialize", "cors", "rate limit", "password hash", "jwt".
5. **Run `scripts/scan.py`.** It is stack-neutral for secrets, browser token storage, wildcard CORS, source maps, raw-SQL candidates, and dependency audits for npm, .NET, and Python.
6. **Record what you could not check.** Use `not-verified` with the reason. Do not guess.

## Writing a new adapter

Copy the shape of `dotnet-angular.md`: one line per checklist ID, naming the APIs, config keys, and file locations that matter for that stack. Keep it to patterns and questions to ask. Leave out code to copy. Add the file under `references/stacks/`, add its detection rule to the Dynamic Context in `SKILL.md`, and make sure every ID it mentions exists in the checklist (the tests check this).

Good adapters for other ecosystems would cover Java/Spring, Go, Ruby on Rails, PHP/Laravel, and mobile (Android/iOS) clients.
