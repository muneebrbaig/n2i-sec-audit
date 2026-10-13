# Bundle the skill into a project

Bundle the skill when a team repo should carry it, so engineers never pull it by hand. The skill repo stays the single source of truth. The project holds a git submodule that points at it, and a SessionStart hook keeps it current.

This works the same way as [n2i-dev-cycle](https://github.com/muneebrbaig/n2i-dev-cycle). If that skill is already bundled, you need steps 1, 4, and 5, plus the hook in step 2. The hook template here handles every `n2i-*` skill, so it replaces an older single-skill copy.

For a single-user install, follow the Install section in the README.

## How it works

- The skill is a git submodule at `.claude/skills/n2i-sec-audit`, cloned over HTTPS. Anyone can clone it while the repo is public, with no SSH keys or credentials.
- One hook script in the project, `.claude/hooks/sync-n2i-skill.sh`, runs at the start of every Claude Code session. It:
  - initializes each `.claude/skills/n2i-*` submodule, so a fresh clone needs no `--recurse-submodules`;
  - pulls the tip of `main` at most once a week per clone;
  - links each skill's subagents from `agents/` into the project's `.claude/agents/`, and removes links whose target is gone.
- The hook prints nothing and always exits 0, so an offline machine or a failed fetch never blocks a session. It retries on the next one.
- The hook lives in the project because it has to exist before the submodule does. Copy `scripts/project-sync.sh` from this repo as the starting point.

## Setup

Run these from the project root. A person reviews and commits the result. Agents must not commit or push.

1. Add the submodule and stop git from showing pointer drift:

   ```bash
   git submodule add -b main https://github.com/muneebrbaig/n2i-sec-audit.git .claude/skills/n2i-sec-audit
   git config -f .gitmodules submodule..claude/skills/n2i-sec-audit.ignore all
   ```

2. Copy the hook template into the project. This replaces any older single-skill copy:

   ```bash
   mkdir -p .claude/hooks
   cp .claude/skills/n2i-sec-audit/scripts/project-sync.sh .claude/hooks/sync-n2i-skill.sh
   chmod +x .claude/hooks/sync-n2i-skill.sh
   ```

3. Register the hook in the project's `.claude/settings.json` if it is not there yet. Merge it into any existing `hooks` object:

   ```json
   {
     "hooks": {
       "SessionStart": [
         {
           "hooks": [
             {
               "type": "command",
               "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/sync-n2i-skill.sh"
             }
           ]
         }
       ]
     }
   }
   ```

4. Add the generated agent links and the skill's local state to the project's `.gitignore`:

   ```text
   .claude/agents/n2i-*.md
   .n2i-sec-audit/
   ```

5. Commit `.gitmodules`, the submodule entry, the hook script, `settings.json`, and `.gitignore`. Restart Claude Code in the project. The first session finishes the setup. If the agents do not appear, restart once more, because Claude Code loads agents at session start.

Notes:
- If the project gitignores `.claude/skills/`, remove that rule for this path so git can track the submodule.
- The scripts use bash. On Windows, run them in WSL or Git Bash.

## How updates reach people

- A change pushed to `main` reaches every engineer within about a week.
- To pick one up sooner, delete `.git/n2i-skill-synced` in your clone and start a new Claude session.
- Nothing pins a version. A project that wants a gate can track a release tag instead of `main`.
