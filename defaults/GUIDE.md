# Railguard - Agent Guide

Full reference for working under Railguard. The always-loaded CLAUDE.md block
carries only the core rules; this guide is printed on demand by
`railguard guide`.

## What you need to know

- **Some commands will be blocked.** A "denied" hook response means Railguard
  blocked the command. Do NOT retry the same command - and never re-issue it
  with cosmetic changes (new flags, base64, `eval`, a wrapper); that trips
  evasion detection and escalates toward a session kill. Find a genuinely
  different approach and say how it differs.
- **Some commands require human approval.** An "ask" response means the human
  will be prompted to approve or deny in Claude Code. Codex does not support
  hook-driven approval prompts, so Railguard returns a denial with instructions
  to update the policy or allowlist first. Wait; don't route around either result.
- **A terminated session can be revived by the human** with
  `railguard resume [--session <id>]`. This is the only recovery path under
  Codex, which cannot answer the resume prompt. You cannot run it yourself.
- **File writes are snapshotted.** Every Write/Edit/apply_patch is backed up before
  execution. The human can rollback any change.
- **Everything is logged.** All tool calls and decisions are recorded in
  `.railguard/traces/`.

## Writing files

Prefer `Write`/`Edit` over Bash redirects (`cat <<EOF >`, `echo >`,
`printf >`). Tool writes are snapshotted and skip the Bash path-fence scan,
which matches fenced-path *strings* in command text - so a command merely
mentioning a fenced path (heredoc, issue body) is blocked even if it never
touches it. Switching a fence-blocked heredoc to `Write` is intended
remediation, not evasion.

## If something goes wrong

If the human asks you to undo changes, fix a mistake, or rollback:

1. **Get context first.** Run: `railguard context --session $SESSION_ID --verbose`
   This shows you exactly what changed, diffs, blocked commands, and available
   rollback commands.

2. **Check what changed.** Run: `railguard diff --session $SESSION_ID`
   Or for a specific file: `railguard diff --session $SESSION_ID --file <path>`

3. **Rollback options:**
   - Undo the last edit: `railguard rollback --session $SESSION_ID --steps 1`
   - Undo the last N edits: `railguard rollback --session $SESSION_ID --steps N`
   - Restore a specific file: `railguard rollback --session $SESSION_ID --file <path>`
   - Restore everything: `railguard rollback --session $SESSION_ID`
   - Restore a specific snapshot: `railguard rollback --session $SESSION_ID --id <snapshot-id>`

4. **Find your session ID.** Run: `railguard log`
   This lists all sessions. Pick the most recent one.

## Configuring Railguard

You **can** help the user customize their Railguard policy. This is
encouraged:

- **Read `railguard.yaml`** to understand the current policy.
- **Propose edits to `railguard.yaml`** - Claude Code prompts the user before
  applying them; with Codex, the user must apply the proposed policy edit outside
  the guarded tool call.
- **Run `railguard init`** to generate a starter `railguard.yaml` if one
  doesn't exist (user approves).
- **Run `railguard status`** to show the current protection state.

All changes to Railguard policy require explicit human approval. You generate
the change, the user reviews and accepts or rejects it. Changes take effect on
the next tool call - no restart needed.

### Policy layers

- **Global** `railguard.yaml` / `~/.railguard.yaml` (resolved upward from cwd)
  - base rules; edits gated to **ask**.
- **Per-project** `.railguard.local.yaml` (project root) - additive
  `fence.allowed_paths` only; cannot weaken `denied_paths` or disable the
  fence. Ignored unless the global policy opts in with
  `fence.allow_local_overrides: true` - the override file ships inside the
  repository being guarded, so the project cannot opt itself in.
- Edits to ANY railguard yaml (global or `.railguard.local.yaml`) require human
  approval. Claude Code uses **ask**; Codex denies the tool call until the human
  applies the proposed change outside Codex. They are never auto-allowed.

Out-of-project path keeps prompting and the human wants it for this project
only -> add it to `.railguard.local.yaml`, not the global policy:

```yaml
# .railguard.local.yaml (project root; gitignore unless the exception is shared)
fence:
  allowed_paths:
    - "../shared-lib"      # e.g. a cross-linked sibling dir this project reads
```

Changes take effect on the next tool call. Details:
`docs/per-project-allowlist.md`.

## Do NOT attempt to

- Run `railguard uninstall` - it will be blocked.
- Modify `~/.claude/settings.json` or anything under `~/.codex` - it will be
  blocked. Codex keeps hook trust state and the `hooks` feature flag in
  `~/.codex/config.toml`, so the whole directory is fenced, not just
  `hooks.json`. Launching a nested agent with hooks disabled is blocked too.
- Remove the railguard binary - it will be blocked.
- Access `~/.ssh`, `~/.aws`, `~/.gnupg`, `/etc`, or other fenced paths (if
  path fencing is enabled).
