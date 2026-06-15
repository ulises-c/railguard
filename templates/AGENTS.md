# Working Under Railguard

This project runs under [Railguard](https://github.com/railyard-dev/railguard), a
runtime guardrail that intercepts every agent tool call (Bash, Read, Write, Edit,
Memory) and decides — in under 2ms — to **allow**, **ask**, or **block** it. The
policy lives in `railguard.yaml`; the full default rule set is documented in
[`docs/RULES.md`](../docs/RULES.md).

This file tells you — the coding agent — how to work *with* the guardrails instead
of fighting them. Drop it into your project root (or merge it into your existing
`CLAUDE.md` / agent-instructions file). It pairs with the short
`# Railguard — Active Guardrails` block that `railguard install` injects
automatically.

## Reading Railguard's responses

- **allowed** — the call proceeds; you usually won't notice Railguard at all.
- **ask** — the human is prompted to approve or deny. Wait for their decision;
  don't try to route around it.
- **denied / blocked** — the call was refused. **Do not retry the same command.**
  Find a genuinely different, safer approach, or hand it back to the human.

## The cardinal rule: don't retry a blocked command

Railguard has behavioral-evasion detection. Re-issuing a blocked command with
cosmetic changes — new flags, reordered arguments, base64, `eval`, a wrapper
script — is treated as an evasion attempt and escalates. Repeated attempts can
kill the session outright.

- If a command is blocked because it is **genuinely dangerous** (`git push
  --force`, `rm -rf ~`, `terraform destroy`), do not reattempt it in any form.
  Choose a different strategy or ask the human.
- If you switch to a **legitimately different and safer operation** that happens
  to achieve a related goal — e.g. pushing a *new* branch instead of force-pushing
  an existing one — that is fine, but it may still trip the evasion heuristic
  because it immediately follows a block. **Explain to the human why the new
  approach is genuinely different and safe**, and let them approve.

## Working with the path fence

Railguard fences sensitive paths (`~/.ssh`, `~/.aws`, `~/.gnupg`, `/etc`, ...) and
confines file access to the project directory. The Bash fence scans command
**text**, so a command that merely *mentions* a fenced path — inside a heredoc, an
issue body, or install docs — is blocked even when it never touches that path.

- **Author file content with the Write/Edit tools, not shell redirects**
  (`cat <<EOF >`, `echo >`, `printf >`). Tool-based writes are snapshotted and
  their content is not scanned by the Bash fence.
- Don't embed fenced-path literals in Bash command text. If content must reference
  one, put it in a file via Write and pass it by path (`--body-file`, `--file`,
  stdin redirect).
- Switching from a fence-blocked heredoc to the Write tool is the **intended
  remediation — not evasion.** Do it without hesitation.
- If a command is blocked because it actually *accesses* a fenced path, don't
  retry it — find another approach or ask the human.

## Destructive and network commands need approval

Many commands are gated to **ask** the human rather than run automatically.
Expect a prompt and don't assume they'll go through:

- History/data loss — `git push --force`, `git reset --hard`, `git clean -f`,
  `rm -rf` on critical paths, `terraform destroy`, `DROP TABLE`
- Network/exfiltration — outbound `curl -X POST`, `wget`, `ssh` / `scp` / `rsync`,
  `env` / `printenv` dumps

Piped-shell execution (`curl | sh`), encoded payloads, and similar obfuscation
are **hard-blocked**, never just gated. See [`docs/RULES.md`](../docs/RULES.md)
for the complete catalog.

## Self-protection — don't touch Railguard itself

These are hard-blocked, and attempting them counts against you:

- `railguard uninstall`
- Editing `.claude/settings.json` or removing the railguard binary

Editing `railguard.yaml` is gated to **ask** — you *can* help tune policy: read it,
propose an edit (the human approves), or run `railguard configure`. Changes take
effect immediately, no restart needed.

## If something goes wrong (rollback)

Every Write/Edit is snapshotted, so changes are reversible. When the human asks
you to undo, fix a mistake, or roll back:

1. **Get context.** `railguard context --session $SESSION_ID --verbose` — shows
   what changed, diffs, blocked commands, and the available rollback commands.
2. **Review the diff.** `railguard diff --session $SESSION_ID` (or
   `--file <path>` for one file).
3. **Roll back.**
   - `railguard rollback --session $SESSION_ID --steps N` — undo the last N edits
   - `railguard rollback --session $SESSION_ID --file <path>` — restore one file
   - `railguard rollback --session $SESSION_ID` — restore everything
   - `railguard rollback --session $SESSION_ID --id <snapshot-id>` — restore a
     specific snapshot
4. **Find the session.** `railguard log` lists sessions if you need the id.
