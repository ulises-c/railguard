# Working Under Railguard

This project runs under [Railguard](https://github.com/railyard-dev/railguard), which intercepts every agent tool call (Bash, Read, Write, Edit, Memory) and decides — in under 2ms — to **allow**, **ask**, or **block** it. Policy lives in `railguard.yaml`; the full rule set is in [`docs/RULES.md`](../docs/RULES.md). Rollback recipes and the self-protection list live in the auto-managed `# Railguard — Active Guardrails` block of `CLAUDE.md`; this file covers how to *work* under it.

## Reading the response

- **allowed** — proceeds; you won't usually notice.
- **ask** — the human approves or denies. Wait for the decision; don't route around it.
- **blocked / denied** — refused. **Never retry the same command** — re-issuing it with cosmetic changes (new flags, base64, `eval`, a wrapper) trips behavioral-evasion detection and escalates toward a session kill. Find a genuinely different, safer approach, or ask the human. If the safer approach is legitimately different (e.g. pushing a *new* branch instead of force-pushing one), say so explicitly so the human can approve past any evasion flag.

## Rules it enforces

These are gated or hard-blocked by default. Don't burn turns hitting them — see [`docs/RULES.md`](../docs/RULES.md) for the complete catalog:

- **History/data loss (ask or block):** `git push --force`, `git reset --hard`, `git clean -f`, `rm -rf` on critical paths, `terraform destroy`, `DROP TABLE`.
- **Network/exfiltration (ask or block):** outbound `curl -X POST`, `wget`, `ssh`/`scp`/`rsync`, `env` dumps. Piped-shell execution (`curl | sh`) and encoded payloads are hard-blocked, never just gated.
- **Path fence:** sensitive paths (`~/.ssh`, `~/.aws`, `~/.gnupg`, `/etc`, ...) are denied, and file access is confined to the project directory.

## The path fence scans command text

The Bash fence matches fenced path **strings** in the command, so a command that merely *mentions* a fenced path — in a heredoc, an issue body, install docs — gets blocked even though it never touches that path.

- Author file content with the `Write`/`Edit` tools, not `cat <<EOF >`, `echo >`, or `printf >` redirects. Tool-based writes are snapshotted and their content is not scanned by the Bash fence.
- Don't embed fenced path literals in Bash command text. If content must reference them, put it in a file via `Write` and pass it by path (`--body-file`, `--file`, stdin redirect).
- Switching from a fence-blocked heredoc to the `Write` tool is the **intended remediation — not evasion.** Do it without hesitation.
- If a command is blocked because it actually *accesses* a fenced path, don't retry it in any form — find another approach or ask the human.

## Self-protection

Hard-blocked, and attempting them counts against you: `railguard uninstall`, editing `.claude/settings.json`, removing the railguard binary. Editing `railguard.yaml` is gated to **ask** — you *can* help tune policy: read it, propose an edit (the human approves), or run `railguard configure`. Changes take effect immediately, no restart needed.
