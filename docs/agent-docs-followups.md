# Agent-docs follow-ups

Low-severity findings from the `/code-review` of the agent-doc parity work
(`CLAUDE.md`, `defaults/CLAUDE.md`, `templates/AGENTS.md`, `defaults/railguard.yaml`).
None are correctness or security defects — every behavioral claim in those docs
was verified accurate against the implementation. These are precision and
consistency improvements to make later.

## 1. `.railguard.local.yaml` — "(project root)" is imprecise

The agent docs describe the override as living in "(project root)", but it is
resolved by **walking up** parent directories to the filesystem root —
`find_local_override_file` (`src/policy/loader.rs:72-84`) is identical to the
base-policy lookup. An override placed in a shared ancestor directory silently
widens `fence.allowed_paths` for every project beneath it. `SECURITY.md`
documents this as a known limitation; the agent surfaces flatten it to
"(project root)".

- As *placement guidance* ("put it at your project root") it's fine.
- As a statement of *where the file is read from* it's incomplete.
- Affected: `CLAUDE.md`, `defaults/CLAUDE.md`, `templates/AGENTS.md`.
- Fix: reword to note it's resolved by walking up from cwd (like the base
  policy), or add a one-clause caveat. One-word/one-clause change.

## 2. AGENTS.md omits the global `~/.railguard.yaml` location

`templates/AGENTS.md` names the global policy as only `railguard.yaml`, while
`CLAUDE.md` lists `railguard.yaml` / `~/.railguard.yaml`. A Codex/other agent
reading only AGENTS.md never learns the policy can live at the global
`~/.railguard.yaml` (which `find_policy_file` resolves via walk-up). Minor
parity gap between the two surfaces this work is meant to keep at parity.

- Also: neither surface mentions `railguard.yml`, which `find_policy_file`
  also accepts (`src/policy/loader.rs:13`). Pre-existing; low priority.
- Fix: add `~/.railguard.yaml` to the AGENTS.md global-policy mention.

## 3. Triple hand-duplication of the same guidance

The same guidance is hand-maintained across three files (`CLAUDE.md` and
`defaults/CLAUDE.md` are byte-identical, plus `templates/AGENTS.md`). Every
future edit must touch all surfaces or they drift.

- Already tracked in #7 (generate per-agent context files from one source of
  truth). Listed here only so the local follow-ups are in one place.
