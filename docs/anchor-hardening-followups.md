# Stable-anchor hardening — follow-ups

Tracks items surfaced while implementing **#16** (anchor the path fence + policy
to a stable session project root) and during two adversarial review passes of
that change. Records what was fixed in the #16 PR and what is deliberately
deferred, with rationale, so the deferred work is not silently lost.

## Background

The #16 fix stopped re-deriving the "project directory" from each hook call's
`cwd`. It introduced a session anchor recoverable by `session_id` independent of
cwd: a global registry (`~/.railguard/sessions/<session_id>`) plus a precedence
resolver (`SessionState::resolve_project_root_with_source`):

1. cwd-walked local session state,
2. the global pointer,
3. the nearest `.git` ancestor of cwd,
4. cwd itself (untrustworthy fallback — never persisted).

Both the path fence (`fence_root`) and policy resolution consume this one
anchor, and snapshots are anchored to it too.

## Fixed in the #16 PR

- **Stable anchor + global pointer registry** — the core #16 fix.
- **`RAILGUARD_HOME` is debug-build-only** (`railguard_home`) — the env seam that
  redirects global state (traces/sessions/locks) for tests cannot relocate the
  audit log in an installed (release) binary.
- **Evidence-based anchor validation** (`is_valid_anchor`) — a trustworthy
  anchor must currently resolve to a real `.git` project. Rejects, with one
  check applied to every trustworthy tier: `/`, broad dirs (`/home`, `/tmp`,
  `/usr`), poisoned state/pointer values, and stale roots whose directory was
  moved or deleted.
- **Uniform "never persist an untrustworthy root"** — both `SessionStart`
  (`anchor_to_persist`) and the PreToolUse back-fill gate persistence on the
  same trustworthiness check, so a non-repo launch dir (`~`, `/tmp`) never
  becomes the sticky anchor.
- **Pointer mtime refresh** — the pointer is rewritten on every trustworthy
  call, so a long-running (>24h) session's anchor is never reaped by
  `cleanup_old_pointers`.
- **Snapshots anchored to `fence_root`** — Write/Edit backups land under the
  project root (where `railguard rollback` reads them), not a drifted cwd.
- **`lock_dir()` routed through `railguard_home()`** — the seam now covers
  traces, sessions, and locks consistently.

## Deferred

### 1. Anchor provenance / integrity — `→ new issue`

**Severity: medium-high (guardrail weakening, gated by preconditions).**

The anchor's trust model rests on data a monitored agent can influence:

- A session with **no SessionStart** (resume/fork, or a harness that only fires
  PreToolUse) whose first call is inside an unrelated **sibling git repo** B
  anchors to B and persists it — the real project A's `allowed_paths`/policy are
  replaced for the session (`pre_tool` GitAncestor → trustworthy → persisted).
- A **forged `.git`** (`mkdir -p /tmp/x/.git`) passes `is_valid_anchor`, so an
  agent-controlled scratch dir can become the anchor — and the anchor also
  drives policy loading, so an agent-authored `railguard.yaml` at that root is
  loaded (it can even set `fence.enabled: false`).
- The global pointer is plaintext in a non-fenced dir; the local state file is
  in-project and agent-writable. Poisoning them with a path that **is** a real
  repo passes validation (the `.git`-evidence check blocks only broad/non-repo
  roots, not an agent-created repo).

**Why deferred:** closing this needs anchor *provenance* (binding the persisted
anchor to a trusted writer / integrity-checking the pointer), a larger design
change than #16. Partially mitigated today: Claude Code resets cwd to the
project root each call (the agent can't easily steer first-call cwd), SessionStart
is authoritative when it fires, and `denied_paths` (`~/.ssh`, `/etc`,
`~/.claude/settings.json`, …) are checked first in `check_path` and so still
protect secrets regardless of a poisoned anchor.

### 2. Threat-state scatter on cwd drift — `→ tracked in #20`

**Severity: medium (evasion of behavioral detection, not the fence).**

`SessionState::locate_state_dir` finds the state file by walking **up from the
per-call cwd**. When cwd drifts outside the project subtree, the walk misses the
project's state and a **fresh empty** `SessionState` is loaded, so the threat
accumulators (`block_history`, `warning_count`, `heightened_until_call`,
`terminated`) read as empty. Consequences: Tier-3 retry-after-block detection,
Tier-2 escalation, and the session-termination resume-gate can be bypassed by
`cd`-ing outside the project before retrying. State is also written back to the
drifted dir, scattering stale `<sid>.json` files.

This is **pre-existing** (`locate_state_dir` predates #16) and is exactly the
root cause of **#20** ("Threat-state dir anchors to per-call cwd + ancestor
`.git`"). #16 fixed the *fence* half of cwd drift; #20 should route
`locate_state_dir` through the same stable anchor (`resolve_project_root` /
global pointer) that #16 introduced.

## Notes

- `HANDOFF-16.md` is a scratch handoff doc — delete it before the #16 PR merges.
