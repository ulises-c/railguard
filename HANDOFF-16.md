# Handoff: Issue #16 — anchor the path fence to a stable session project root

> Scratch handoff doc for a fresh Claude Code session. **Delete this file before the PR merges.**
> Repo: `railguard` (fork `ulises-c/railguard`, upstream `railyard-dev/railguard`). Rust.
> Branch: `fix/16-stable-policy-anchor` (created off `main`). Issue: https://github.com/ulises-c/railguard/issues/16

## TL;DR — the issue's framing is half-wrong; here is the real bug

Issue #16 reports two symptoms:
1. Paths nested under an `allowed_paths` entry (e.g. `~/github/railguard` under `~/github`, or a `/tmp/...` scratch file under `/tmp`) still get a fence approval prompt.
2. The fence re-anchors its "project directory" from each call's cwd, so `cd` drift makes the repo root start prompting.

**Descendant matching is NOT broken.** `check_path` in `src/fence/path.rs:48-63` already prefix-matches via `path_starts_with` (`Path::starts_with`, path.rs:140-144), `~` is expanded consistently (path.rs:124-137), and canonicalization handles the macOS `/tmp`→`/private/tmp` symlink. Unit tests confirm descendant matching works.

**The real root cause:** the *entire policy* is re-resolved from the **per-call `input.cwd`** on every hook invocation, and silently falls back to **empty defaults** when that cwd is outside the project.

- `src/hook/handler.rs:28-29`: `let cwd = Path::new(&input.cwd); let policy = load_policy_or_defaults(cwd);` — policy loaded from the per-call cwd, every call.
- `src/policy/loader.rs:40-53` `load_policy_or_defaults`: calls `find_policy_file(cwd)` which walks **up** from cwd for `railguard.yaml`/`.railguard.yaml` (loader.rs:6-26). If cwd is outside the project tree (e.g. a tool running in `/tmp/claude-xxx/...`, or any dir from which the project's config isn't an ancestor), it finds nothing → returns `None` → falls back to `default_policy()`.
- `default_policy()`'s fence is `FenceConfig::default()` with `allowed_paths: vec![]` (`src/types.rs:166`).
- `apply_local_overrides` (loader.rs:51, 110-120) is **additive only** — it can't restore the project's global `allowed_paths` that were just dropped.
- Back in `check_path`, `allowed_paths.is_empty()` is now true, so it takes the **default branch** (path.rs:65-71) whose message is literally `"Path Fence: '<x>' is outside project directory '<cwd>'"` — exactly the message in the issue, and the reason `allowed_paths` "appears ignored."

So: **the fence anchor (`fence_root`) is already stable, but the policy that feeds the fence is not.** Fix the policy resolution and both reported symptoms go away.

## What IS already stable (don't re-do)

- The fence root passed to `check_path` is `fence_root` = `state.project_root`, captured once and reused via `get_or_insert_with` (`src/hook/pre_tool.rs:44-49`); set at SessionStart (`src/hook/session.rs:21-24`). See `SessionState::find_project_root` / `locate_state_dir` in `src/threat/state.rs:74-101`.
- `cd <dir> && <cmd>` handling and the read-only-command waiver are fine (`pre_tool.rs` ~250-370 and `is_read_only_command` ~541-581).

## Proposed fix (direction — confirm before deep implementation)

Resolve the policy from the **session's stable project root**, not the per-call cwd, so config doesn't evaporate when the tool runs outside the project.

Two viable approaches:

- **A. Anchor policy lookup at the captured project root.** Load state first (it holds `project_root`), then call `load_policy_or_defaults(project_root)` instead of `load_policy_or_defaults(input.cwd)`. Smallest change, reuses the existing anchor. Wrinkle: `handler.rs` currently loads policy *before* dispatch/state-load; you'd reorder so the session project root is known first (it's per-session; SessionStart already persists it). For PreToolUse, `pre_tool.rs` already computes `fence_root` — thread that into policy resolution, or resolve policy inside the handler after reading `state.project_root`.
- **B. Cache the resolved policy (or its file path) in session state at SessionStart** and reuse it for the session. More robust against any cwd drift, but adds policy (or path) serialization to `SessionState` and a staleness question if the user edits `railguard.yaml` mid-session.

Recommendation: **A** (anchor lookup at the project root) — minimal, and it makes the policy and the fence agree on one root. Keep `find_policy_file`'s walk-up, just start it from the project root. Preserve the existing "no SessionStart → first PreToolUse anchors" fallback.

Coordinate with **#20** (threat-state dir escapes via `find_project_root`/`locate_state_dir` ancestor `.git`): same "stable session project root" theme. Whatever anchor mechanism this PR lands, #20 should consume it. See #20's comment thread for that plan.

## Implementation checklist

- [ ] Change policy resolution to anchor at the session project root (approach A). Likely touches `src/hook/handler.rs` (and/or `src/hook/pre_tool.rs`, `src/policy/loader.rs`).
- [ ] Keep behavior identical when cwd == project root (no regression for the common case).
- [ ] Confirm `allowed_paths` descendant matching with a unit test in `src/fence/path.rs` (e.g. allowed `~/github`, target `~/github/railguard/foo` → Allow) — likely already passes; lock it in.
- [ ] Add an integration test (pattern: `tests/path_fence_false_positives.rs`) that runs a PreToolUse with `cwd` OUTSIDE the project while `railguard.yaml` lives at the project root, and asserts the project's `allowed_paths` still apply (no "outside project directory" prompt for a configured allowed path).
- [ ] Decide #16's second half: the issue also wants descendant matching "confirmed"; since it already works, the test above is the deliverable, not a code change.

## Verify / test commands

- Build: `cargo build`
- Fence unit tests: `cargo test --test path_fence_false_positives` and `cargo test fence` (lib unit tests in `src/fence/path.rs`).
- Full suite: `cargo test`.
- NOTE on test hygiene: PR #15 (branch `fix/hermetic-threat-state-tests`, may already be merged to `main` by the time you read this) made the integration suites hermetic (unique session ids + a `.git` marker per tempdir). If `main` already has it, rebase this branch onto `main`. If not, expect the pre-existing threat-state flakiness in unrelated suites; it does not affect fence tests.

## Key file:line map

| Concern | Location |
|---|---|
| Policy loaded from per-call cwd | `src/hook/handler.rs:28-29` |
| Walk-up policy search + default fallback | `src/policy/loader.rs:6-26`, `40-53` |
| Default fence has empty allowed_paths | `src/types.rs:162-178` (`allowed_paths: vec![]` at 166) |
| Local overrides are additive only | `src/policy/loader.rs:110-120` |
| Fence decision + branches/messages | `src/fence/path.rs:22-74` |
| Descendant matching (works) | `src/fence/path.rs:140-144`, `124-137`, `79-111` |
| Stable fence root (already captured) | `src/hook/pre_tool.rs:44-49`; `src/hook/session.rs:21-24` |
| Project-root / state-dir resolution | `src/threat/state.rs:74-101` |
