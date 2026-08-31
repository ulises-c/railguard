# Railguard Revamp Plan

Strategic plan for Railguard as an independent project, following the detach from
the abandoned `railyard-dev` upstream. This sits **above** [`docs/TODO.md`](TODO.md)
(which prioritizes the open bug/feature issues) and defines the identity,
distribution, and product direction.

**Decisions locked in (2026-07-12):**
- Keep the name `railguard` for now; a full rename comes later (Phase 4).
- Ambition: detach **and** strategically redirect — not just cleanup.
- Upstream owns both `crates.io/railguard` and `railguard.tech`. We route around
  both until the rename.

The central constraint: because upstream owns the `railguard` crate name,
`cargo install railguard` installs *their* stale build. Self-publishing under the
current name is impossible, so **the eventual rename is the unblock for crates.io
distribution**, not a cosmetic afterthought. Everything below is sequenced around
that fact.

---

## Phase 0 — Attribution & legal continuity ✅

- [x] `ATTRIBUTION.md` stating origin, fork point, and license continuity.
- [x] Add the maintainer's copyright line to `LICENSE` alongside the retained
      original notice (MIT requires keeping the original; we add, not replace).
- [x] Link `ATTRIBUTION.md` from `README.md` (one line near the license footer).

## Phase 1 — Detach identity (repoint everything off `railyard-dev`)

Fifteen-plus tracked files still hard-code the upstream org/domain. Repoint them
to `ulises-c` (interim home) and neutralize upstream-owned links.

- [ ] `railyard-dev` → `ulises-c` across: `Cargo.toml` (`repository`),
      `.claude-plugin/plugin.json` (`author`, `homepage`, `repository`),
      `CONTRIBUTING.md`, `SECURITY.md`, `npm/package.json`, `defaults/railguard.yaml`,
      `railguard.yaml`, `src/configure.rs:405`, `templates/AGENTS.md`,
      `docs/per-project-allowlist.md`, and the README badge URLs.
- [ ] `railguard.tech` links (README header): replace with the repo URL or a new
      domain we control. Do **not** keep pointing users at upstream's domain.
- [ ] `.github/FUNDING.yml`: set to own sponsor handle or leave disabled — resolves
      the placeholder note already in the file.
- [ ] **Stale Discord links.** Three references to upstream's server
      (`discord.gg/MyaUZSus`): README badge, README contributing footer, and
      `CONTRIBUTING.md`. Replace with our own invite or remove until we have one —
      do not keep pointing contributors at upstream's community.
- [ ] `README.md` badges: the crates.io version badge and stars badge currently
      reflect upstream. Point stars at this repo; drop/replace the crates.io badge
      until we publish under a new name (Phase 4).
- [ ] Fix `cargo install railguard` in `README.md` — it currently installs
      upstream. Replace with `cargo install --git https://github.com/ulises-c/railguard`
      or the local/npm path until the rename.
- [ ] **Cleanup:** remove the 154 committed stale-state files in `.railroad/` (136)
      and `.railyard/` (18) — leftover session snapshots from earlier state-dir
      names — and add both to `.gitignore` (only `.railguard/` is ignored today).

## Phase 2 — Ship independently under the current name

Get to a trustworthy, installable build *before* the rename, working around the
name collision.

- [ ] **#11 — single-source the version.** Version is duplicated across `Cargo.toml`,
      `plugin.json`, `npm/package.json`, and hard-coded strings; drift is already
      visible. Derive all from `Cargo.toml` (build script / generated constant).
      Prerequisite for any real release pipeline.
- [ ] Interim distribution: document and test `cargo install --git`, the
      `railguard install local` path (build from checkout), and the npm shim.
      Fix `npm/bin/railroad` — it still prints "railyard binary not found".
- [ ] Release engineering: tag → GitHub Release with prebuilt binaries; make
      `railguard update` actually fetch from this repo's releases.
- [ ] CHANGELOG: open a fork-era section documenting the detach and rebrand.

## Phase 3 — Restore trust in the guardrail (Tier-1 correctness)

Strategic, not just bugfix: an untrusted guardrail is worse than none — false
positives train users and agents to route around it, and a silently broken
detector provides false assurance. These are the Tier-1 items from `docs/TODO.md`.

- [ ] **#28** — the `invalid_regex` backreference never compiles, so
      `detect_variable_expansion` has silently never worked. Fix, then make
      clippy/fmt CI gating blocking.
- [ ] **#18 / #25 / #24** — false-positive cluster (behavioral-evasion FPs,
      self-protection firing on read-only/fake-home commands, dead glob entries in
      `fence.allowed_paths` causing silent over-blocking).

## Phase 4 — The rename (unblocks self-publishing)

The strategic pivot. A new name gets us an ownable crate name, an ownable domain,
and a clean break from upstream's registry/web presence.

- [ ] Choose the new name; verify the crate name is free on crates.io and the
      domain is registerable **before** committing.
- [ ] Rename crate, both binaries (`railguard`, `railguard-shell`), and CLI.
- [ ] **State-dir migration with back-compat.** Existing users have `.railguard/`
      (project) and `~/.railguard/` (global traces) directories. The rename must
      detect and migrate/read the old locations so it doesn't silently orphan
      snapshots, locks, and trace history. This is the riskiest part of the rename.
- [ ] Update the injected `CLAUDE.md` guardrails block, `templates/AGENTS.md`, and
      all docs to the new name.
- [ ] Publish to crates.io under the new name; stand up the new domain; update
      install instructions to the now-working `cargo install <newname>`.

## Phase 5 — Strategic redirect (product direction)

Now that it's yours, define what Railguard *is* going forward rather than
inheriting upstream's scope by default.

- [ ] **Positioning:** the middle ground between manual approval and
      `--dangerously-skip-permissions`. Sharpen this — is the primary audience
      individual devs, teams, or CI/agent fleets? That choice drives everything.
- [ ] **Multi-agent / fleet story:** the coordination layer (per-session file
      locks, shared context) is a differentiator. Decide whether to invest here vs.
      keep it single-developer focused. Ties into TODO #7 (per-agent context) and
      #30 (slim injected context).
- [ ] **Config ergonomics vs. safety:** the FP cluster shows the current defaults
      are too aggressive. Decide the default posture (strict vs. balanced) and make
      it a first-class, documented choice rather than an implicit one.
- [ ] **Scope discipline:** dashboard/replay/rollback are broad. Confirm each still
      earns its place or split into optional features to keep the core lean.
- [ ] Write a short public roadmap / vision doc from the decisions above.

---

## Sequencing

```
Phase 0 ─ attribution/legal ... do now (small)
Phase 1 ─ detach identity ..... do now; unblocks an honest public repo
Phase 2 ─ ship independently .. #11 first (single-source version)
Phase 3 ─ restore trust ....... parallel-safe with Phase 2; #28 gates CI
Phase 4 ─ rename .............. gated on Phase 2 (release pipeline) + a chosen name
Phase 5 ─ strategic redirect .. ongoing; informs Phase 4 naming & scope
```

Phases 0–1 make the repo honest and self-consistent. Phase 2–3 make it
trustworthy and installable. Phase 4 removes the last dependency on upstream's
registry/domain. Phase 5 is the throughline that should shape naming and scope
choices in every earlier phase.
