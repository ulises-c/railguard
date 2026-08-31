# TODO — open issues by priority

Ranked 2026-07-12 from the open issues on `ulises-c/railguard`. Three axes: does it
silently weaken protection, does it fire on everyday work (false positives), and
effort-to-value. Update this file when issues close or priorities shift; the issue
threads hold the full detail.

## Tier 1 — fix now

- [ ] **#28 — clippy `invalid_regex` + warnings + fmt drift; make CI gating blocking.**
      Not just lint debt: the backreference regex never compiles, so
      `detect_variable_expansion` has silently never worked. Fix unblocks required
      clippy/fmt CI gates.
- [ ] **#18 — behavioral-evasion & interpreter-obfuscation false positives.**
      Fires on routine commands (`git add && git commit`, heredoc-to-python) and
      escalates toward session kills. FPs train users/agents to distrust the tool.
- [ ] **#25 — self-protection false positive on read-only / fake-home commands.**
      Hard-blocks any command *mentioning* `.claude/settings.json`, including
      `test -f` against a disposable `$HOME`.
- [ ] **#24 — glob entries in `fence.allowed_paths` never match.**
      Shipped default config contains dead entries (literal prefix compare, no glob
      expansion) → silent over-blocking. `glob` crate already a dependency.

## Tier 2 — real gaps, less urgent

- [ ] **#19 — `railguard init` defaults: GPG-dir deny breaks signed commits; stale repo URLs.**
      ~30-minute fix; batch with any Tier 1 PR.
- [ ] **#26 — path fence indirect-execution gaps (pipe-to-shell, deep nesting).**
      Genuine under-fencing, partially mitigated by the evasion tier. Wants the #27
      consolidation so the fix doesn't add a fourth duplicate detector.
- [ ] **#20 — threat-state dir anchors to per-call cwd → cross-project state bleed.**
      Latent production defect (tests worked around it in PR #15). Share the fix with
      the stable-session-root work from #16.
- [ ] **#21 — anchor provenance hardening (forged .git / sibling-repo hijack).**
      Real vectors but gated today (`denied_paths` checked first; SessionStart
      authoritative). Do after #20 — same anchoring machinery.

## Tier 3 — strategic / structural

- [ ] **#11 — release engineering: single-source version, CHANGELOG, release/update pipeline.**
      Version drift across 5 files; `railguard update` has nothing to fetch.
      Prerequisite for #9.
- [ ] **#30 — slim the injected CLAUDE.md block (partial import + on-demand reference).**
      Defines the core/reference tiering that #7 and #14 build on — land before them.
- [ ] **#7 — generate per-agent context files from one source of truth.**
      Right architecture for multi-agent support; simpler once #30 settles the tiers.
- [ ] **#14 — plugin mode ships hooks but no guidance (plugin skill).**
      Small once #7 exists — the skill becomes another generated target.
- [ ] **#27 — consolidate duplicated interpreter/assignment detection in `evasion.rs`.**
      Pure refactor; fold into #26 rather than standalone.
- [ ] **#9 — detach fork from abandoned upstream (self-publish + rename).**
      Deliberately deferred ("eventually, not yet"); blocked on #11 for a working
      release pipeline.

## Ordering judgment

The false-positive cluster (#18/#25/#24) ranks above the coverage-gap cluster
(#26/#21/#20): FPs fire on real sessions today and erode trust in the guardrail,
while the gaps are edge-case vectors with partial mitigations.
