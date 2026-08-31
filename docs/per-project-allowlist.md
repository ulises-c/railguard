# Per-project allowlist overrides

Tracked in [ulises-c/railguard#2](https://github.com/ulises-c/railguard/issues/2).

## Problem

The path fence allows writes inside the project directory (cwd) plus anything in
`fence.allowed_paths`; everything else prompts. The only place to add an
allowed path is the policy file that `find_policy_file` resolves by walking up
from cwd — in a typical setup a single global `~/.railguard.yaml`.

That is too coarse for a common case: working in one repo while an agent edits
files that live *outside* it and are specific to that one project. The concrete
motivating case is a software-testing notes vault on iCloud:

```
~/Library/Mobile Documents/iCloud~md~obsidian/<vault>/
```

Adding that path to the global policy works, but it is wrong in two ways:

- it is macOS-/vault-specific, yet pollutes a policy shared across every machine
  that consumes the same `~/.railguard.yaml`;
- it grants the exception everywhere, when it is wanted for exactly one project.

Dropping a full `railguard.yaml` into the project root doesn't help either: that
file *replaces* the resolved policy rather than extending it, so you'd have to
duplicate the whole global policy to add one path.

## How it works

A project may ship a dedicated, additive override file:

```
.railguard.local.yaml
```

It is **not** a full policy. It carries only `fence.allowed_paths`, and those
entries are appended to the effective policy's allowed list. Resolution order:

1. `load_policy_or_defaults(cwd)` resolves the base policy as before
   (`find_policy_file` walks up; falls back to built-in defaults).
2. `apply_local_overrides(cwd)` walks up for `.railguard.local.yaml` and, unless
   the base policy opted out, appends its `fence.allowed_paths` (de-duplicated).

The override file name is distinct from the `.railguard.yaml` full-policy file
that `find_policy_file` already recognizes, so the two never collide.

## Usage

1. Local overrides are enabled by default. To state that explicitly in your
   base (global) policy, for example `~/.railguard.yaml`:

   ```yaml
   fence:
     enabled: true
     allow_local_overrides: true
   ```

2. In the project that needs an exception, add `.railguard.local.yaml`:

   ```yaml
   fence:
     allowed_paths:
       - "~/Library/Mobile Documents/iCloud~md~obsidian"
   ```

3. The override is per-machine/per-checkout state — add it to the project's
   `.gitignore` unless you want to commit a shared exception.

If `allow_local_overrides` is not set, it defaults to `true`. Set it to `false`
in the trusted base policy to ignore `.railguard.local.yaml` files.

## Security model / reasoning

The fence exists to constrain an agent (including a prompt-injected one). A
per-project file that can widen access is therefore a deliberate trust decision,
designed with three guarantees:

- **Additive only.** The override can add `allowed_paths` and nothing else. It
  cannot remove or weaken `denied_paths`, change rules, or disable the fence.
- **Trusted-layer opt-out.** Overrides are honored by default. The
  human-controlled base policy can set `allow_local_overrides: false` when
  repositories must not widen access. Project overrides remain additive-only
  and cannot weaken denied paths.
- **Denies still win.** `check_path` evaluates `denied_paths` before
  `allowed_paths`, so even an opted-in override that lists `~/.ssh` or `/etc`
  cannot expose them — the deny fires first. (Covered by
  `test_local_override_cannot_weaken_denied_paths`.)

A malformed `.railguard.local.yaml` is warned about and ignored, never fatal.

## Implementation

- `src/types.rs` - `FenceConfig.allow_local_overrides: bool` defaults to `true`.
- `src/policy/loader.rs` — `find_local_override_file`, `apply_local_overrides`,
  and the `LocalOverride` parse struct (reads only `fence.allowed_paths`).
- `src/configure.rs` — emits the flag in the generated template for discoverability.
- Tests: enabled-by-default add, explicit opt-out, and deny precedence.

## Contribution workflow

Branch off `main`, implement and test, then open a PR against this repo.

```
git switch -c feat/per-project-allowlist main
# implement + test
git push -u origin feat/per-project-allowlist
gh pr create --repo ulises-c/railguard --base main --head feat/per-project-allowlist
```
