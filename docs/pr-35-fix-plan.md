# PR #35 Fix Plan

**Status: all four findings fixed** in `2bf7b5c`, `f129584`, `af97821`,
`1b97471`, then six defects in those fixes corrected in `d32dbf1`, `fae2e97`,
`0fd2b4e`. See [Outcome](#outcome) for the post-fix differential replay and
[Review round](#review-round) for what the review of the fixes turned up.

Companion to [`pr-35-code-review.md`](pr-35-code-review.md). All four findings
were reproduced end-to-end through the `PreToolUse` hook on
`fix/18-detector-false-positives` (`284f763`) and cross-checked against
`origin/main`. Every one is a real regression introduced by this branch, not a
pre-existing gap.

## Verification results

Each case was replayed as a real hook invocation (`railguard hook --event
PreToolUse` with a Bash `tool_input`, `RAILGUARD_HOME` pointed at a throwaway
project root with an empty blocklist), so the decision below is what Claude Code
would act on. `allow` means railguard suppresses Claude Code's own permission
prompt, so an allowed obfuscated payload runs unattended.

| Case | `origin/main` | HEAD | Verdict |
| --- | --- | --- | --- |
| `strace python3 -c "…chr()…os.system…"` | ask | **allow** | finding confirmed |
| `taskset -c 0 python3 -c …` | ask | **allow** | finding confirmed |
| `watch -n 1 python3 -c …` | ask | **allow** | finding confirmed |
| `systemd-run --user python3 -c …` | ask | **allow** | new, same root cause |
| `bash <<'SH'` wrapping `python3 -c …` | ask | **allow** | finding confirmed |
| `sh <<'SH'` wrapping `python3 -c …` | ask | **allow** | new, same root cause |
| `echo "$(printf ')'; python3 -c …)"` | ask | **allow** | finding confirmed |
| `xargs bash <<'EOF'` with `b64decode` prose | allow | **ask** | false positive confirmed |
| `xargs bash <<< '…b64decode…'` | allow | **ask** | new, same root cause |
| bare `python3 -c …` (control) | ask | ask | detector baseline intact |

Two related behaviors are intentional and must stay as they are:

- `python3 <<'PY'` whose body uses `os.system`/`chr()` is allowed. Multi-line
  script bodies deliberately only match `STRONG_OBFUSCATION_SIGNALS`
  (issue #18). Do not "fix" this while fixing the nested-inline case below.
- `bash <<'EOF'` whose body mentions `b64decode` asks. A shell heredoc body is
  executable script text, so a strong signal there is legitimately suspicious.
  The `xargs` case differs only because `xargs` eats the heredoc as data.

The line references in the review doc are accurate: `evasion.rs:472`
(`resolve_effective_command` call), `:450` (heredoc payload loop), `:1450`
(`read_substitution`), `:738` (`heredoc_body_is_code`).

## Root cause

The branch replaced flat-regex scanning with a parser that scans only inside
resolved executable payloads. That is the right shape for issue #18, but the
parser **fails open** in three places and **fails closed** in one:

1. Payload collection returns early unless the segment's *effective* command
   resolves to a shell or interpreter, and `is_wrapper` is a finite allowlist.
   Any command that execs another program and is not on the list hides
   everything after it (P1a).
2. Heredoc bodies consumed by a shell are pushed as `PayloadKind::Script` but
   never re-parsed as shell text, so a nested one-liner never earns
   `PayloadKind::Inline` and never sees the inline signal set (P1b). The path
   extractor already recurses these bodies (`evasion.rs:617`); payload
   collection just never got the same line.
3. `read_substitution` counts parens with no quote or escape state, truncating a
   substitution at the first `)` inside a quoted string (P1c).
4. `xargs` is modeled as a transparent wrapper, so the heredoc it consumes is
   attributed to the wrapped command and classified as code (P2).

Fixes 1, 2 and 4 all live in the same classification path, and fix 3 is a
self-contained scanner change. All four should land in one parser revision.

## Fix 1: stop failing open on unknown command runners

Do **not** just grow `is_wrapper`. A finite runner list reproduces this bug on
the next tool (`flock`, `chroot`, `firejail`, `nsenter`, `perf stat`,
`gdb --args`, `runuser`, `ltrace`, …).

Add one shared helper next to `resolve_effective_command`:

```rust
/// Word indices to treat as command starts: the resolved effective command,
/// plus any later bare interpreter word when the effective command is not
/// itself an interpreter. An unrecognized runner (`strace`, `taskset`,
/// `systemd-run`) must not hide the interpreter it execs.
fn interpreter_word_indices(words: &[&str], eff_idx: usize) -> Vec<usize>
```

Then:

- `collect_payloads_from_segment` (`:457`): replace the early `return` with a
  loop over `interpreter_word_indices`, running the existing token walk once per
  index. Extract the walk body into a helper so both call sites share it.
- `heredoc_body_is_code` (`:738`): when the effective command is not a
  shell/interpreter, retry from the next interpreter index instead of returning
  `false`, so `strace bash <<'EOF'` still classifies stdin as code. The `xargs`
  guard from fix 4 must short-circuit **before** this retry, or the retry will
  re-find `bash` and undo it.
- `collect_paths_from_segment` (`:636`): same loop, for parity with issue #27.
  Without it, `strace python3 -c 'open("~/.ssh/id_ed25519")'` also escapes the
  path fence.

False-positive containment: matching is on whole shell words after quote
removal, so `git commit -m "python3 -c 'chr(1)'"` and `grep "python3 -c" .`
stay single data words and never match. A payload is still only flagged when its
own text carries obfuscation signals.

## Fix 2: recurse shell heredoc bodies

In `collect_interpreter_payloads` (`:450`), keep the `PayloadKind::Script` push
and add the recursion the path extractor already does:

```rust
if heredoc.body_is_code {
    payloads.push((PayloadKind::Script, heredoc.body.clone()));
    collect_interpreter_payloads(&heredoc.body, depth + 1, payloads);
}
```

`MAX_EXTRACT_DEPTH` already bounds recursion. No new field on `Heredoc` is
needed: recursing an interpreter body (rather than only shell bodies) costs
nothing, since Python/Node source does not tokenize into interpreter
invocations, and it keeps this function symmetric with `extract_paths_inner`.

Accepted tradeoff: a multi-line script that itself contains an obfuscated
one-liner now prompts. That is the intended reading of "inline shape is
suspicious regardless of nesting depth" and is the only way P1b closes.

## Fix 3: make `read_substitution` quote and escape aware

Rewrite the scan at `:1450` to carry `in_single` / `in_double` / escape state
and only adjust depth on parens outside single quotes, mirroring the main
tokenizer's quote handling. Unquoted `$(...)` is unaffected: it is split by the
`(` / `)` operator path, which already treats a quoted `)` as a word.

Cover with unit tests in the `tests` module of `evasion.rs`: `)` inside single
quotes, inside double quotes, escaped `\)`, and a nested `$( … $( … ) … )`.

## Fix 4: model `xargs` as a stdin consumer

`xargs` reads stdin itself and passes the wrapped command arguments, never
stdin. In `heredoc_body_is_code` (`:738`), before classification:

```rust
if words[..=eff_idx]
    .iter()
    .any(|word| command_basename(word) == "xargs")
{
    return false;
}
```

Keep `xargs` in `is_wrapper`: path extraction (`xargs rm /etc/x`) and inline
payload collection (`… | xargs bash -c 'code'`) both still need to resolve
through it. Only the stdin classification changes. This covers the herestring
variant in the same edit, since `<<<` gating also routes through
`heredoc_body_is_code` (`:494`).

## Tests

End-to-end hook tests in `tests/threat_detection.rs`, matching the existing
`simulate_hook` style (that is the layer where all four bugs are observable;
unit tests on `is_interpreter_obfuscation` alone would have missed none of them
but prove less):

Must ask:

- `strace`, `taskset`, `watch`, `systemd-run`, `flock` each wrapping an
  obfuscated `python3 -c` one-liner (five runner shapes, one per bug class).
- `strace bash <<'EOF'` with a `b64decode` body (runner plus stdin
  classification).
- `bash <<'SH'` and `sh <<'SH'` wrapping an obfuscated one-liner.
- `echo "$(printf ')'; python3 -c …)"` and the escaped-paren variant.

Must allow (false-positive guards, these are the point of the PR):

- `xargs bash <<'EOF'` and `xargs bash <<< …` carrying signal words as data.
- The existing issue #18 corpus in `threat_detection.rs` and
  `path_fence_false_positives.rs` must not change decision. Re-run both in full
  after fix 1 and fix 2, which are the two that widen detection.

## Verification

1. `cargo test --locked --all-targets --all-features`
2. `cargo clippy --locked --all-targets --all-features -- -D warnings`
3. `cargo fmt --all --check`
4. Replay the ten-case table above against the rebuilt binary and against a
   `origin/main` worktree build. Every P1 row must read `ask` on both, and both
   `xargs` rows must read `allow` on both. This differential replay is what
   caught the regressions; it is the check that proves them closed.

## Outcome

Landed in the planned order, one commit per fix:

| Commit | Fix |
| --- | --- |
| `2bf7b5c` | `xargs` stdin is argument data (P2, plus the here-string variant) |
| `f129584` | quote- and escape-aware `read_substitution` (P1c) |
| `af97821` | heredoc script bodies re-parsed as commands (P1b) |
| `1b97471` | interpreters resolved past unrecognized runners (P1a) |

One deviation from the plan: for path extraction, fix 1 recurses only the nested
interpreter's `-c` payload rather than re-running the whole operand walk from
the nested index. Re-running it would have re-read the runner's own operands as
path candidates, which can invent a fence violation out of a `git -m` value.
The narrower loop closes the same gap
(`strace python3 -c "open('/etc/shadow')"` now reaches the fence) without that
side effect.

Post-fix differential replay, every case decided by both the `origin/main`
binary and the fixed branch:

- All eleven must-ask rows ask on both, including the five runner shapes
  (`strace`, `taskset`, `watch`, `systemd-run`, `flock`), `bash`/`sh` heredocs
  nesting a one-liner, `strace bash <<'SH'`, and the quoted-paren substitution.
- All twenty must-allow rows allow on the fixed branch: both `xargs` data
  shapes, clean `python3`/`bash` heredocs, and a corpus of everyday commands
  (`cargo test`, `strace ./target/debug/railguard status`,
  `watch -n 5 git status`, `find … | xargs rm -f`, `git ls-files | xargs grep -l
  python3`, `sed 's/foo(1)/bar(2)/g'`, `env`/`nice`/`timeout` wrappers).
- The only everyday row whose decision changed is
  `git commit -m "document python3 -c chr() usage and the b64decode helper"`:
  `main` asks, the branch allows. That is the false positive issue #18 exists to
  remove, not a regression.

Checks on the fixed branch: `cargo test --locked --all-targets` (343 passing,
19 new), `cargo clippy --locked --all-targets --all-features -- -D warnings`
clean, `cargo fmt --all --check` clean, `git diff --check origin/main...HEAD`
clean.

## Review round

The four fixes were then reviewed twice: by hand against the diff, and by Codex
against the same commit range. Six defects surfaced, all reproduced end-to-end
before being fixed, all now covered by tests that fail when the fix is reverted.

Found reviewing the diff by hand:

| Defect | Fix |
| --- | --- |
| `xargs -a file` reads its item list from the file and leaves the child's stdin attached, so the heredoc there really is the wrapped script. The P2 fix hid it. | `d32dbf1` |
| The interpreter retry added for unknown runners also fired on filters, so `grep python3 <<'EOF' … EOF` over a blob containing `eval(` started prompting. | `d32dbf1` |
| Each command start re-walked the whole segment, so a segment with k interpreter words produced O(k²) payloads: a 5k-word command took 24.8s against 0.18s before, past the hook's 5s budget, where a timeout means the call is never adjudicated. | `fae2e97` |

Found by Codex:

| Defect | Fix |
| --- | --- |
| A trailing backslash in an unterminated substitution (`echo "$(foo\`) advanced the index past the end: the final slice panicked and the hook exited 101 without a decision. | `0fd2b4e` |
| `stdin_is_data_for` scanned raw leading words, so an option *value* sharing a filter's name (`env -u grep bash <<'EOF'`) was read as a data consumer and the script it ran stopped being classified as code. | `0fd2b4e` |
| A later interpreter word was promoted to a command start even after a command that only prints its arguments, so `printf '%s\n' python3 -c …` prompted. | `0fd2b4e` |

Codex's suggested remedy for the last one was to require a known runner before
promoting an operand. That was not taken: a runner allowlist is exactly the
finite list whose gaps produced P1a, and gating on it would reopen that bypass.
The fix instead names the commands that demonstrably do *not* execute their
arguments. Both new lists (`consumes_stdin_as_data`, `treats_arguments_as_data`)
are deliberately finite where `is_wrapper` may not be: an omission in these costs
a prompt, never a missed payload, which is the opposite polarity from a runner
list.

### Still open

`bash <(printf '%s' "…")` and `diff <(python3 -c '…') /dev/null` are allowed.
Process substitution is not parsed as an executable region at all: `<(` lexes as
a `<` redirection plus a `(` operator. `origin/main` asks on both, so this is a
regression this PR introduces, in the same class as P1a but in a separate code
path from the four findings. It is left for a follow-up rather than folded in
here.

Not a regression, for the record: `cat <<'EOF' … EOF | bash` is allowed on
`origin/main`, before these fixes, and after them. A heredoc consumed by a filter
and piped into a shell has never been classified as code.

## Suggested commit order

Independent changes, cheapest and lowest risk first, each verifiable on its own:

1. Fix 4 (`xargs` stdin) plus its two allow-tests.
2. Fix 3 (`read_substitution`) plus unit tests.
3. Fix 2 (heredoc recursion) plus nested-interpreter tests, then re-run the
   false-positive corpus.
4. Fix 1 (runner fail-open) plus runner tests and the path-extraction parity
   change, then re-run the false-positive corpus.
