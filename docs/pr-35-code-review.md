# PR #35 Code Review Findings

PR: `fix(threat): stop behavioral-evasion & interpreter-obfuscation false positives`

Review status: **Not ready to merge**

The state-machine fix is internally consistent, and the standard test and lint
checks pass. However, end-to-end probes found three security regressions in the
new payload parser and one false positive in heredoc classification.

## P1: Command runners bypass interpreter detection

Affected code:
[`src/block/evasion.rs:472`](../src/block/evasion.rs#L472)

`collect_payloads_from_segment` resolves only the first effective command. If
that command is not a shell or interpreter, payload collection returns early.
The finite wrapper list does not include many commands that execute another
program.

The following commands are allowed:

```bash
strace python3 -c "import os; os.system(chr(108)+chr(115))"
taskset -c 0 python3 -c "import os; os.system(chr(108)+chr(115))"
watch -n 1 python3 -c "import os; os.system(chr(108)+chr(115))"
```

The previous unanchored detector recognized the nested interpreter invocation.
With the policy backstop removed, the commands now reach an `allow` decision.

Recommendation: preserve interpreter detection through command runners without
depending exclusively on a finite wrapper list, and add end-to-end regression
tests for multiple runner shapes.

## P1: Inline interpreters inside shell heredocs are not recursively parsed

Affected code:
[`src/block/evasion.rs:450`](../src/block/evasion.rs#L450)

Executable heredoc bodies are added as `PayloadKind::Script`, but shell heredoc
bodies are not recursively parsed as shell commands. As a result, nested
interpreter one-liners never become `PayloadKind::Inline`.

The following command is allowed:

```bash
bash <<'SH'
python3 -c "import os; os.system(chr(108)+chr(115))"
SH
```

Signals such as `chr` and `os.system` are checked only for inline payloads, so
the outer script classification hides the nested inline command. The previous
detector caught this command.

Recommendation: recursively parse heredoc bodies consumed by a shell while
retaining script-level classification for heredocs consumed directly by
interpreters.

## P1: Command-substitution parsing terminates on quoted parentheses

Affected code:
[`src/block/evasion.rs:1450`](../src/block/evasion.rs#L1450)

`read_substitution` changes nesting depth for every parenthesis without tracking
shell quotes or escapes. A `)` inside a quoted string therefore terminates the
captured substitution early.

The following valid command is allowed:

```bash
echo "$(printf ')'; python3 -c 'import os; os.system(chr(108)+chr(115))')"
```

The executable Python command falls outside the truncated substitution captured
by the parser. The previous detector caught the interpreter invocation.

Recommendation: make substitution parsing quote-aware and escape-aware, then
add coverage for parentheses inside single quotes, double quotes, and nested
substitutions.

## P2: `xargs` heredoc data is classified as executable code

Affected code:
[`src/block/evasion.rs:738`](../src/block/evasion.rs#L738)

`xargs` consumes standard input as argument data. Treating it as a transparent
wrapper causes the parser to classify the effective command as the heredoc
consumer instead.

The following command incorrectly produces an approval prompt:

```bash
xargs bash <<'EOF'
note: use the b64decode helper
EOF
```

The heredoc is input data for `xargs`, not a Bash script. This recreates the
false-positive class the PR is intended to fix.

Recommendation: model wrappers that consume standard input separately from
transparent command runners, and add a regression test proving that signal
words in `xargs` input remain data.

## Validation

The following checks pass on the reviewed branch:

- GitHub Build & test
- GitHub Clippy
- GitHub Rustfmt
- `cargo test --locked --all-targets --all-features`
- `cargo clippy --locked --all-targets --all-features -- -D warnings`
- `cargo fmt --all --check`
- `git diff --check origin/main...HEAD`

The full local test suite was run with `RAILGUARD_HOME` redirected to a writable
temporary directory.

## Merge recommendation

Fix the three P1 detector regressions and add end-to-end coverage for their
reproduction cases before merging. The P2 heredoc false positive should be
addressed in the same parser revision because it conflicts directly with the
PR's stated goal.
