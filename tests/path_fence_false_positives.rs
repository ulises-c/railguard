//! Path-fence false-positive tests.
//!
//! The fence's whole reason to exist is reducing prompt fatigue: if benign,
//! read-only commands keep triggering "approve?" prompts, the human learns to
//! rubber-stamp everything and the guardrail becomes noise. A false positive
//! here is therefore a real defect, not a cosmetic one.
//!
//! Every command below is benign — it reads/inspects, navigates, or merely
//! *mentions* path-shaped text (sed/awk regex addresses, jq operators, URLs,
//! arithmetic, paths quoted inside commit messages or heredoc prose) — and
//! must NOT be stopped by the path fence. None of them *accesses* a denied
//! path (`~/.ssh`, `/etc`, ...); a few mention one inside message data, which
//! is exactly the false positive of issue #17.
//!
//! The command runs with cwd == the policy/project dir, so any path the fence
//! flags is necessarily a spurious "outside project" extraction.

use std::io::Write;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use tempfile::TempDir;

fn railguard_binary() -> String {
    let mut path = std::env::current_dir().unwrap();
    path.push("target/debug/railguard");
    path.to_str().unwrap().to_string()
}

static SESSION_SEQ: AtomicU64 = AtomicU64::new(0);

/// A session id unique across tests, parallelism, and `cargo test` runs.
/// Threat state is keyed per session at `.railguard/state/{id}.json`; reusing
/// a literal id let suspicion/approvals bleed between tests and persist on disk.
fn unique_session_id() -> String {
    format!(
        "test-{}-{}",
        std::process::id(),
        SESSION_SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

fn create_policy_dir(yaml: &str) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    // Anchor the project root at the tempdir so threat state lands inside it
    // (and is dropped with the tempdir) instead of escaping up to a shared
    // ancestor — e.g. a stray `.git` above the system temp dir.
    std::fs::create_dir_all(dir.path().join(".git")).unwrap();
    std::fs::write(dir.path().join("railguard.yaml"), yaml).unwrap();
    dir
}

fn rg_home_for(input_json: &str) -> String {
    serde_json::from_str::<serde_json::Value>(input_json)
        .ok()
        .and_then(|v| v.get("cwd").and_then(|c| c.as_str()).map(String::from))
        .unwrap_or_else(|| ".".to_string())
}

fn simulate_hook(binary: &str, input_json: &str) -> String {
    let output = Command::new(binary)
        .arg("hook")
        .arg("--event")
        .arg("PreToolUse")
        .env("RAILGUARD_NO_KILL", "1")
        .env("RAILGUARD_HOME", rg_home_for(input_json))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(input_json.as_bytes()).ok();
            }
            child.wait_with_output()
        })
        .unwrap();
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn bash_input(cwd: &str, command: &str) -> String {
    serde_json::json!({
        "session_id": unique_session_id(),
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "tool_use_id": "fp-001"
    })
    .to_string()
}

/// True if the decision is a path-fence prompt/block (the false positive we hunt).
fn path_fenced(stdout: &str) -> bool {
    stdout.to_lowercase().contains("path fence")
}

/// Benign commands that must never trip the path fence. Grouped by the shape of
/// path-like text that historically caused a false positive.
const BENIGN: &[(&str, &str)] = &[
    // ── jq alternative operator (`a // b`) — the `//` reported as a path ──
    ("jq direct", r#"jq '.version // "0.0.0"' package.json"#),
    ("jq after cd", r#"cd sub && jq '.a // 0' data.json"#),
    // ── sed / awk regex addresses — `/fn`, `/struct`, `/^}/` look like paths ──
    ("sed address", r#"sed -n '/fn main/,/^}/p' src/lib.rs"#),
    (
        "sed after cd",
        r#"cd src && sed -n '/struct Config/p' lib.rs"#,
    ),
    ("sed substitution", r#"sed 's/foo/bar/g' notes.txt"#),
    (
        "awk regex + division",
        r#"awk '/^Total/ {print $2/$3}' report.txt"#,
    ),
    // ── arithmetic / ratios — division slashes ──
    ("arithmetic echo", r#"echo $((100 / 4))"#),
    ("ratio printf", r#"printf 'aspect %s\n' "16/9""#),
    // ── URLs ──
    ("curl url", r#"curl -s https://example.com/api/v1/status"#),
    ("git clone url after cd", r#"cd repo && git remote -v"#),
    // ── regex patterns mentioning slash tokens (no real target) ──
    (
        "grep slash pattern",
        r#"grep -nE '/api/v[0-9]+' routes.txt"#,
    ),
    ("rg slash pattern", r#"rg -n 'TODO//FIXME' src"#),
    // ── ordinary read-only inspection, with and without a cd prefix ──
    ("git log", r#"git log --oneline -5"#),
    ("git status after cd", r#"cd project && git status"#),
    ("find", r#"find . -name '*.rs'"#),
    ("ls after cd", r#"cd src && ls -la"#),
    ("cat relative", r#"cat README.md"#),
    // ── compound / piped read-only chains (every segment must be read-only) ──
    (
        "multi cd then sed",
        r#"cd a && cd b && sed -n '/fn /p' f.rs"#,
    ),
    (
        "piped read-only with jq",
        r#"cat data.json | jq '.x // empty' | sort"#,
    ),
    (
        "pushd grep popd",
        r#"pushd src && grep -rn '/v1/' . && popd"#,
    ),
    (
        "cd chain to awk",
        r#"cd src && awk -F/ '{print $2}' paths.txt"#,
    ),
    // ── issue #17: path-shaped text in data positions (never accessed) ──
    (
        "sed conflict markers",
        r#"sed -n '/<<<<<<< /,/>>>>>>> /p' file.rs"#,
    ),
    (
        "file url with variable",
        r#"curl -s file://$PWD/fixtures/data.json"#,
    ),
    (
        "commit msg mentions path",
        r#"git commit -m "docs: update ~/.claude/docs/RAILGUARD.md notes""#,
    ),
    (
        "commit msg slash token",
        r#"git commit -m "ran /verify and it passed""#,
    ),
    (
        "commit msg bare path",
        r#"git commit -m "~/.claude/docs/RAILGUARD.md""#,
    ),
    (
        "heredoc doc text",
        "cat <<EOF\nSee /verify and ~/.claude/docs for details\nEOF",
    ),
];

#[test]
fn benign_commands_are_not_path_fenced() {
    let dir = create_policy_dir("version: 1\nblocklist: []\n");
    let cwd = dir.path().to_str().unwrap();
    let binary = railguard_binary();

    let mut failures = Vec::new();
    for (label, cmd) in BENIGN {
        let stdout = simulate_hook(&binary, &bash_input(cwd, cmd));
        if path_fenced(&stdout) {
            failures.push(format!("  [{label}] `{cmd}`"));
        }
    }

    assert!(
        failures.is_empty(),
        "{} benign command(s) were path-fenced (prompt fatigue):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Issue #32, unmasked. The BENIGN corpus above already carries sed/awk regex
/// addresses, but every one of those pipelines is read-only end to end, so
/// `is_read_only_command` waives the prompt and the extraction bug stays
/// hidden. Pairing the same regexes with a non-read-only stage (`cargo test`)
/// removes the waiver, so these fail on the extraction itself.
const REGEX_OPERAND_BESIDE_WRITE_CAPABLE: &[(&str, &str)] = &[
    (
        "awk regex",
        r#"cargo test 2>&1 | awk '/test result/ {print $4}'"#,
    ),
    ("sed address", r#"cargo test | sed -n '/1000/p'"#),
    ("sed range", r#"cargo test | sed -n '/1000/,$p'"#),
    ("grep literal", r#"cargo test | grep -o '/1000'"#),
    ("rg pattern", r#"cargo build | rg '/etc/passwd'"#),
];

#[test]
fn regex_operands_beside_a_write_capable_stage_are_not_fenced() {
    let dir = create_policy_dir("version: 1\nblocklist: []\n");
    let cwd = dir.path().to_str().unwrap();
    let mut failures = Vec::new();

    for (label, cmd) in REGEX_OPERAND_BESIDE_WRITE_CAPABLE {
        let stdout = simulate_hook(&railguard_binary(), &bash_input(cwd, cmd));
        if path_fenced(&stdout) {
            failures.push(format!("  [{label}] `{cmd}`"));
        }
    }

    assert!(
        failures.is_empty(),
        "{} regex operand(s) were fenced as paths:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The flip side: the same tools naming a real file outside the project must
/// still be fenced. Only the program slot is exempt, never a path operand.
const REGEX_TOOL_REAL_PATH_OUTSIDE: &[(&str, &str)] = &[
    (
        "sed file operand outside",
        r#"cargo run | sed -n '/x/p' ~/outside/f.txt"#,
    ),
    (
        "awk file operand outside",
        r#"cargo run | awk '/x/{print}' ~/outside/f.txt"#,
    ),
    (
        "grep -f outside",
        r#"cargo run | grep -f ~/outside/patterns.txt data.txt"#,
    ),
];

#[test]
fn regex_tools_naming_real_outside_paths_are_still_fenced() {
    let dir = create_policy_dir("version: 1\nblocklist: []\n");
    let cwd = dir.path().to_str().unwrap();
    let mut leaks = Vec::new();

    for (label, cmd) in REGEX_TOOL_REAL_PATH_OUTSIDE {
        let stdout = simulate_hook(&railguard_binary(), &bash_input(cwd, cmd));
        if !path_fenced(&stdout) {
            leaks.push(format!("  [{label}] `{cmd}`"));
        }
    }

    assert!(
        leaks.is_empty(),
        "{} outside path(s) slipped past the fence:\n{}",
        leaks.len(),
        leaks.join("\n")
    );
}

/// The flip side of prompt fatigue: write-capable tools that name a path OUTSIDE
/// the project must still be fenced. `is_read_only_command` waives the prompt
/// only for tools that purely read; interpreters, compilers, VCS, package
/// managers, and `xargs` write as a normal mode of operation and cannot be
/// judged read-only from their leading token, so a leading `cd` into an outside
/// directory must not launder them past the fence. None of these reference a
/// denied path — they reference `~/...` outside the temp project, so the
/// expected decision is the OutsideProject approval prompt.
const WRITE_CAPABLE_OUTSIDE: &[(&str, &str)] = &[
    ("git -C outside", r#"git -C ~/other-repo log --oneline"#),
    (
        "cd outside then python",
        r#"cd ~/scratch && python build.py"#,
    ),
    ("node outside script", r#"node ~/outside/app.js"#),
    (
        "cargo manifest outside",
        r#"cargo build --manifest-path ~/other/Cargo.toml"#,
    ),
    ("npm prefix outside", r#"npm install --prefix ~/other/pkg"#),
    ("ruby outside script", r#"ruby ~/scratch/gen.rb"#),
    // issue #17: executable payloads and operands must still be fenced even
    // though word-level extraction skips quoted message data
    ("bash -c naming outside", r#"bash -c "touch ~/outside/x""#),
    ("cp to outside", r#"cp notes.txt ~/outside/x"#),
    ("redirect to outside", r#"echo x > ~/outside/x"#),
];

#[test]
fn write_capable_commands_outside_project_are_fenced() {
    let dir = create_policy_dir("version: 1\nblocklist: []\n");
    let cwd = dir.path().to_str().unwrap();
    let binary = railguard_binary();

    let mut leaks = Vec::new();
    for (label, cmd) in WRITE_CAPABLE_OUTSIDE {
        let stdout = simulate_hook(&binary, &bash_input(cwd, cmd));
        if !path_fenced(&stdout) {
            leaks.push(format!("  [{label}] `{cmd}`"));
        }
    }

    assert!(
        leaks.is_empty(),
        "{} write-capable command(s) reached an outside path without a fence prompt:\n{}",
        leaks.len(),
        leaks.join("\n")
    );
}
