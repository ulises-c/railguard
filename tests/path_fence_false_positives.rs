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
    ("find delete", r#"find ~/outside -depth -delete"#),
    ("find exec", r#"find ~/outside -exec rm {} +"#),
    ("find execdir", r#"find ~/outside -execdir rm {} +"#),
    ("find ok", r#"find ~/outside -ok rm {} +"#),
    ("sed in place", r#"sed -i 's/a/b/' ~/outside/file"#),
    (
        "sed backup in place",
        r#"sed -ibak 's/a/b/' ~/outside/file"#,
    ),
    (
        "sed long in place",
        r#"sed --in-place 's/a/b/' ~/outside/file"#,
    ),
    ("yq in place", r#"yq -i '.x = 1' ~/outside/file.yaml"#),
    (
        "yq long in place",
        r#"yq --inplace '.x = 1' ~/outside/file.yaml"#,
    ),
    ("sort output", r#"sort -o ~/outside/sorted.txt input.txt"#),
    (
        "sort long output",
        r#"sort --output ~/outside/sorted.txt input.txt"#,
    ),
    (
        "uniq output",
        r#"uniq --output=~/outside/uniq.txt input.txt"#,
    ),
    ("xxd revert", r#"xxd -r dump.hex ~/outside/output.bin"#),
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

#[test]
fn non_force_worktree_removal_outside_project_is_allowed() {
    let dir = create_policy_dir("version: 1\nblocklist: []\n");
    let cwd = dir.path().to_str().unwrap();
    let stdout = simulate_hook(
        &railguard_binary(),
        &bash_input(cwd, "git worktree remove ~/old-worktree"),
    );

    assert!(
        stdout.contains("\"permissionDecision\":\"allow\""),
        "non-force worktree removal should rely on Git's dirty-worktree check: {stdout}"
    );
}

#[test]
fn hard_policy_block_wins_over_outside_project_prompt() {
    let dir = create_policy_dir(
        r#"version: 1
blocklist:
  - name: never-delete-marker
    tool: Bash
    pattern: "rm\\s+.*outside-policy-block"
    action: block
    message: "test hard block"
"#,
    );
    let cwd = dir.path().to_str().unwrap();
    let stdout = simulate_hook(
        &railguard_binary(),
        &bash_input(cwd, "rm -rf ~/outside-policy-block"),
    );

    assert!(stdout.contains("Railguard BLOCKED"), "stdout: {stdout}");
    assert!(!path_fenced(&stdout), "hard block was downgraded: {stdout}");
}

#[test]
fn memory_delete_is_snapshotted_before_approval() {
    let dir = tempfile::Builder::new()
        .prefix(".railguard-memory-test-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    std::fs::create_dir_all(dir.path().join(".git")).unwrap();
    std::fs::write(
        dir.path().join("railguard.yaml"),
        "version: 1\nblocklist: []\n",
    )
    .unwrap();
    let memory_dir = dir.path().join(".claude/projects/test-project/memory");
    std::fs::create_dir_all(&memory_dir).unwrap();
    let memory_file = memory_dir.join("stale.md");
    std::fs::write(&memory_file, "stale memory").unwrap();
    let cwd = dir.path().to_str().unwrap();
    let session_id = unique_session_id();
    let command = format!("rm -rf {}", memory_dir.display());
    let paths = railguard::block::evasion::extract_paths_from_command(&command);
    assert!(
        paths
            .iter()
            .any(|path| railguard::memory::guard::is_memory_path(path)),
        "memory path was not extracted from `{command}`: {paths:?}"
    );
    let loaded =
        railguard::policy::loader::load_policy(&dir.path().join("railguard.yaml")).unwrap();
    assert!(loaded.memory.enabled);
    let input = serde_json::json!({
        "session_id": session_id,
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "tool_use_id": "memory-delete"
    })
    .to_string();

    let stdout = simulate_hook(&railguard_binary(), &input);
    assert!(
        stdout.contains("\"permissionDecision\":\"ask\""),
        "stdout: {stdout}"
    );

    let manifest = dir
        .path()
        .join(".railguard/snapshots")
        .join(&session_id)
        .join("manifest.jsonl");
    let entries = std::fs::read_to_string(&manifest)
        .unwrap_or_else(|error| panic!("missing pre-approval snapshot: {error}"));
    assert!(entries.contains(memory_file.to_str().unwrap()), "{entries}");
}

#[test]
fn claude_memory_container_roots_remain_blocked() {
    let dir = create_policy_dir(
        "version: 1\nblocklist: []\nmemory:\n  enabled: false\nfence:\n  enabled: true\n  allowed_paths:\n    - ~/.claude\n  denied_paths: []\n",
    );
    let cwd = dir.path().to_str().unwrap();

    for target in ["~/.claude", "~/.claude/projects"] {
        let stdout = simulate_hook(
            &railguard_binary(),
            &bash_input(cwd, &format!("find {target} -depth -delete")),
        );
        assert!(
            stdout.contains("\"permissionDecision\":\"deny\""),
            "`{target}` should remain blocked: {stdout}"
        );
    }
}
