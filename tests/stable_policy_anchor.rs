//! Stable session project-root anchor (issue #16).
//!
//! The path fence and policy must anchor to a project root captured once per
//! session, not re-derived from each hook call's cwd. When the agent's cwd
//! drifts OUTSIDE the project subtree (a sibling repo, or a `/tmp` dir the
//! harness reports as cwd), the project's `railguard.yaml` — and its
//! `allowed_paths` — must still apply. Before the fix, resolving policy from
//! the drifted cwd found no config and fell back to empty defaults, so a path
//! the policy explicitly allows was prompted as "outside project directory".
//!
//! These tests drive the real binary and redirect all global railguard state
//! (`sessions`, `traces`) into a tempdir via `RAILGUARD_HOME`, so they never
//! touch the developer's real `~/.railguard`.

use std::io::Write;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn railguard_binary() -> String {
    let mut path = std::env::current_dir().unwrap();
    path.push("target/debug/railguard");
    path.to_str().unwrap().to_string()
}

/// A project dir (with a `.git` marker so `find_project_root` resolves to it)
/// holding a policy that allows an external sibling path.
fn make_project(allowed_abs: &Path) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".git")).unwrap();
    let yaml = format!(
        "version: 1\nblocklist: []\nfence:\n  enabled: true\n  allowed_paths:\n    - \"{}\"\n",
        allowed_abs.display()
    );
    std::fs::write(dir.path().join("railguard.yaml"), yaml).unwrap();
    dir
}

fn run_hook(binary: &str, event: &str, rg_home: &Path, input_json: &str) -> String {
    let output = Command::new(binary)
        .arg("hook")
        .arg("--event")
        .arg(event)
        .env("RAILGUARD_NO_KILL", "1")
        .env("RAILGUARD_HOME", rg_home)
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

fn session_start(cwd: &Path, sid: &str) -> String {
    serde_json::json!({
        "session_id": sid,
        "cwd": cwd.to_str().unwrap(),
        "hook_event_name": "SessionStart"
    })
    .to_string()
}

fn write_input(cwd: &Path, sid: &str, file_path: &Path) -> String {
    serde_json::json!({
        "session_id": sid,
        "cwd": cwd.to_str().unwrap(),
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": { "file_path": file_path.to_str().unwrap(), "content": "x" },
        "tool_use_id": "anchor-001"
    })
    .to_string()
}

fn path_fenced(stdout: &str) -> bool {
    stdout.to_lowercase().contains("path fence")
}

/// The regression: SessionStart anchors at the project root, then a tool call
/// from a cwd OUTSIDE the project writes to a configured allowed path. The
/// project's `allowed_paths` must still authorize it.
#[test]
fn policy_anchor_survives_cwd_drift() {
    let binary = railguard_binary();
    let rg_home = tempfile::tempdir().unwrap();
    let allowed = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let project = make_project(allowed.path());
    let sid = format!("anchor-drift-{}", std::process::id());

    // Anchor the session at the real project root.
    run_hook(
        &binary,
        "SessionStart",
        rg_home.path(),
        &session_start(project.path(), &sid),
    );
    assert!(
        rg_home.path().join("sessions").join(&sid).exists(),
        "SessionStart should write a global project-root pointer"
    );

    // cwd has drifted outside the project; the allowed path must still apply.
    let target = allowed.path().join("sub").join("file.txt");
    let stdout = run_hook(
        &binary,
        "PreToolUse",
        rg_home.path(),
        &write_input(outside.path(), &sid, &target),
    );
    assert!(
        !path_fenced(&stdout),
        "configured allowed_path was fenced after cwd drift (issue #16):\n{stdout}"
    );
}

/// The flip side: a genuinely-outside path (not under any allowed entry) must
/// still be fenced, proving the anchor fix doesn't disable the fence.
#[test]
fn genuinely_outside_path_still_fenced_after_drift() {
    let binary = railguard_binary();
    let rg_home = tempfile::tempdir().unwrap();
    let allowed = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let project = make_project(allowed.path());
    let sid = format!("anchor-outside-{}", std::process::id());

    run_hook(
        &binary,
        "SessionStart",
        rg_home.path(),
        &session_start(project.path(), &sid),
    );

    let target = outside.path().join("evil.txt");
    let stdout = run_hook(
        &binary,
        "PreToolUse",
        rg_home.path(),
        &write_input(outside.path(), &sid, &target),
    );
    assert!(
        path_fenced(&stdout),
        "a path outside every allowed entry must still be fenced:\n{stdout}"
    );
}

/// Sessions that never ran SessionStart still anchor: the first PreToolUse
/// (at/below the real root) back-fills the global pointer, so a later
/// cwd-drifted call recovers the root.
#[test]
fn fence_root_stable_without_session_start() {
    let binary = railguard_binary();
    let rg_home = tempfile::tempdir().unwrap();
    let allowed = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let project = make_project(allowed.path());
    let sid = format!("anchor-nostart-{}", std::process::id());

    // First PreToolUse at the project root — no prior SessionStart.
    let in_project = project.path().join("readme.md");
    run_hook(
        &binary,
        "PreToolUse",
        rg_home.path(),
        &write_input(project.path(), &sid, &in_project),
    );
    assert!(
        rg_home.path().join("sessions").join(&sid).exists(),
        "first PreToolUse should back-fill the global pointer"
    );

    // Now drift outside and hit a configured allowed path.
    let target = allowed.path().join("file.txt");
    let stdout = run_hook(
        &binary,
        "PreToolUse",
        rg_home.path(),
        &write_input(outside.path(), &sid, &target),
    );
    assert!(
        !path_fenced(&stdout),
        "allowed_path fenced after drift for a session without SessionStart:\n{stdout}"
    );
}

/// Regression for the sticky-wrong-root bug: a session with no SessionStart
/// whose FIRST tool call already reports a cwd OUTSIDE any repo must not persist
/// that cwd as the anchor. A later call at the real project root must resolve
/// correctly instead of staying stuck on the drifted directory.
#[test]
fn drifted_first_call_without_session_start_does_not_stick() {
    let binary = railguard_binary();
    let rg_home = tempfile::tempdir().unwrap();
    let allowed = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap(); // no .git — a bare cwd fallback
    let project = make_project(allowed.path());
    let sid = format!("anchor-drift-first-{}", std::process::id());

    // First call already outside any repo. It resolves for this call but the
    // untrustworthy cwd fallback must NOT be persisted as the session anchor.
    let scratch = outside.path().join("scratch.txt");
    run_hook(
        &binary,
        "PreToolUse",
        rg_home.path(),
        &write_input(outside.path(), &sid, &scratch),
    );
    assert!(
        !rg_home.path().join("sessions").join(&sid).exists(),
        "an outside-cwd first call must not back-fill a (wrong) global pointer"
    );

    // A later call at the real project root must anchor correctly, not inherit
    // the drifted directory.
    let target = allowed.path().join("file.txt");
    let stdout = run_hook(
        &binary,
        "PreToolUse",
        rg_home.path(),
        &write_input(project.path(), &sid, &target),
    );
    assert!(
        !path_fenced(&stdout),
        "session stuck on the drifted root — allowed path fenced from the real project:\n{stdout}"
    );
}
