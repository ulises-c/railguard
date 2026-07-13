//! Threat Detection Integration Tests
//!
//! Tests the "Ask the Human" system:
//! - Tier 1: Ask user on unambiguous evasion, allow if approved
//! - Tier 2: Warning on first occurrence, ask on second
//! - Tier 3: Behavioral retry detection — ask, then allow if approved
//! - Session approvals persist within a session
//! - Session state persistence

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

fn create_test_dir() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    // Anchor the project root at the tempdir so threat state lands inside it
    // (and is dropped with the tempdir) instead of escaping up to a shared
    // ancestor — e.g. a stray `.git` above the system temp dir.
    std::fs::create_dir_all(dir.path().join(".git")).unwrap();
    let yaml = "version: 1\nblocklist: []\ntrace:\n  enabled: true\n  directory: .railguard/traces";
    let policy_path = dir.path().join("railguard.yaml");
    std::fs::write(&policy_path, yaml).unwrap();
    dir
}

fn rg_home_for(input_json: &str) -> String {
    serde_json::from_str::<serde_json::Value>(input_json)
        .ok()
        .and_then(|v| v.get("cwd").and_then(|c| c.as_str()).map(String::from))
        .unwrap_or_else(|| ".".to_string())
}

fn simulate_hook(binary: &str, event: &str, input_json: &str) -> (i32, String, String) {
    let output = Command::new(binary)
        .arg("hook")
        .arg("--event")
        .arg(event)
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

    let code = output.status.code().unwrap_or(0);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stdout, stderr)
}

fn make_bash_input(session_id: &str, cwd: &str, command: &str) -> String {
    serde_json::json!({
        "session_id": session_id,
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "tool_use_id": "test-001"
    })
    .to_string()
}

fn output_contains_deny(stdout: &str) -> bool {
    stdout.contains("\"deny\"")
}

fn output_contains_ask(stdout: &str) -> bool {
    stdout.contains("\"ask\"")
}

fn output_is_not_allowed(stdout: &str) -> bool {
    stdout.contains("\"deny\"") || stdout.contains("\"ask\"")
}

// ═══════════════════════════════════════════════════════════════════
// TIER 1: Evasion detected — asks user for approval
// ═══════════════════════════════════════════════════════════════════

#[test]
fn tier1_rev_pipe_sh_asks_user() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();
    let sid = unique_session_id();

    let input = make_bash_input(&sid, cwd, "rev <<< 'yortsed mrofarret' | sh");
    let (_, stdout, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input);

    assert!(
        output_contains_ask(&stdout),
        "should ask user for approval: {}",
        stdout
    );
    assert!(
        stdout.contains("RAILGUARD"),
        "should mention RAILGUARD: {}",
        stdout
    );

    // State file should have a pending approval
    let state_path = dir.path().join(format!(".railguard/state/{}.json", sid));
    assert!(state_path.exists(), "state file should be created");
    let state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    assert!(
        !state["terminated"].as_bool().unwrap_or(false),
        "should NOT terminate"
    );
    assert!(
        state["pending_approval"].is_string(),
        "should have pending approval"
    );
}

#[test]
fn tier1_double_base64_asks_user() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();

    let input = make_bash_input(
        &unique_session_id(),
        cwd,
        "echo abc123 | base64 -d | base64 -d | sh",
    );
    let (_, stdout, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input);
    assert!(output_contains_ask(&stdout), "should ask user: {}", stdout);
}

#[test]
fn tier1_python_chr_asks_user() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();

    let input = make_bash_input(
        &unique_session_id(),
        cwd,
        r#"python3 -c "import os; os.system(chr(114)+chr(109))""#,
    );
    let (_, stdout, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input);
    assert!(output_contains_ask(&stdout), "should ask user: {}", stdout);
}

#[test]
fn tier1_printf_hex_asks_user() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();

    let input = make_bash_input(
        &unique_session_id(),
        cwd,
        r"$(printf '\x72\x6d') -rf /tmp/something",
    );
    let (_, stdout, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input);
    assert!(output_contains_ask(&stdout), "should ask user: {}", stdout);
}

// ═══════════════════════════════════════════════════════════════════
// TIER 1: Approval persists within session
// ═══════════════════════════════════════════════════════════════════

#[test]
fn tier1_approval_allows_subsequent_same_pattern() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();
    let sid = unique_session_id();

    // First call: should ask
    let input1 = make_bash_input(&sid, cwd, "rev <<< 'test' | sh");
    let (_, stdout1, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input1);
    assert!(
        output_contains_ask(&stdout1),
        "first should ask: {}",
        stdout1
    );

    // Simulate user approval by making a subsequent call
    // (resolve_pending_approval runs at start of next call)
    // The next call with a similar Tier 1 pattern should be allowed
    let input2 = make_bash_input(&sid, cwd, "rev <<< 'another' | sh");
    let (_, stdout2, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input2);
    assert!(
        !output_contains_deny(&stdout2),
        "second should be allowed after approval: {}",
        stdout2
    );
    assert!(
        !output_contains_ask(&stdout2),
        "should not ask again: {}",
        stdout2
    );
}

// ═══════════════════════════════════════════════════════════════════
// TIER 2: Escalating — warn first, ask on second
// ═══════════════════════════════════════════════════════════════════

#[test]
fn tier2_first_occurrence_warns() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();

    // First: variable-then-execution — should warn but NOT ask/terminate
    let input = make_bash_input(&unique_session_id(), cwd, r#"CMD="ls -la"; $CMD"#);
    let (_, stdout, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input);

    assert!(
        !output_contains_ask(&stdout),
        "first Tier 2 should not ask: {}",
        stdout
    );
    assert!(
        !output_contains_deny(&stdout),
        "first Tier 2 should not deny: {}",
        stdout
    );
}

#[test]
fn tier2_second_occurrence_asks_user() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();

    let sid = unique_session_id();

    // First occurrence — warning
    let input1 = make_bash_input(&sid, cwd, r#"CMD="ls -la"; $CMD"#);
    let (_, stdout1, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input1);
    assert!(!output_contains_ask(&stdout1), "first should not ask");

    // Second occurrence — should ask user
    let input2 = make_bash_input(&sid, cwd, r#"X="echo hello"; $X"#);
    let (_, stdout2, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input2);
    assert!(
        output_contains_ask(&stdout2),
        "second Tier 2 should ask user: {}",
        stdout2
    );
}

// ═══════════════════════════════════════════════════════════════════
// TIER 3: Behavioral retry detection
// ═══════════════════════════════════════════════════════════════════

#[test]
fn tier3_retry_after_block_asks_user() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();

    let sid = unique_session_id();

    // Step 1: Run terraform destroy — gets blocked by policy
    let input1 = make_bash_input(&sid, cwd, "terraform destroy");
    let (_, stdout1, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input1);
    assert!(
        output_contains_deny(&stdout1),
        "terraform destroy should be blocked"
    );

    // Step 2: Try again with same keywords — behavioral evasion detected, asks user
    let input2 = make_bash_input(&sid, cwd, "terraform apply -destroy");
    let (_, stdout2, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input2);
    assert!(
        output_is_not_allowed(&stdout2),
        "retry should be caught: {}",
        stdout2
    );
}

// ═══════════════════════════════════════════════════════════════════
// ISSUE #18: detector false positives
// ═══════════════════════════════════════════════════════════════════

#[test]
fn benign_git_sequence_never_flagged() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();
    let sid = unique_session_id();

    let input1 = make_bash_input(
        &sid,
        cwd,
        r#"git add src/foo.rs && git commit -m "fix: update foo""#,
    );
    let (_, stdout1, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input1);
    assert!(!output_is_not_allowed(&stdout1), "first git: {}", stdout1);

    let input2 = make_bash_input(&sid, cwd, "git log --oneline -1 && grep -n foo src/foo.rs");
    let (_, stdout2, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input2);
    assert!(!output_is_not_allowed(&stdout2), "second git: {}", stdout2);
}

#[test]
fn tier1_ask_does_not_cascade_into_tier3() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();
    let sid = unique_session_id();

    // A Tier-1 ask (transform-pipe-to-shell) whose text shares words with the
    // routine follow-up. The ask must not arm retry detection.
    let input1 = make_bash_input(&sid, cwd, "rev <<< 'railguard yaml reorder' | sh");
    let (_, stdout1, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input1);
    assert!(
        output_contains_ask(&stdout1),
        "tier1 should ask: {}",
        stdout1
    );

    let input2 = make_bash_input(
        &sid,
        cwd,
        r#"git add railguard.yaml && git commit -m "reorder yaml""#,
    );
    let (_, stdout2, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input2);
    assert!(
        !output_is_not_allowed(&stdout2),
        "routine command after a tier1 ask must not be flagged: {}",
        stdout2
    );
}

#[test]
fn heredoc_python_clean_allowed() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();
    let sid = unique_session_id();

    let cmd = "python3 - <<'PY'\n\
               import re\n\
               text = open('railguard.yaml').read()\n\
               open('railguard.yaml', 'w').write('\\n'.join(sorted(text.split('\\n'))))\n\
               PY";
    let input = make_bash_input(&sid, cwd, cmd);
    let (_, stdout, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input);
    assert!(
        !output_is_not_allowed(&stdout),
        "clean heredoc script must be allowed: {}",
        stdout
    );
}

#[test]
fn heredoc_python_obfuscated_asks() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();
    let sid = unique_session_id();

    let cmd = "python3 - <<'PY'\n\
               import base64, os\n\
               os.system(base64.b64decode('dGVycmFmb3JtIGRlc3Ryb3k=').decode())\n\
               PY";
    let input = make_bash_input(&sid, cwd, cmd);
    let (_, stdout, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input);
    assert!(
        output_is_not_allowed(&stdout),
        "obfuscated heredoc payload must be caught: {}",
        stdout
    );
}

// ═══════════════════════════════════════════════════════════════════
// SESSION STATE PERSISTENCE
// ═══════════════════════════════════════════════════════════════════

#[test]
fn state_persists_across_invocations() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();
    let sid = unique_session_id();

    // First call
    let input1 = make_bash_input(&sid, cwd, "echo hello");
    simulate_hook(&railguard_binary(), "PreToolUse", &input1);

    // State file should exist
    let state_path = dir.path().join(format!(".railguard/state/{}.json", sid));
    assert!(state_path.exists(), "state file should be created");

    let state1: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    assert_eq!(state1["tool_call_count"], 1);

    // Second call
    let input2 = make_bash_input(&sid, cwd, "echo world");
    simulate_hook(&railguard_binary(), "PreToolUse", &input2);

    let state2: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    assert_eq!(state2["tool_call_count"], 2);
}

#[test]
fn session_approvals_persist_in_state() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();
    let sid = unique_session_id();

    // Trigger a Tier 1 ask
    let input1 = make_bash_input(&sid, cwd, "rev <<< 'test' | sh");
    let (_, stdout1, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input1);
    assert!(output_contains_ask(&stdout1));

    // State should have pending_approval
    let state_path = dir.path().join(format!(".railguard/state/{}.json", sid));
    let state1: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    assert!(state1["pending_approval"].is_string());

    // Next call resolves the pending approval
    let input2 = make_bash_input(&sid, cwd, "echo safe");
    simulate_hook(&railguard_binary(), "PreToolUse", &input2);

    let state2: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    assert!(
        state2["pending_approval"].is_null(),
        "pending should be resolved"
    );
    assert!(
        !state2["session_approvals"].as_array().unwrap().is_empty(),
        "should have session approvals"
    );
}

// ═══════════════════════════════════════════════════════════════════
// SESSION RESUME: Terminated sessions can be resumed with approval
// ═══════════════════════════════════════════════════════════════════

#[test]
fn terminated_session_asks_to_resume() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();
    let sid = unique_session_id();

    // Manually create a terminated session state
    let state_dir = dir.path().join(".railguard/state");
    std::fs::create_dir_all(&state_dir).unwrap();
    let state_json = serde_json::json!({
        "session_id": &sid,
        "tool_call_count": 10,
        "suspicion_level": 2,
        "warning_count": 1,
        "block_history": [],
        "heightened_until_call": null,
        "heightened_keywords": [],
        "session_approvals": [],
        "pending_approval": null,
        "terminated": true,
        "termination_reason": "Tier 1 evasion detected: interpreter-obfuscation",
        "termination_timestamp": "2026-03-22T00:00:00Z"
    });
    std::fs::write(
        state_dir.join(format!("{}.json", sid)),
        serde_json::to_string_pretty(&state_json).unwrap(),
    )
    .unwrap();

    // First tool call on terminated session should ASK (not deny)
    let input = make_bash_input(&sid, cwd, "echo hello");
    let (_, stdout, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input);
    assert!(
        output_contains_ask(&stdout),
        "terminated session should ask to resume, not deny: {}",
        stdout
    );
    assert!(
        stdout.contains("RAILGUARD"),
        "should mention RAILGUARD: {}",
        stdout
    );
    assert!(
        !output_contains_deny(&stdout),
        "should NOT hard deny: {}",
        stdout
    );
}

#[test]
fn terminated_session_resumes_after_approval() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();
    let sid = unique_session_id();

    // Create terminated state
    let state_dir = dir.path().join(".railguard/state");
    std::fs::create_dir_all(&state_dir).unwrap();
    let state_json = serde_json::json!({
        "session_id": &sid,
        "tool_call_count": 10,
        "suspicion_level": 2,
        "warning_count": 3,
        "block_history": [{"timestamp": "2026-03-22T00:00:00Z", "tool_call_count": 9, "command": "bad cmd", "rule": "test", "keywords": ["bad"], "tier": 1}],
        "heightened_until_call": 13,
        "heightened_keywords": ["bad"],
        "session_approvals": [],
        "pending_approval": null,
        "terminated": true,
        "termination_reason": "Tier 1 evasion detected: test-pattern",
        "termination_timestamp": "2026-03-22T00:00:00Z"
    });
    std::fs::write(
        state_dir.join(format!("{}.json", sid)),
        serde_json::to_string_pretty(&state_json).unwrap(),
    )
    .unwrap();

    // First call: asks to resume
    let input1 = make_bash_input(&sid, cwd, "echo hello");
    let (_, stdout1, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input1);
    assert!(output_contains_ask(&stdout1), "should ask to resume");

    // Second call: approval resolved, session should be clean
    let input2 = make_bash_input(&sid, cwd, "echo world");
    let (_, stdout2, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input2);
    assert!(
        !output_contains_deny(&stdout2),
        "should not deny after approval: {}",
        stdout2
    );
    assert!(
        !output_contains_ask(&stdout2),
        "should not ask again: {}",
        stdout2
    );

    // Verify state was fully reset
    let state: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(state_dir.join(format!("{}.json", sid))).unwrap(),
    )
    .unwrap();
    assert!(
        !state["terminated"].as_bool().unwrap_or(true),
        "terminated should be false"
    );
    assert_eq!(state["suspicion_level"], 0, "suspicion should be reset");
    assert_eq!(state["warning_count"], 0, "warnings should be reset");
    assert!(
        state["block_history"].as_array().unwrap().is_empty(),
        "block history should be cleared"
    );
}

#[test]
fn terminated_session_stays_blocked_if_denied() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();
    let sid = unique_session_id();

    // Create terminated state with NO pending approval (simulates user denied)
    let state_dir = dir.path().join(".railguard/state");
    std::fs::create_dir_all(&state_dir).unwrap();
    let state_json = serde_json::json!({
        "session_id": &sid,
        "tool_call_count": 10,
        "suspicion_level": 2,
        "warning_count": 1,
        "block_history": [],
        "heightened_until_call": null,
        "heightened_keywords": [],
        "session_approvals": [],
        "pending_approval": null,
        "terminated": true,
        "termination_reason": "test reason",
        "termination_timestamp": "2026-03-22T00:00:00Z"
    });

    // Each call should keep asking (not silently allow)
    std::fs::write(
        state_dir.join(format!("{}.json", sid)),
        serde_json::to_string_pretty(&state_json).unwrap(),
    )
    .unwrap();

    let input1 = make_bash_input(&sid, cwd, "echo hello");
    let (_, stdout1, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input1);
    assert!(output_contains_ask(&stdout1), "should ask: {}", stdout1);

    // Simulate denial: rewrite state without the pending approval being resolved
    // (In real life, if user denies, Claude Code doesn't run the tool, so no next call.
    // But if Claude retries, the pending_approval is still there and gets resolved.)
    // To truly test denial, we'd need to clear pending_approval manually.
    // For now, we just verify it keeps asking on fresh state.
    std::fs::write(
        state_dir.join(format!("{}.json", sid)),
        serde_json::to_string_pretty(&state_json).unwrap(),
    )
    .unwrap();

    let input2 = make_bash_input(&sid, cwd, "echo world");
    let (_, stdout2, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input2);
    assert!(
        output_contains_ask(&stdout2),
        "should still ask: {}",
        stdout2
    );
}

// ═══════════════════════════════════════════════════════════════════
// SAFE COMMANDS NOT AFFECTED
// ═══════════════════════════════════════════════════════════════════

#[test]
fn normal_commands_unaffected_by_threat_system() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();

    let safe_commands = [
        "npm test",
        "cargo build --release",
        "git status",
        "ls -la",
        "python3 -c \"print('hello')\"",
        "echo hello | grep hello",
    ];

    for cmd in &safe_commands {
        let input = make_bash_input(&unique_session_id(), cwd, cmd);
        let (_, stdout, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input);
        assert!(
            !output_is_not_allowed(&stdout),
            "'{}' should not trigger threat detection: {}",
            cmd,
            stdout
        );
    }
}
