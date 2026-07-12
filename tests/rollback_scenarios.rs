/// Integration tests for Railguard's rollback and context system.
///
/// These tests simulate real editing sessions: files get created, modified,
/// and deleted — then we use Railguard's snapshot system to travel back in time
/// and verify everything is restored correctly.
use std::fs;
use std::path::Path;

// ── Helpers ──────────────────────────────────────────────────────────

fn create_session(
    snap_dir: &Path,
    session_id: &str,
    tool_use_id: &str,
    file_path: &str,
) -> railguard::types::SnapshotEntry {
    railguard::snapshot::capture::capture_snapshot(snap_dir, session_id, tool_use_id, file_path)
        .unwrap()
}

// ── Test: Single file, multiple edits, rollback to any point ──────

#[test]
fn rollback_multi_edit_to_any_point() {
    let dir = tempfile::tempdir().unwrap();
    let snap_dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("app.rs");

    // Version 1: original code
    fs::write(&file, "fn main() { println!(\"v1\"); }").unwrap();
    let snap1 = create_session(snap_dir.path(), "s1", "t1", file.to_str().unwrap());

    // Version 2: agent adds a feature
    fs::write(&file, "fn main() { println!(\"v2\"); }\nfn feature() {}").unwrap();
    let snap2 = create_session(snap_dir.path(), "s1", "t2", file.to_str().unwrap());

    // Version 3: agent refactors (introduces a bug)
    fs::write(&file, "fn main() { panic!(\"bug!\"); }\nfn feature() {}").unwrap();
    let snap3 = create_session(snap_dir.path(), "s1", "t3", file.to_str().unwrap());

    // Version 4: agent tries to fix but makes it worse
    fs::write(&file, "// everything is broken").unwrap();

    // Rollback to version 3 (before the "everything is broken" write)
    railguard::snapshot::rollback::rollback_by_id(snap_dir.path(), "s1", &snap3.id).unwrap();
    assert_eq!(
        fs::read_to_string(&file).unwrap(),
        "fn main() { panic!(\"bug!\"); }\nfn feature() {}"
    );

    // Rollback to version 2 (before the bug was introduced)
    railguard::snapshot::rollback::rollback_by_id(snap_dir.path(), "s1", &snap2.id).unwrap();
    assert_eq!(
        fs::read_to_string(&file).unwrap(),
        "fn main() { println!(\"v2\"); }\nfn feature() {}"
    );

    // Rollback to version 1 (the original)
    railguard::snapshot::rollback::rollback_by_id(snap_dir.path(), "s1", &snap1.id).unwrap();
    assert_eq!(
        fs::read_to_string(&file).unwrap(),
        "fn main() { println!(\"v1\"); }"
    );
}

// ── Test: File created then deleted via rollback ──────────────────

#[test]
fn rollback_removes_newly_created_file() {
    let dir = tempfile::tempdir().unwrap();
    let snap_dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("new_module.rs");

    // Snapshot before creation (file doesn't exist)
    let snap = create_session(snap_dir.path(), "s1", "t1", file.to_str().unwrap());
    assert!(!snap.existed);

    // Agent creates the file
    fs::write(&file, "pub fn new_module() {}").unwrap();
    assert!(file.exists());

    // Rollback — file should be deleted
    railguard::snapshot::rollback::rollback_by_id(snap_dir.path(), "s1", &snap.id).unwrap();
    assert!(!file.exists());
}

// ── Test: Multiple files, rollback entire session ────────────────

#[test]
fn rollback_entire_session_multiple_files() {
    let dir = tempfile::tempdir().unwrap();
    let snap_dir = tempfile::tempdir().unwrap();

    let main_rs = dir.path().join("main.rs");
    let lib_rs = dir.path().join("lib.rs");
    let config = dir.path().join("config.toml");

    // Original state
    fs::write(&main_rs, "fn main() {}").unwrap();
    fs::write(&lib_rs, "pub fn lib() {}").unwrap();
    fs::write(&config, "debug = true").unwrap();

    // Snapshot all three
    create_session(snap_dir.path(), "s1", "t1", main_rs.to_str().unwrap());
    create_session(snap_dir.path(), "s1", "t2", lib_rs.to_str().unwrap());
    create_session(snap_dir.path(), "s1", "t3", config.to_str().unwrap());

    // Agent modifies all three
    fs::write(&main_rs, "fn main() { broken(); }").unwrap();
    fs::write(&lib_rs, "pub fn lib() { also_broken(); }").unwrap();
    fs::write(&config, "debug = false\nproduction = true").unwrap();

    // Verify they're all changed
    assert!(fs::read_to_string(&main_rs).unwrap().contains("broken"));
    assert!(fs::read_to_string(&lib_rs).unwrap().contains("broken"));
    assert!(fs::read_to_string(&config).unwrap().contains("production"));

    // Rollback entire session
    let msgs = railguard::snapshot::rollback::rollback_session(snap_dir.path(), "s1").unwrap();
    assert_eq!(msgs.len(), 3);

    // All files should be back to original
    assert_eq!(fs::read_to_string(&main_rs).unwrap(), "fn main() {}");
    assert_eq!(fs::read_to_string(&lib_rs).unwrap(), "pub fn lib() {}");
    assert_eq!(fs::read_to_string(&config).unwrap(), "debug = true");
}

// ── Test: Step-based rollback (undo last N edits) ────────────────

#[test]
fn rollback_steps_undoes_last_n_edits() {
    let dir = tempfile::tempdir().unwrap();
    let snap_dir = tempfile::tempdir().unwrap();

    let file_a = dir.path().join("a.rs");
    let file_b = dir.path().join("b.rs");

    fs::write(&file_a, "original a").unwrap();
    fs::write(&file_b, "original b").unwrap();

    // 4 edits in sequence
    create_session(snap_dir.path(), "s1", "t1", file_a.to_str().unwrap());
    fs::write(&file_a, "edit 1 of a").unwrap();

    create_session(snap_dir.path(), "s1", "t2", file_b.to_str().unwrap());
    fs::write(&file_b, "edit 1 of b").unwrap();

    create_session(snap_dir.path(), "s1", "t3", file_a.to_str().unwrap());
    fs::write(&file_a, "edit 2 of a").unwrap();

    create_session(snap_dir.path(), "s1", "t4", file_b.to_str().unwrap());
    fs::write(&file_b, "edit 2 of b").unwrap();

    // Undo last 2 edits (should restore file_a to "edit 1 of a" and file_b to "edit 1 of b")
    railguard::snapshot::rollback::rollback_steps(snap_dir.path(), "s1", 2).unwrap();

    assert_eq!(fs::read_to_string(&file_a).unwrap(), "edit 1 of a");
    assert_eq!(fs::read_to_string(&file_b).unwrap(), "edit 1 of b");
}

// ── Test: Rollback specific file only ────────────────────────────

#[test]
fn rollback_single_file_leaves_others_intact() {
    let dir = tempfile::tempdir().unwrap();
    let snap_dir = tempfile::tempdir().unwrap();

    let good_file = dir.path().join("good.rs");
    let bad_file = dir.path().join("bad.rs");

    fs::write(&good_file, "good original").unwrap();
    fs::write(&bad_file, "bad original").unwrap();

    create_session(snap_dir.path(), "s1", "t1", good_file.to_str().unwrap());
    create_session(snap_dir.path(), "s1", "t2", bad_file.to_str().unwrap());

    // Agent modifies both
    fs::write(&good_file, "good modified (keep this)").unwrap();
    fs::write(&bad_file, "bad modified (revert this)").unwrap();

    // Only rollback the bad file
    railguard::snapshot::rollback::rollback_file(
        snap_dir.path(),
        "s1",
        bad_file.to_str().unwrap(),
    )
    .unwrap();

    // Good file should still be modified
    assert_eq!(
        fs::read_to_string(&good_file).unwrap(),
        "good modified (keep this)"
    );
    // Bad file should be reverted
    assert_eq!(fs::read_to_string(&bad_file).unwrap(), "bad original");
}

// ── Test: Context generation includes file changes ───────────────

#[test]
fn context_includes_file_changes_and_rollback_commands() {
    let dir = tempfile::tempdir().unwrap();
    let snap_dir = tempfile::tempdir().unwrap();
    let trace_dir = tempfile::tempdir().unwrap();

    let file = dir.path().join("src/main.rs");
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    fs::write(&file, "fn main() {}").unwrap();

    // Create a snapshot
    let snap = create_session(snap_dir.path(), "s1", "t1", file.to_str().unwrap());

    // Create a trace entry
    let trace = railguard::types::TraceEntry {
        timestamp: "2026-03-09T12:00:00Z".to_string(),
        session_id: "s1".to_string(),
        event: "PreToolUse".to_string(),
        tool: "Edit".to_string(),
        input_summary: file.to_str().unwrap().to_string(),
        decision: "allow".to_string(),
        rule: None,
        duration_ms: 1,
    };
    railguard::trace::logger::log_trace(trace_dir.path(), "s1", &trace).unwrap();

    // Modify the file
    fs::write(&file, "fn main() { new_code(); }").unwrap();

    // Generate context
    let context = railguard::context::generate_context(
        trace_dir.path(),
        snap_dir.path(),
        "s1",
        false,
    )
    .unwrap();

    // Context should include key information
    assert!(context.contains("Session Context: s1"));
    assert!(context.contains("Files Changed"));
    assert!(context.contains("main.rs"));
    assert!(context.contains("rollback"));
    assert!(context.contains(&snap.id));
}

// ── Test: Context with verbose diffs ─────────────────────────────

#[test]
fn context_verbose_shows_diffs() {
    let dir = tempfile::tempdir().unwrap();
    let snap_dir = tempfile::tempdir().unwrap();
    let trace_dir = tempfile::tempdir().unwrap();

    let file = dir.path().join("code.rs");
    fs::write(&file, "line one\nline two\nline three\n").unwrap();

    create_session(snap_dir.path(), "s1", "t1", file.to_str().unwrap());
    fs::write(&file, "line one\nline CHANGED\nline three\nnew line four\n").unwrap();

    let context = railguard::context::generate_context(
        trace_dir.path(),
        snap_dir.path(),
        "s1",
        true, // verbose = show diffs
    )
    .unwrap();

    assert!(context.contains("```diff"));
    assert!(context.contains("+ line CHANGED") || context.contains("+"));
}

// ── Test: Diff command shows changes ─────────────────────────────

#[test]
fn diff_shows_changes_between_snapshot_and_current() {
    let dir = tempfile::tempdir().unwrap();
    let snap_dir = tempfile::tempdir().unwrap();

    let file = dir.path().join("test.txt");
    fs::write(&file, "hello world\n").unwrap();

    create_session(snap_dir.path(), "s1", "t1", file.to_str().unwrap());
    fs::write(&file, "hello changed world\n").unwrap();

    let diff = railguard::context::show_diff(
        snap_dir.path(),
        "s1",
        Some(file.to_str().unwrap()),
    )
    .unwrap();

    assert!(diff.contains("test.txt"));
    // Should show something changed
    assert!(diff.contains("+") || diff.contains("-"));
}

// ── Test: Context shows blocked commands ──────────────────────────

#[test]
fn context_shows_blocked_commands() {
    let snap_dir = tempfile::tempdir().unwrap();
    let trace_dir = tempfile::tempdir().unwrap();

    // Log a blocked command
    let trace = railguard::types::TraceEntry {
        timestamp: "2026-03-09T12:00:00Z".to_string(),
        session_id: "s1".to_string(),
        event: "PreToolUse".to_string(),
        tool: "Bash".to_string(),
        input_summary: "terraform destroy".to_string(),
        decision: "block".to_string(),
        rule: Some("terraform-destroy".to_string()),
        duration_ms: 1,
    };
    railguard::trace::logger::log_trace(trace_dir.path(), "s1", &trace).unwrap();

    let context = railguard::context::generate_context(
        trace_dir.path(),
        snap_dir.path(),
        "s1",
        false,
    )
    .unwrap();

    assert!(context.contains("Blocked Commands"));
    assert!(context.contains("terraform destroy"));
    assert!(context.contains("terraform-destroy"));
}

// ── Test: "Digital twin" — fork, modify, rollback, verify ────────
// Simulates the scenario where an agent goes down a wrong path,
// you rollback, and then a different approach is taken.

#[test]
fn digital_twin_fork_and_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let snap_dir = tempfile::tempdir().unwrap();

    let api_rs = dir.path().join("api.rs");
    let db_rs = dir.path().join("db.rs");
    let test_rs = dir.path().join("test.rs");

    // Original codebase
    fs::write(&api_rs, "pub fn handle_request() -> Response { ok() }").unwrap();
    fs::write(&db_rs, "pub fn query() -> Vec<Row> { vec![] }").unwrap();
    fs::write(&test_rs, "fn test_api() { assert!(handle_request().is_ok()); }").unwrap();

    // Snapshot everything (session 1: the "good" state)
    create_session(snap_dir.path(), "attempt-1", "t1", api_rs.to_str().unwrap());
    create_session(snap_dir.path(), "attempt-1", "t2", db_rs.to_str().unwrap());
    create_session(snap_dir.path(), "attempt-1", "t3", test_rs.to_str().unwrap());

    // Agent attempt 1: tries to add caching but breaks everything
    fs::write(&api_rs, "pub fn handle_request() -> Response { cache.get_or_else(|| panic!()) }").unwrap();
    fs::write(&db_rs, "pub fn query() -> Vec<Row> { CACHE.lock().unwrap() }").unwrap();
    fs::write(&test_rs, "fn test_api() { /* tests removed because they fail */ }").unwrap();

    // That's bad! Rollback the entire attempt
    let msgs = railguard::snapshot::rollback::rollback_session(snap_dir.path(), "attempt-1").unwrap();
    assert_eq!(msgs.len(), 3);

    // Verify we're back to the original "good" state
    assert_eq!(
        fs::read_to_string(&api_rs).unwrap(),
        "pub fn handle_request() -> Response { ok() }"
    );
    assert_eq!(
        fs::read_to_string(&db_rs).unwrap(),
        "pub fn query() -> Vec<Row> { vec![] }"
    );
    assert_eq!(
        fs::read_to_string(&test_rs).unwrap(),
        "fn test_api() { assert!(handle_request().is_ok()); }"
    );

    // Now agent attempt 2 can take a different approach from the clean state
    // (In real usage, Claude would read the context and try something different)
    create_session(snap_dir.path(), "attempt-2", "t1", api_rs.to_str().unwrap());
    fs::write(&api_rs, "pub fn handle_request() -> Response { let data = query(); ok_with(data) }").unwrap();

    // This time it's good! The original db.rs and test.rs are untouched.
    assert!(fs::read_to_string(&db_rs).unwrap().contains("pub fn query()"));
    assert!(fs::read_to_string(&test_rs).unwrap().contains("assert!"));
}

// ── Test: Rollback preserves files not in snapshot ───────────────

#[test]
fn rollback_doesnt_touch_untracked_files() {
    let dir = tempfile::tempdir().unwrap();
    let snap_dir = tempfile::tempdir().unwrap();

    let tracked = dir.path().join("tracked.rs");
    let untracked = dir.path().join("untracked.rs");

    fs::write(&tracked, "tracked original").unwrap();
    fs::write(&untracked, "untracked content").unwrap();

    // Only snapshot the tracked file
    create_session(snap_dir.path(), "s1", "t1", tracked.to_str().unwrap());

    // Agent modifies both
    fs::write(&tracked, "tracked modified").unwrap();
    fs::write(&untracked, "untracked modified").unwrap();

    // Rollback session — should only restore tracked file
    railguard::snapshot::rollback::rollback_session(snap_dir.path(), "s1").unwrap();

    assert_eq!(fs::read_to_string(&tracked).unwrap(), "tracked original");
    assert_eq!(
        fs::read_to_string(&untracked).unwrap(),
        "untracked modified"
    );
}

// ── Test: Many edits to same file, step back precisely ───────────

#[test]
fn precise_step_back_through_edit_history() {
    let dir = tempfile::tempdir().unwrap();
    let snap_dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("evolving.txt");

    let versions = ["v1: initial",
        "v2: add feature A",
        "v3: refactor",
        "v4: add feature B",
        "v5: fix bug in A",
        "v6: optimization",
        "v7: add feature C",
        "v8: everything breaks"];

    // Write v1
    fs::write(&file, versions[0]).unwrap();

    // Snapshot before each subsequent version
    for (i, version) in versions.iter().enumerate().skip(1) {
        create_session(
            snap_dir.path(),
            "s1",
            &format!("t{}", i),
            file.to_str().unwrap(),
        );
        fs::write(&file, version).unwrap();
    }

    // Current state is v8 (broken)
    assert_eq!(fs::read_to_string(&file).unwrap(), "v8: everything breaks");

    // Step back 1 → v7 snapshot restored (which contains v7 content)
    railguard::snapshot::rollback::rollback_steps(snap_dir.path(), "s1", 1).unwrap();
    assert_eq!(fs::read_to_string(&file).unwrap(), "v7: add feature C");

    // Step back 3 more from original manifest → gets v4 snapshot
    // (steps 5, 6, 7 from the manifest which correspond to v5, v6, v7)
    // Actually rollback_steps reads from manifest and takes last N entries
    // Let's just step back the full history
    railguard::snapshot::rollback::rollback_steps(snap_dir.path(), "s1", 4).unwrap();
    // The 4th from the end is v4's snapshot (which was taken before v5 was written)
    // So it restores v4
    assert_eq!(fs::read_to_string(&file).unwrap(), "v4: add feature B");
}

// ── Test: New file creation + modification + rollback to before creation ──

#[test]
fn rollback_new_file_through_multiple_edits() {
    let dir = tempfile::tempdir().unwrap();
    let snap_dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("brand_new.rs");

    // Snapshot before file exists
    let snap_creation = create_session(snap_dir.path(), "s1", "t1", file.to_str().unwrap());
    assert!(!snap_creation.existed);

    // Agent creates the file
    fs::write(&file, "fn new() {}").unwrap();

    // Agent modifies it twice more
    create_session(snap_dir.path(), "s1", "t2", file.to_str().unwrap());
    fs::write(&file, "fn new() { improved(); }").unwrap();

    create_session(snap_dir.path(), "s1", "t3", file.to_str().unwrap());
    fs::write(&file, "fn new() { improved(); extra(); }").unwrap();

    // File exists with latest content
    assert!(file.exists());
    assert!(fs::read_to_string(&file).unwrap().contains("extra"));

    // Rollback to before creation — file should be deleted entirely
    railguard::snapshot::rollback::rollback_session(snap_dir.path(), "s1").unwrap();
    assert!(!file.exists());
}

// ── Test: Manifest records full history ──────────────────────────

#[test]
fn manifest_records_complete_edit_history() {
    let dir = tempfile::tempdir().unwrap();
    let snap_dir = tempfile::tempdir().unwrap();

    let file = dir.path().join("history.txt");
    fs::write(&file, "start").unwrap();

    for i in 0..10 {
        create_session(
            snap_dir.path(),
            "s1",
            &format!("tool-{}", i),
            file.to_str().unwrap(),
        );
        fs::write(&file, format!("edit {}", i)).unwrap();
    }

    let manifest = railguard::snapshot::capture::read_manifest(snap_dir.path(), "s1").unwrap();
    assert_eq!(manifest.len(), 10);

    // Each entry should have a unique tool_use_id
    let tool_ids: std::collections::HashSet<&str> =
        manifest.iter().map(|e| e.tool_use_id.as_str()).collect();
    assert_eq!(tool_ids.len(), 10);

    // Each entry should have the same file path
    assert!(manifest.iter().all(|e| e.file_path == file.to_str().unwrap()));
}

// ── Test: Context output is valid for LLM consumption ────────────

#[test]
fn context_output_is_structured_and_complete() {
    let dir = tempfile::tempdir().unwrap();
    let snap_dir = tempfile::tempdir().unwrap();
    let trace_dir = tempfile::tempdir().unwrap();

    let file_a = dir.path().join("a.rs");
    let file_b = dir.path().join("b.rs");

    fs::write(&file_a, "original a").unwrap();

    create_session(snap_dir.path(), "s1", "t1", file_a.to_str().unwrap());
    fs::write(&file_a, "modified a").unwrap();

    // New file
    create_session(snap_dir.path(), "s1", "t2", file_b.to_str().unwrap());
    fs::write(&file_b, "new file b").unwrap();

    // Log some traces
    for (decision, tool, summary) in [
        ("allow", "Edit", "a.rs"),
        ("allow", "Write", "b.rs"),
        ("block", "Bash", "rm -rf /"),
    ] {
        let trace = railguard::types::TraceEntry {
            timestamp: "2026-03-09T12:00:00Z".to_string(),
            session_id: "s1".to_string(),
            event: "PreToolUse".to_string(),
            tool: tool.to_string(),
            input_summary: summary.to_string(),
            decision: decision.to_string(),
            rule: if decision == "block" {
                Some("rm-rf-critical".to_string())
            } else {
                None
            },
            duration_ms: 1,
        };
        railguard::trace::logger::log_trace(trace_dir.path(), "s1", &trace).unwrap();
    }

    let context = railguard::context::generate_context(
        trace_dir.path(),
        snap_dir.path(),
        "s1",
        false,
    )
    .unwrap();

    // Verify structure
    assert!(context.contains("# Railguard Session Context"));
    assert!(context.contains("## Summary"));
    assert!(context.contains("## Files Changed"));
    assert!(context.contains("## Blocked Commands"));
    assert!(context.contains("## Recent Timeline"));
    assert!(context.contains("## Available Rollback Commands"));

    // Verify stats
    assert!(context.contains("Tool calls:** 3"));
    assert!(context.contains("Blocked:** 1"));
    assert!(context.contains("Files modified:** 2"));

    // Verify file info
    assert!(context.contains("MODIFIED"));
    assert!(context.contains("NEW FILE"));
}
