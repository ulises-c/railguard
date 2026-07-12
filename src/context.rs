use colored::Colorize;
use std::fs;
use std::path::Path;

use crate::snapshot::capture::read_manifest;
use crate::trace::logger;
use crate::types::{SnapshotEntry, TraceEntry};

/// Generate a rich context summary for Claude Code to reason about rollbacks.
/// Output is designed to be read by an LLM — structured, complete, and actionable.
pub fn generate_context(
    trace_dir: &Path,
    snapshot_dir: &Path,
    session_id: &str,
    verbose: bool,
) -> Result<String, String> {
    let traces = logger::read_traces(trace_dir, session_id)?;
    let snapshots = read_manifest(snapshot_dir, session_id)?;

    if traces.is_empty() && snapshots.is_empty() {
        return Err(format!("No data found for session '{}'", session_id));
    }

    let mut out = String::new();

    out.push_str(&format!("# Railguard Session Context: {}\n\n", session_id));

    // Summary stats
    let total_calls = traces.len();
    let blocked = traces.iter().filter(|t| t.decision == "block").count();
    let approved = traces.iter().filter(|t| t.decision == "approve").count();
    let files_touched: std::collections::HashSet<&str> = snapshots
        .iter()
        .map(|s| s.file_path.as_str())
        .collect();

    out.push_str("## Summary\n\n");
    out.push_str(&format!("- **Tool calls:** {}\n", total_calls));
    out.push_str(&format!("- **Blocked:** {}\n", blocked));
    out.push_str(&format!("- **Approved (human sign-off):** {}\n", approved));
    out.push_str(&format!("- **Files modified:** {}\n", files_touched.len()));
    out.push_str(&format!("- **Snapshots available:** {}\n\n", snapshots.len()));

    // File change summary with diffs
    if !snapshots.is_empty() {
        out.push_str("## Files Changed\n\n");

        // Group snapshots by file path
        let mut file_history: std::collections::BTreeMap<&str, Vec<&SnapshotEntry>> =
            std::collections::BTreeMap::new();
        for snap in &snapshots {
            file_history
                .entry(&snap.file_path)
                .or_default()
                .push(snap);
        }

        for (file_path, snaps) in &file_history {
            let first = snaps.first().unwrap();
            let edit_count = snaps.len();

            let state = if !first.existed {
                "NEW FILE"
            } else {
                "MODIFIED"
            };

            out.push_str(&format!(
                "### `{}` ({}, {} edit{})\n\n",
                file_path,
                state,
                edit_count,
                if edit_count > 1 { "s" } else { "" }
            ));

            // Show the diff between original snapshot and current file
            if verbose {
                if let Some(diff) = compute_diff(snapshot_dir, session_id, first, file_path) {
                    out.push_str("```diff\n");
                    out.push_str(&diff);
                    out.push_str("```\n\n");
                }
            } else {
                // Show a brief summary
                let current_size = fs::metadata(file_path)
                    .map(|m| m.len())
                    .unwrap_or(0);
                let original_size = if first.existed {
                    get_snapshot_size(snapshot_dir, session_id, &first.hash)
                } else {
                    0
                };

                let size_delta = current_size as i64 - original_size as i64;
                let delta_str = if size_delta > 0 {
                    format!("+{} bytes", size_delta)
                } else if size_delta < 0 {
                    format!("{} bytes", size_delta)
                } else {
                    "unchanged size".to_string()
                };

                out.push_str(&format!("  Original: {} bytes → Current: {} bytes ({})\n\n", original_size, current_size, delta_str));
            }

            // Edit timeline
            out.push_str("  Edit history:\n");
            for (i, snap) in snaps.iter().enumerate() {
                let action = if !snap.existed && i == 0 {
                    "created"
                } else {
                    "modified"
                };
                out.push_str(&format!(
                    "  {}. [{}] {} at {}\n",
                    i + 1,
                    snap.id,
                    action,
                    snap.timestamp
                ));
            }
            out.push('\n');
        }
    }

    // Blocked commands (important context for understanding what went wrong)
    let blocked_traces: Vec<&TraceEntry> = traces
        .iter()
        .filter(|t| t.decision == "block")
        .collect();

    if !blocked_traces.is_empty() {
        out.push_str("## Blocked Commands\n\n");
        for t in &blocked_traces {
            let rule_str = t.rule.as_deref().unwrap_or("unknown");
            out.push_str(&format!(
                "- `{}` — blocked by rule `{}` at {}\n",
                t.input_summary, rule_str, t.timestamp
            ));
        }
        out.push('\n');
    }

    // Timeline (last 20 events)
    if !traces.is_empty() {
        out.push_str("## Recent Timeline\n\n");
        out.push_str("```\n");
        let start = if traces.len() > 20 { traces.len() - 20 } else { 0 };
        for t in &traces[start..] {
            out.push_str(&format!("{}\n", logger::format_trace_entry(t)));
        }
        out.push_str("```\n\n");
    }

    // Rollback commands (actionable for Claude)
    if !snapshots.is_empty() {
        out.push_str("## Available Rollback Commands\n\n");
        out.push_str(&format!(
            "```bash\n# Undo the last edit\nrailguard rollback --session {} --steps 1\n\n",
            session_id
        ));
        out.push_str(&format!(
            "# Undo the last N edits\nrailguard rollback --session {} --steps N\n\n",
            session_id
        ));
        out.push_str(&format!(
            "# Restore a specific file to its original state\nrailguard rollback --session {} --file <path>\n\n",
            session_id
        ));
        out.push_str(&format!(
            "# Restore everything to the session start\nrailguard rollback --session {} \n\n",
            session_id
        ));

        // List specific snapshot IDs
        out.push_str("# Restore a specific snapshot\n");
        for snap in &snapshots {
            let state = if snap.existed { "before edit" } else { "before creation" };
            out.push_str(&format!(
                "railguard rollback --session {} --id {}   # {} — {}\n",
                session_id, snap.id, snap.file_path, state
            ));
        }
        out.push_str("```\n");
    }

    Ok(out)
}

/// Compute a unified diff between a snapshot and the current file.
fn compute_diff(
    snapshot_dir: &Path,
    session_id: &str,
    original_snap: &SnapshotEntry,
    file_path: &str,
) -> Option<String> {
    let current_content = fs::read_to_string(file_path).ok()?;

    let original_content = if original_snap.existed {
        let snap_path = snapshot_dir
            .join(session_id)
            .join(format!("{}.snapshot", original_snap.hash));
        fs::read_to_string(snap_path).ok()?
    } else {
        String::new()
    };

    if original_content == current_content {
        return Some("(no changes from original)\n".to_string());
    }

    // Simple line-by-line diff
    let original_lines: Vec<&str> = original_content.lines().collect();
    let current_lines: Vec<&str> = current_content.lines().collect();

    let mut diff = String::new();
    diff.push_str(&format!("--- a/{}\n", file_path));
    diff.push_str(&format!("+++ b/{}\n", file_path));

    // Use a simple LCS-based diff
    let changes = simple_diff(&original_lines, &current_lines);

    // Limit diff output to avoid overwhelming the context
    let max_lines = 100;
    for (line_count, change) in changes.iter().enumerate() {
        if line_count >= max_lines {
            diff.push_str(&format!("\n... ({} more lines)\n", changes.len() - line_count));
            break;
        }
        diff.push_str(change);
        diff.push('\n');
    }

    Some(diff)
}

/// Simple diff producing +/- lines (not a full unified diff, but good enough for LLM context).
fn simple_diff(original: &[&str], current: &[&str]) -> Vec<String> {
    let mut changes = Vec::new();
    let mut i = 0;
    let mut j = 0;

    while i < original.len() || j < current.len() {
        if i < original.len() && j < current.len() && original[i] == current[j] {
            // Context line (skip to keep output concise)
            i += 1;
            j += 1;
            continue;
        }

        // Find the next matching line to resync
        let mut found = false;

        // Look ahead in current for a match with original[i]
        if i < original.len() {
            let end = std::cmp::min(j + 5, current.len());
            if let Some(k) = (j..end).find(|&k| current[k] == original[i]) {
                // Lines j..k are additions
                for line in &current[j..k] {
                    changes.push(format!("+ {}", line));
                }
                j = k;
                found = true;
            }
        }

        if !found && j < current.len() {
            // Look ahead in original for a match with current[j]
            let end = std::cmp::min(i + 5, original.len());
            if let Some(k) = (i..end).find(|&k| original[k] == current[j]) {
                // Lines i..k are removals
                for line in &original[i..k] {
                    changes.push(format!("- {}", line));
                }
                i = k;
                found = true;
            }
        }

        if !found {
            // No match found nearby — record as change
            if i < original.len() {
                changes.push(format!("- {}", original[i]));
                i += 1;
            }
            if j < current.len() {
                changes.push(format!("+ {}", current[j]));
                j += 1;
            }
        }
    }

    changes
}

/// Get the size of a snapshot file.
fn get_snapshot_size(snapshot_dir: &Path, session_id: &str, hash: &str) -> u64 {
    let snap_path = snapshot_dir
        .join(session_id)
        .join(format!("{}.snapshot", hash));
    fs::metadata(snap_path).map(|m| m.len()).unwrap_or(0)
}

/// Show a diff between a snapshot and the current file state.
pub fn show_diff(
    snapshot_dir: &Path,
    session_id: &str,
    file_path: Option<&str>,
) -> Result<String, String> {
    let snapshots = read_manifest(snapshot_dir, session_id)?;

    if snapshots.is_empty() {
        return Err(format!("No snapshots found for session '{}'", session_id));
    }

    let mut out = String::new();

    // Group by file and show diff for each (or just the requested file)
    let mut seen = std::collections::HashSet::new();
    let originals: Vec<&SnapshotEntry> = snapshots
        .iter()
        .filter(|e| seen.insert(e.file_path.clone()))
        .filter(|e| file_path.is_none() || file_path == Some(e.file_path.as_str()))
        .collect();

    if originals.is_empty() {
        return Err(format!("No snapshots found for file '{}'", file_path.unwrap_or("")));
    }

    for snap in &originals {
        out.push_str(&format!("=== {} ===\n", snap.file_path));

        if let Some(diff) = compute_diff(snapshot_dir, session_id, snap, &snap.file_path) {
            out.push_str(&diff);
        } else {
            out.push_str("(file no longer exists or cannot be read)\n");
        }
        out.push('\n');
    }

    Ok(out)
}

/// Print context to stdout for the user / Claude Code.
pub fn print_context(
    trace_dir: &Path,
    snapshot_dir: &Path,
    session_id: &str,
    verbose: bool,
) {
    match generate_context(trace_dir, snapshot_dir, session_id, verbose) {
        Ok(context) => println!("{}", context),
        Err(e) => eprintln!("  {} {}", "✗".red().bold(), e),
    }
}

/// Print diff to stdout.
pub fn print_diff(
    snapshot_dir: &Path,
    session_id: &str,
    file_path: Option<&str>,
) {
    match show_diff(snapshot_dir, session_id, file_path) {
        Ok(diff) => println!("{}", diff),
        Err(e) => eprintln!("  {} {}", "✗".red().bold(), e),
    }
}
