use std::fs;
use std::path::Path;

use crate::snapshot::capture::read_manifest;
use crate::types::SnapshotEntry;

/// Rollback a specific snapshot by ID.
pub fn rollback_by_id(
    snapshot_dir: &Path,
    session_id: &str,
    snapshot_id: &str,
) -> Result<String, String> {
    let manifest = read_manifest(snapshot_dir, session_id)?;

    let entry = manifest
        .iter()
        .find(|e| e.id == snapshot_id)
        .ok_or_else(|| {
            format!(
                "Snapshot '{}' not found in session '{}'",
                snapshot_id, session_id
            )
        })?;

    restore_entry(snapshot_dir, entry)
}

/// Rollback the most recent snapshot for a file.
pub fn rollback_file(
    snapshot_dir: &Path,
    session_id: &str,
    file_path: &str,
) -> Result<String, String> {
    let manifest = read_manifest(snapshot_dir, session_id)?;

    let entry = manifest
        .iter()
        .rev()
        .find(|e| e.file_path == file_path)
        .ok_or_else(|| {
            format!(
                "No snapshot found for '{}' in session '{}'",
                file_path, session_id
            )
        })?;

    restore_entry(snapshot_dir, entry)
}

/// Rollback all files in a session to their state before the session started.
/// Uses the first snapshot of each file (the original state).
pub fn rollback_session(snapshot_dir: &Path, session_id: &str) -> Result<Vec<String>, String> {
    let manifest = read_manifest(snapshot_dir, session_id)?;

    // Get the first snapshot for each unique file path (original state)
    let mut seen = std::collections::HashSet::new();
    let originals: Vec<&SnapshotEntry> = manifest
        .iter()
        .filter(|e| seen.insert(e.file_path.clone()))
        .collect();

    let mut restored = vec![];
    for entry in originals {
        let msg = restore_entry(snapshot_dir, entry)?;
        restored.push(msg);
    }

    Ok(restored)
}

/// Step back N edits in a session (undo the last N tool calls).
pub fn rollback_steps(
    snapshot_dir: &Path,
    session_id: &str,
    steps: usize,
) -> Result<Vec<String>, String> {
    let manifest = read_manifest(snapshot_dir, session_id)?;

    // A step is one tool call, not one file. A single apply_patch snapshots
    // every file it touches under one tool_use_id, so counting entries would
    // undo a rename only halfway — deleting the destination without restoring
    // the source.
    let mut calls: Vec<&str> = Vec::new();
    for entry in &manifest {
        if !calls.contains(&entry.tool_use_id.as_str()) {
            calls.push(&entry.tool_use_id);
        }
    }

    if steps > calls.len() {
        return Err(format!(
            "Only {} snapshots available, cannot step back {}",
            calls.len(),
            steps
        ));
    }

    let selected: Vec<&str> = calls.iter().rev().take(steps).copied().collect();
    let to_rollback: Vec<&SnapshotEntry> = manifest
        .iter()
        .rev()
        .filter(|entry| selected.contains(&entry.tool_use_id.as_str()))
        .collect();
    let mut restored = vec![];

    for entry in to_rollback {
        let msg = restore_entry(snapshot_dir, entry)?;
        restored.push(msg);
    }

    Ok(restored)
}

/// Restore a file from a snapshot entry.
fn restore_entry(snapshot_dir: &Path, entry: &SnapshotEntry) -> Result<String, String> {
    let target = Path::new(&entry.file_path);

    if !entry.existed {
        // File didn't exist before — delete it
        if target.exists() {
            fs::remove_file(target)
                .map_err(|e| format!("Failed to remove {}: {}", entry.file_path, e))?;
        }
        return Ok(format!("Removed {} (didn't exist before)", entry.file_path));
    }

    // Restore from snapshot file
    let snap_path = snapshot_dir
        .join(&entry.session_id)
        .join(format!("{}.snapshot", entry.hash));

    if !snap_path.exists() {
        return Err(format!("Snapshot file missing for {}", entry.file_path));
    }

    let content = fs::read(&snap_path).map_err(|e| format!("Failed to read snapshot: {}", e))?;

    // Ensure parent directory exists
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create directory: {}", e))?;
    }

    fs::write(target, &content)
        .map_err(|e| format!("Failed to restore {}: {}", entry.file_path, e))?;

    Ok(format!(
        "Restored {} from snapshot {}",
        entry.file_path, entry.id
    ))
}

/// List snapshots for a session in a human-readable format.
pub fn list_snapshots(snapshot_dir: &Path, session_id: &str) -> Result<Vec<String>, String> {
    let manifest = read_manifest(snapshot_dir, session_id)?;

    Ok(manifest
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let state = if e.existed { "modified" } else { "created" };
            format!(
                "  {}. [{}] {} — {} ({})",
                i + 1,
                e.id,
                e.timestamp,
                e.file_path,
                state
            )
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::capture::capture_snapshot;

    #[test]
    fn test_rollback_restores_file() {
        let dir = tempfile::tempdir().unwrap();
        let snap_dir = tempfile::tempdir().unwrap();

        let target = dir.path().join("test.txt");
        fs::write(&target, "original content").unwrap();

        // Snapshot the original
        let entry = capture_snapshot(
            snap_dir.path(),
            "session-1",
            "tool-1",
            target.to_str().unwrap(),
        )
        .unwrap();

        // Simulate the agent modifying the file
        fs::write(&target, "agent modified this").unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "agent modified this");

        // Rollback
        rollback_by_id(snap_dir.path(), "session-1", &entry.id).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "original content");
    }

    #[test]
    fn test_rollback_removes_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let snap_dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("new_file.txt");

        // Snapshot before creation (file doesn't exist)
        let entry = capture_snapshot(
            snap_dir.path(),
            "session-1",
            "tool-1",
            target.to_str().unwrap(),
        )
        .unwrap();

        // Simulate agent creating the file
        fs::write(&target, "new content").unwrap();
        assert!(target.exists());

        // Rollback should delete it
        rollback_by_id(snap_dir.path(), "session-1", &entry.id).unwrap();
        assert!(!target.exists());
    }

    #[test]
    fn test_rollback_steps() {
        let dir = tempfile::tempdir().unwrap();
        let snap_dir = tempfile::tempdir().unwrap();

        let target = dir.path().join("test.txt");

        // Version 1
        fs::write(&target, "v1").unwrap();
        capture_snapshot(snap_dir.path(), "s1", "t1", target.to_str().unwrap()).unwrap();

        // Version 2
        fs::write(&target, "v2").unwrap();
        capture_snapshot(snap_dir.path(), "s1", "t2", target.to_str().unwrap()).unwrap();

        // Version 3
        fs::write(&target, "v3").unwrap();
        capture_snapshot(snap_dir.path(), "s1", "t3", target.to_str().unwrap()).unwrap();

        // Agent writes v4
        fs::write(&target, "v4").unwrap();

        // Step back 1 → should restore v3
        rollback_steps(snap_dir.path(), "s1", 1).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "v3");
    }

    #[test]
    fn test_rollback_one_step_undoes_a_whole_multi_file_patch() {
        let dir = tempfile::tempdir().unwrap();
        let snap_dir = tempfile::tempdir().unwrap();

        let old_path = dir.path().join("old.txt");
        let new_path = dir.path().join("new.txt");
        fs::write(&old_path, "original").unwrap();

        // One apply_patch renaming old.txt → new.txt: both files are snapshotted
        // under a single tool_use_id.
        capture_snapshot(snap_dir.path(), "s1", "patch-1", old_path.to_str().unwrap()).unwrap();
        capture_snapshot(snap_dir.path(), "s1", "patch-1", new_path.to_str().unwrap()).unwrap();
        fs::remove_file(&old_path).unwrap();
        fs::write(&new_path, "renamed").unwrap();

        // One step is one tool call, so it must undo the entire rename.
        rollback_steps(snap_dir.path(), "s1", 1).unwrap();

        assert_eq!(fs::read_to_string(&old_path).unwrap(), "original");
        assert!(!new_path.exists(), "destination should have been removed");
    }

    #[test]
    fn test_rollback_session() {
        let dir = tempfile::tempdir().unwrap();
        let snap_dir = tempfile::tempdir().unwrap();

        let file_a = dir.path().join("a.txt");
        let file_b = dir.path().join("b.txt");

        fs::write(&file_a, "original a").unwrap();
        fs::write(&file_b, "original b").unwrap();

        capture_snapshot(snap_dir.path(), "s1", "t1", file_a.to_str().unwrap()).unwrap();
        capture_snapshot(snap_dir.path(), "s1", "t2", file_b.to_str().unwrap()).unwrap();

        // Agent modifies both
        fs::write(&file_a, "modified a").unwrap();
        fs::write(&file_b, "modified b").unwrap();

        // Rollback entire session
        rollback_session(snap_dir.path(), "s1").unwrap();
        assert_eq!(fs::read_to_string(&file_a).unwrap(), "original a");
        assert_eq!(fs::read_to_string(&file_b).unwrap(), "original b");
    }
}
