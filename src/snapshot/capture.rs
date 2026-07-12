use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

use crate::types::SnapshotEntry;

/// Capture a snapshot of a file before it gets modified.
/// Returns the snapshot entry, or None if the file doesn't exist (new file creation).
pub fn capture_snapshot(
    snapshot_dir: &Path,
    session_id: &str,
    tool_use_id: &str,
    file_path: &str,
) -> Result<SnapshotEntry, String> {
    let session_dir = snapshot_dir.join(session_id);
    fs::create_dir_all(&session_dir)
        .map_err(|e| format!("Failed to create snapshot dir: {}", e))?;

    let file_path_expanded = expand_home(file_path);
    let target = Path::new(&file_path_expanded);
    let existed = target.exists();

    let (hash, content) = if existed {
        let content =
            fs::read(target).map_err(|e| format!("Failed to read file for snapshot: {}", e))?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let hash = hex::encode(hasher.finalize());
        (hash, Some(content))
    } else {
        ("__new_file_____0".to_string(), None)
    };

    // Write snapshot file
    if let Some(content) = content {
        let snap_path = session_dir.join(format!("{}.snapshot", &hash[..16]));
        if !snap_path.exists() {
            fs::write(&snap_path, &content)
                .map_err(|e| format!("Failed to write snapshot: {}", e))?;
        }
    }

    let entry = SnapshotEntry {
        id: uuid::Uuid::new_v4().to_string()[..8].to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        session_id: session_id.to_string(),
        tool_use_id: tool_use_id.to_string(),
        file_path: file_path.to_string(),
        hash: hash[..16].to_string(),
        existed,
    };

    // Append to manifest
    append_manifest(&session_dir, &entry)?;

    Ok(entry)
}

/// Append a snapshot entry to the session manifest.
fn append_manifest(session_dir: &Path, entry: &SnapshotEntry) -> Result<(), String> {
    let manifest_path = session_dir.join("manifest.jsonl");
    let line = serde_json::to_string(entry)
        .map_err(|e| format!("Failed to serialize manifest entry: {}", e))?;

    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&manifest_path)
        .map_err(|e| format!("Failed to open manifest: {}", e))?;

    use std::io::Write;
    writeln!(file, "{}", line).map_err(|e| format!("Failed to write manifest: {}", e))?;

    Ok(())
}

/// Read the manifest for a session.
pub fn read_manifest(snapshot_dir: &Path, session_id: &str) -> Result<Vec<SnapshotEntry>, String> {
    let manifest_path = snapshot_dir.join(session_id).join("manifest.jsonl");
    if !manifest_path.exists() {
        return Ok(vec![]);
    }

    let contents = fs::read_to_string(&manifest_path)
        .map_err(|e| format!("Failed to read manifest: {}", e))?;

    let entries: Vec<SnapshotEntry> = contents
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();

    Ok(entries)
}

fn expand_home(path: &str) -> String {
    if path.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            return format!("{}{}", home.display(), &path[1..]);
        }
    }
    path.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capture_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let snap_dir = tempfile::tempdir().unwrap();

        // Create a file to snapshot
        let target = dir.path().join("test.txt");
        fs::write(&target, "hello world").unwrap();

        let entry = capture_snapshot(
            snap_dir.path(),
            "session-1",
            "tool-1",
            target.to_str().unwrap(),
        )
        .unwrap();

        assert!(entry.existed);
        assert_ne!(entry.hash, "__new_file__");
        assert_eq!(entry.session_id, "session-1");

        // Verify snapshot file exists
        let snap_file = snap_dir
            .path()
            .join("session-1")
            .join(format!("{}.snapshot", entry.hash));
        assert!(snap_file.exists());

        // Verify manifest
        let manifest = read_manifest(snap_dir.path(), "session-1").unwrap();
        assert_eq!(manifest.len(), 1);
    }

    #[test]
    fn test_capture_new_file() {
        let snap_dir = tempfile::tempdir().unwrap();

        let entry = capture_snapshot(
            snap_dir.path(),
            "session-1",
            "tool-1",
            "/tmp/nonexistent_file_railguard_test.txt",
        )
        .unwrap();

        assert!(!entry.existed);
        assert!(!entry.existed);
    }

    #[test]
    fn test_multiple_snapshots() {
        let dir = tempfile::tempdir().unwrap();
        let snap_dir = tempfile::tempdir().unwrap();

        let target = dir.path().join("test.txt");
        fs::write(&target, "version 1").unwrap();
        capture_snapshot(
            snap_dir.path(),
            "session-1",
            "tool-1",
            target.to_str().unwrap(),
        )
        .unwrap();

        fs::write(&target, "version 2").unwrap();
        capture_snapshot(
            snap_dir.path(),
            "session-1",
            "tool-2",
            target.to_str().unwrap(),
        )
        .unwrap();

        let manifest = read_manifest(snap_dir.path(), "session-1").unwrap();
        assert_eq!(manifest.len(), 2);
        assert_ne!(manifest[0].hash, manifest[1].hash);
    }
}
