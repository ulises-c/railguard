use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Persistent session state for threat detection.
/// Stored at `.railguard/state/{session_id}.json`.
/// Each hook invocation loads, modifies, and saves this state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub session_id: String,
    pub tool_call_count: u64,
    pub suspicion_level: u32, // 0=normal, 1=warned, 2=heightened
    pub warning_count: u32,
    pub block_history: Vec<BlockEvent>,
    /// Tool call count at which heightened mode expires
    pub heightened_until_call: Option<u64>,
    /// Keywords to watch for during heightened state
    pub heightened_keywords: Vec<String>,
    /// Threat patterns the user has approved for this session.
    /// Once approved, the same pattern won't prompt again.
    #[serde(default)]
    pub session_approvals: Vec<String>,
    /// Pattern currently awaiting user approval via "ask", and the `tool_use_id`
    /// of the call that asked.
    ///
    /// The id is what makes the answer knowable. This used to resolve on the mere
    /// arrival of a later tool call, on the theory that a next call proved the
    /// human had approved — but a human who clicks *deny* also goes on to make
    /// other tool calls, so a denial silently became a session-wide approval.
    #[serde(default)]
    pub pending_approval: Option<String>,
    #[serde(default)]
    pub pending_approval_tool_use_id: Option<String>,
    /// Project root captured when the session was anchored (SessionStart, or
    /// first PreToolUse for sessions without a SessionStart hook). The path
    /// fence evaluates against this instead of the per-call cwd, which drifts
    /// as the agent cd's around the repo.
    #[serde(default)]
    pub project_root: Option<String>,
    pub terminated: bool,
    pub termination_reason: Option<String>,
    pub termination_timestamp: Option<String>,
}

/// Where `resolve_project_root_with_source` found the anchor. Everything except
/// `CwdFallback` is trustworthy enough to persist as the session's sticky root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootSource {
    LocalState,
    Pointer,
    GitAncestor,
    CwdFallback,
}

impl RootSource {
    /// True when the resolved root may be persisted into local state and the
    /// global pointer. A `CwdFallback` root is just the current cwd with no repo
    /// evidence, so persisting it would make a one-time drift stick forever.
    pub fn is_trustworthy(self) -> bool {
        !matches!(self, RootSource::CwdFallback)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEvent {
    pub timestamp: String,
    pub tool_call_count: u64,
    pub command: String,
    pub rule: String,
    pub keywords: Vec<String>,
    pub tier: u8,
}

impl SessionState {
    pub fn new(session_id: &str) -> Self {
        SessionState {
            session_id: session_id.to_string(),
            tool_call_count: 0,
            suspicion_level: 0,
            warning_count: 0,
            block_history: Vec::new(),
            heightened_until_call: None,
            heightened_keywords: Vec::new(),
            session_approvals: Vec::new(),
            pending_approval: None,
            pending_approval_tool_use_id: None,
            project_root: None,
            terminated: false,
            termination_reason: None,
            termination_timestamp: None,
        }
    }

    fn state_path(state_dir: &Path, session_id: &str) -> PathBuf {
        state_dir.join(format!("{}.json", session_id))
    }

    /// Find the project root for a session: the nearest ancestor of `cwd`
    /// containing `.git` (a dir, or a file for worktrees/submodules), falling
    /// back to `cwd` itself outside a git repo.
    pub fn find_project_root(cwd: &Path) -> PathBuf {
        Self::find_git_root(cwd).unwrap_or_else(|| cwd.to_path_buf())
    }

    /// The nearest ancestor of `cwd` containing `.git`, or `None` outside a git
    /// repo. Unlike `find_project_root`, this distinguishes "found a real repo
    /// root" from "fell back to cwd" — the caller decides whether the result is
    /// trustworthy enough to persist as the session anchor.
    fn find_git_root(cwd: &Path) -> Option<PathBuf> {
        let mut dir = cwd.to_path_buf();
        loop {
            if dir.join(".git").exists() {
                return Some(dir);
            }
            if !dir.pop() {
                return None;
            }
        }
    }

    /// A trustworthy session anchor must be an absolute path (never the
    /// filesystem root `/`) that CURRENTLY resolves to a real git project root —
    /// i.e. it still contains a `.git`. Requiring `.git` evidence rejects, with
    /// one check, every way a bad root can reach the resolver: the bare `/`
    /// anchor, broad non-project dirs like `/home` or `/tmp`, a poisoned state
    /// file or pointer pointing somewhere with no repo, and a stale root whose
    /// directory was moved or deleted. None of those carry a `.git`, so none can
    /// widen the fence. A non-git project simply never gets a sticky anchor and
    /// resolves per-call from cwd instead.
    fn is_valid_anchor(root: &Path) -> bool {
        root.is_absolute() && root != Path::new("/") && root.join(".git").exists()
    }

    /// The trustworthy anchor to persist for a session whose cwd is `cwd`, or
    /// `None` when cwd is not inside a valid git project. Both SessionStart and
    /// the PreToolUse back-fill use this so the "never persist an untrustworthy
    /// root" invariant is enforced identically in every writer.
    pub fn anchor_to_persist(cwd: &Path) -> Option<PathBuf> {
        Self::find_git_root(cwd).filter(|r| Self::is_valid_anchor(r))
    }

    /// Locate the state dir holding this session's state file by walking up
    /// from `cwd`. The shell cwd persists across tool calls, so after a `cd`
    /// into a subdirectory the state created at the project root would
    /// otherwise not be found. Falls back to the project root for new sessions.
    pub fn locate_state_dir(cwd: &Path, session_id: &str) -> PathBuf {
        let mut dir = cwd.to_path_buf();
        loop {
            let candidate = dir.join(".railguard/state");
            if Self::state_path(&candidate, session_id).exists() {
                return candidate;
            }
            if !dir.pop() {
                return Self::find_project_root(cwd).join(".railguard/state");
            }
        }
    }

    /// Persist the session → project-root pointer to the global, cwd-independent
    /// registry (`~/.railguard/sessions/<session_id>`). Plain text: a single
    /// line holding the project root. Best-effort — never fails the hook.
    pub fn write_global_pointer(sessions_dir: &Path, session_id: &str, project_root: &Path) {
        if fs::create_dir_all(sessions_dir).is_err() {
            return;
        }
        let path = sessions_dir.join(session_id);
        let tmp_path = path.with_extension("tmp");
        if fs::write(&tmp_path, project_root.display().to_string()).is_ok() {
            let _ = fs::rename(&tmp_path, &path);
        }
    }

    /// Read the global project-root pointer for a session, if present.
    pub fn read_global_pointer(sessions_dir: &Path, session_id: &str) -> Option<PathBuf> {
        let path = sessions_dir.join(session_id);
        let contents = fs::read_to_string(path).ok()?;
        let trimmed = contents.trim();
        if trimmed.is_empty() {
            return None;
        }
        Some(PathBuf::from(trimmed))
    }

    /// Resolve the session's stable project root — the single anchor for both
    /// policy resolution and the path fence. See `resolve_project_root_with_source`.
    pub fn resolve_project_root(cwd: &Path, session_id: &str, sessions_dir: &Path) -> PathBuf {
        Self::resolve_project_root_with_source(cwd, session_id, sessions_dir).0
    }

    /// Resolve the anchor and report where it came from. Precedence:
    ///   1. cwd-walked session state (fast path; cwd still at/below the root),
    ///   2. the global pointer keyed by session_id (cwd has drifted outside the
    ///      project subtree, so the walk-up in step 1 can't find the state),
    ///   3. the nearest `.git` ancestor of cwd (a real repo root), else
    ///   4. cwd itself — an UNTRUSTWORTHY fallback for a brand-new session whose
    ///      first call is already outside any repo. The caller must not persist
    ///      this as the session anchor, or a one-time cwd drift would stick.
    ///
    /// Every trustworthy tier (1–3) is gated by `is_valid_anchor`, so a stored
    /// or fallback root that no longer resolves to a real `.git` project — a
    /// poisoned/stale state file or pointer, `/`, or a broad dir like `/home` —
    /// is skipped and resolution falls through to a safer source rather than
    /// widening the fence. Only `CwdFallback` is returned unvalidated, and the
    /// caller must never persist it.
    pub fn resolve_project_root_with_source(
        cwd: &Path,
        session_id: &str,
        sessions_dir: &Path,
    ) -> (PathBuf, RootSource) {
        let state_dir = Self::locate_state_dir(cwd, session_id);
        if let Some(root) = Self::load(&state_dir, session_id).project_root {
            let root = PathBuf::from(root);
            if Self::is_valid_anchor(&root) {
                return (root, RootSource::LocalState);
            }
        }
        if let Some(root) = Self::read_global_pointer(sessions_dir, session_id) {
            if Self::is_valid_anchor(&root) {
                return (root, RootSource::Pointer);
            }
        }
        match Self::find_git_root(cwd) {
            Some(root) if Self::is_valid_anchor(&root) => (root, RootSource::GitAncestor),
            _ => (cwd.to_path_buf(), RootSource::CwdFallback),
        }
    }

    pub fn load(state_dir: &Path, session_id: &str) -> Self {
        let path = Self::state_path(state_dir, session_id);
        if path.exists() {
            if let Ok(data) = fs::read_to_string(&path) {
                if let Ok(state) = serde_json::from_str::<SessionState>(&data) {
                    return state;
                }
            }
        }
        Self::new(session_id)
    }

    /// Atomic save: write to .tmp then rename.
    pub fn save(&self, state_dir: &Path) -> Result<(), String> {
        fs::create_dir_all(state_dir).map_err(|e| format!("create state dir: {}", e))?;

        let path = Self::state_path(state_dir, &self.session_id);
        let tmp_path = path.with_extension("json.tmp");

        let data =
            serde_json::to_string_pretty(self).map_err(|e| format!("serialize state: {}", e))?;

        fs::write(&tmp_path, data).map_err(|e| format!("write state: {}", e))?;
        fs::rename(&tmp_path, &path).map_err(|e| format!("rename state: {}", e))?;

        Ok(())
    }

    pub fn increment_tool_call(&mut self) {
        self.tool_call_count += 1;
    }

    pub fn record_block(&mut self, command: &str, rule: &str, keywords: Vec<String>, tier: u8) {
        self.block_history.push(BlockEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            tool_call_count: self.tool_call_count,
            command: command.chars().take(500).collect(),
            rule: rule.to_string(),
            keywords: keywords.clone(),
            tier,
        });

        // Enter heightened state: watch for keywords in next 3 tool calls
        self.heightened_until_call = Some(self.tool_call_count + 3);
        self.heightened_keywords = keywords;
    }

    pub fn record_warning(&mut self) {
        self.warning_count += 1;
        if self.suspicion_level < 1 {
            self.suspicion_level = 1;
        }
    }

    pub fn is_in_heightened_state(&self) -> bool {
        if let Some(until) = self.heightened_until_call {
            self.tool_call_count <= until
        } else {
            false
        }
    }

    /// Promote a pending approval, but only on proof that the human said yes.
    ///
    /// The proof is a `PostToolUse` event for the same `tool_use_id` we asked
    /// about: the tool only runs after an approval, so a denied call never
    /// produces one. A mismatched or absent id leaves the pending approval in
    /// place, where it expires unused — the failure direction is "ask again".
    pub fn resolve_pending_approval_for(&mut self, tool_use_id: Option<&str>) -> bool {
        let Some(id) = tool_use_id else {
            return false;
        };
        if self.pending_approval_tool_use_id.as_deref() != Some(id) {
            return false;
        }
        self.pending_approval_tool_use_id = None;
        match self.pending_approval.take() {
            Some(pattern) => {
                if !self.session_approvals.contains(&pattern) {
                    self.session_approvals.push(pattern);
                }
                true
            }
            None => false,
        }
    }

    /// Check if a threat pattern has been approved by the user this session.
    pub fn is_approved(&self, pattern: &str) -> bool {
        self.session_approvals.iter().any(|p| p == pattern)
    }

    /// Set a pattern as pending user approval, tagged with the call that asked.
    pub fn set_pending_approval(&mut self, pattern: &str, tool_use_id: Option<&str>) {
        self.pending_approval = Some(pattern.to_string());
        self.pending_approval_tool_use_id = tool_use_id.map(str::to_string);
    }

    pub fn mark_terminated(&mut self, reason: &str) {
        self.terminated = true;
        self.termination_reason = Some(reason.to_string());
        self.termination_timestamp = Some(chrono::Utc::now().to_rfc3339());
    }

    /// Clear a termination along with the threat history behind it.
    ///
    /// This is the only recovery path for a client that cannot answer an
    /// interactive approval prompt: Codex hooks can't ask, so a terminated
    /// Codex session would otherwise stay blocked forever.
    pub fn clear_termination(&mut self) {
        self.terminated = false;
        self.termination_reason = None;
        self.termination_timestamp = None;
        self.suspicion_level = 0;
        self.warning_count = 0;
        self.block_history.clear();
        self.heightened_keywords.clear();
        self.pending_approval = None;
    }

    /// Check all state files for recently terminated sessions.
    pub fn find_recent_terminations(state_dir: &Path) -> Vec<SessionState> {
        let mut terminated = Vec::new();

        if let Ok(entries) = fs::read_dir(state_dir) {
            for entry in entries.flatten() {
                if let Ok(data) = fs::read_to_string(entry.path()) {
                    if let Ok(state) = serde_json::from_str::<SessionState>(&data) {
                        if state.terminated {
                            terminated.push(state);
                        }
                    }
                }
            }
        }

        terminated
    }

    /// Clean up state files older than 24 hours.
    pub fn cleanup_old_states(state_dir: &Path) {
        Self::cleanup_old_files(state_dir);
    }

    /// Clean up global session pointers older than 24 hours.
    pub fn cleanup_old_pointers(sessions_dir: &Path) {
        Self::cleanup_old_files(sessions_dir);
    }

    fn cleanup_old_files(dir: &Path) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    if let Ok(modified) = meta.modified() {
                        if let Ok(age) = modified.elapsed() {
                            if age.as_secs() > 86400 {
                                let _ = fs::remove_file(entry.path());
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_state() {
        let state = SessionState::new("test-123");
        assert_eq!(state.session_id, "test-123");
        assert_eq!(state.tool_call_count, 0);
        assert!(!state.terminated);
    }

    #[test]
    fn test_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = SessionState::new("save-test");
        state.tool_call_count = 5;
        state.warning_count = 2;
        state.save(dir.path()).unwrap();

        let loaded = SessionState::load(dir.path(), "save-test");
        assert_eq!(loaded.tool_call_count, 5);
        assert_eq!(loaded.warning_count, 2);
    }

    #[test]
    fn test_heightened_state() {
        let mut state = SessionState::new("heightened");
        state.tool_call_count = 10;
        assert!(!state.is_in_heightened_state());

        state.record_block(
            "terraform destroy",
            "terraform-destroy",
            vec!["terraform".into(), "destroy".into()],
            1,
        );
        assert!(state.is_in_heightened_state());

        // Still heightened at call 12 (10 + 3 = 13)
        state.tool_call_count = 12;
        assert!(state.is_in_heightened_state());

        // No longer heightened at call 14
        state.tool_call_count = 14;
        assert!(!state.is_in_heightened_state());
    }

    #[test]
    fn test_find_project_root_walks_to_git() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        let nested = dir.path().join("packages/app");
        std::fs::create_dir_all(&nested).unwrap();
        assert_eq!(SessionState::find_project_root(&nested), dir.path());
    }

    #[test]
    fn test_locate_state_dir_walks_up_from_nested_cwd() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("packages/app");
        std::fs::create_dir_all(&nested).unwrap();
        let state_dir = root.path().join(".railguard/state");
        SessionState::new("walkup-test").save(&state_dir).unwrap();
        assert_eq!(
            SessionState::locate_state_dir(&nested, "walkup-test"),
            state_dir
        );
    }

    #[test]
    fn test_locate_state_dir_new_session_uses_project_root() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".git")).unwrap();
        let nested = root.path().join("src");
        std::fs::create_dir_all(&nested).unwrap();
        assert_eq!(
            SessionState::locate_state_dir(&nested, "fresh-session"),
            root.path().join(".railguard/state")
        );
    }

    #[test]
    fn test_global_pointer_roundtrip() {
        let sessions = tempfile::tempdir().unwrap();
        assert_eq!(
            SessionState::read_global_pointer(sessions.path(), "missing"),
            None
        );
        SessionState::write_global_pointer(sessions.path(), "sid-1", Path::new("/repo/root"));
        assert_eq!(
            SessionState::read_global_pointer(sessions.path(), "sid-1"),
            Some(PathBuf::from("/repo/root"))
        );
    }

    #[test]
    fn test_resolve_project_root_prefers_cwd_state() {
        // cwd at/below the root: local state's project_root wins (fast path).
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".git")).unwrap();
        let sessions = tempfile::tempdir().unwrap();
        let state_dir = root.path().join(".railguard/state");
        let mut state = SessionState::new("resolve-state");
        state.project_root = Some(root.path().display().to_string());
        state.save(&state_dir).unwrap();
        // A conflicting pointer must be ignored while local state resolves.
        SessionState::write_global_pointer(sessions.path(), "resolve-state", Path::new("/wrong"));

        let (resolved, source) = SessionState::resolve_project_root_with_source(
            root.path(),
            "resolve-state",
            sessions.path(),
        );
        assert_eq!(resolved, root.path());
        assert_eq!(source, RootSource::LocalState);
    }

    #[test]
    fn test_resolve_project_root_falls_back_to_global_pointer() {
        // cwd drifted outside the subtree: local state isn't found, so the
        // global pointer supplies the stable root (a real git project).
        let real = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(real.path().join(".git")).unwrap();
        let outside = tempfile::tempdir().unwrap();
        let sessions = tempfile::tempdir().unwrap();
        SessionState::write_global_pointer(sessions.path(), "resolve-ptr", real.path());

        let (resolved, source) = SessionState::resolve_project_root_with_source(
            outside.path(),
            "resolve-ptr",
            sessions.path(),
        );
        assert_eq!(resolved, real.path());
        assert_eq!(source, RootSource::Pointer);
    }

    #[test]
    fn test_resolve_project_root_falls_back_to_find_project_root() {
        // Neither local state nor a pointer: derive from cwd's nearest .git.
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".git")).unwrap();
        let nested = root.path().join("src");
        std::fs::create_dir_all(&nested).unwrap();
        let sessions = tempfile::tempdir().unwrap();

        assert_eq!(
            SessionState::resolve_project_root(&nested, "no-anchor", sessions.path()),
            root.path()
        );
    }

    #[test]
    fn test_resolve_cwd_fallback_is_untrustworthy() {
        // First call outside any repo: resolves to cwd but must be flagged
        // untrustworthy so the caller does not persist it as the sticky anchor.
        let outside = tempfile::tempdir().unwrap();
        let sessions = tempfile::tempdir().unwrap();
        let (root, source) = SessionState::resolve_project_root_with_source(
            outside.path(),
            "fresh",
            sessions.path(),
        );
        assert_eq!(root, outside.path());
        assert_eq!(source, RootSource::CwdFallback);
        assert!(!source.is_trustworthy());
    }

    #[test]
    fn test_resolve_skips_implausible_state_root() {
        // A poisoned local-state project_root with no real .git (here a broad,
        // non-repo path) must be ignored so the fence is not widened to that
        // whole subtree; resolution falls through to the real git ancestor.
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".git")).unwrap();
        let state_dir = root.path().join(".railguard/state");
        let mut state = SessionState::new("poisoned");
        // The temp parent exists but is not a git repo — the kind of broad root
        // (cf. "/", "/home", "/tmp") a poisoned/garbage anchor would name.
        state.project_root = Some(root.path().parent().unwrap().display().to_string());
        state.save(&state_dir).unwrap();
        let sessions = tempfile::tempdir().unwrap();

        let (resolved, source) = SessionState::resolve_project_root_with_source(
            root.path(),
            "poisoned",
            sessions.path(),
        );
        assert_eq!(resolved, root.path());
        assert_eq!(source, RootSource::GitAncestor);
    }

    #[test]
    fn test_is_valid_anchor_requires_git_evidence() {
        // Rejects "/", non-absolute, and any dir without a .git marker.
        assert!(!SessionState::is_valid_anchor(Path::new("/")));
        assert!(!SessionState::is_valid_anchor(Path::new("relative/path")));
        let no_git = tempfile::tempdir().unwrap();
        assert!(!SessionState::is_valid_anchor(no_git.path()));
        let with_git = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(with_git.path().join(".git")).unwrap();
        assert!(SessionState::is_valid_anchor(with_git.path()));
    }

    #[test]
    fn test_anchor_to_persist_only_inside_git_project() {
        // A bare cwd outside any repo is not a persistable anchor.
        let no_git = tempfile::tempdir().unwrap();
        assert_eq!(SessionState::anchor_to_persist(no_git.path()), None);
        // Inside a repo, the git root is returned (even from a subdir).
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join(".git")).unwrap();
        let nested = repo.path().join("a/b");
        std::fs::create_dir_all(&nested).unwrap();
        assert_eq!(
            SessionState::anchor_to_persist(&nested),
            Some(repo.path().to_path_buf())
        );
    }

    #[test]
    fn test_cleanup_removes_stale_pointer_keeps_fresh() {
        use std::time::{Duration, SystemTime};
        let sessions = tempfile::tempdir().unwrap();
        SessionState::write_global_pointer(sessions.path(), "stale", Path::new("/repo/a"));
        SessionState::write_global_pointer(sessions.path(), "fresh", Path::new("/repo/b"));

        // Backdate the "stale" pointer to 25h ago.
        let old = SystemTime::now() - Duration::from_secs(25 * 3600);
        let f = std::fs::File::options()
            .write(true)
            .open(sessions.path().join("stale"))
            .unwrap();
        f.set_modified(old).unwrap();

        SessionState::cleanup_old_pointers(sessions.path());
        assert!(
            !sessions.path().join("stale").exists(),
            "stale pointer should be reaped"
        );
        assert!(
            sessions.path().join("fresh").exists(),
            "fresh pointer must survive"
        );
    }

    #[test]
    fn test_project_root_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = SessionState::new("anchor-test");
        state.project_root = Some("/repo".to_string());
        state.save(dir.path()).unwrap();
        let loaded = SessionState::load(dir.path(), "anchor-test");
        assert_eq!(loaded.project_root.as_deref(), Some("/repo"));
    }

    #[test]
    fn test_clear_termination_restores_a_clean_slate() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = SessionState::new("stuck");
        state.record_block("rev <<< x | sh", "evasion", vec!["sh".to_string()], 3);
        state.set_pending_approval("evasion", Some("call-1"));
        state.mark_terminated("evasion detected");
        state.save(dir.path()).unwrap();

        let mut reloaded = SessionState::load(dir.path(), "stuck");
        assert!(reloaded.terminated);
        reloaded.clear_termination();
        reloaded.save(dir.path()).unwrap();

        // Codex cannot answer the resume prompt, so `railguard resume` is the
        // only way out — it must leave nothing behind that re-blocks the session.
        let after = SessionState::load(dir.path(), "stuck");
        assert!(!after.terminated);
        assert!(after.termination_reason.is_none());
        assert!(after.pending_approval.is_none());
        assert!(after.block_history.is_empty());
        assert_eq!(after.warning_count, 0);
        assert_eq!(after.suspicion_level, 0);
    }

    #[test]
    fn test_terminated_state() {
        let mut state = SessionState::new("terminated");
        state.mark_terminated("evasion detected: rev | sh");
        assert!(state.terminated);
        assert!(state
            .termination_reason
            .as_deref()
            .unwrap()
            .contains("rev | sh"));
    }
}
