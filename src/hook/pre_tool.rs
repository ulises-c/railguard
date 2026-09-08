use std::path::Path;
use std::time::Instant;

use regex::Regex;

use crate::block::evasion;
use crate::fence::path::{check_path, extract_file_path, PathCheck};
use crate::memory::guard as memory_guard;
use crate::policy::engine::evaluate;
use crate::snapshot::capture::capture_snapshot;
use crate::threat::classifier::{
    check_behavioral_evasion, classify_threat, extract_keywords, ThreatTier,
};
use crate::threat::state::SessionState;
use crate::trace::logger::log_trace;
use crate::types::{Decision, HookInput, HookOutput, MemoryDecision, Policy, TraceEntry};

/// Result of handling a PreToolUse event.
/// If `terminate` is Some, the caller should terminate the session.
pub struct PreToolResult {
    pub output: HookOutput,
    pub terminate: Option<TerminateRequest>,
}

pub struct TerminateRequest {
    pub tier: ThreatTier,
    pub command: String,
    pub state: SessionState,
}

/// Handle a PreToolUse event.
/// This is the critical path — every tool call passes through here.
pub fn handle(input: &HookInput, policy: &Policy) -> PreToolResult {
    let start = Instant::now();
    let tool_name = input.tool_name.as_deref().unwrap_or("unknown");
    let tool_input = input.tool_input.clone().unwrap_or_default();
    let cwd = Path::new(&input.cwd);

    // Load persistent session state (walk up — the shell cwd persists across
    // tool calls and may have drifted below the project root)
    let state_dir = SessionState::locate_state_dir(cwd, &input.session_id);
    let mut state = SessionState::load(&state_dir, &input.session_id);
    state.resolve_pending_approval();
    state.increment_tool_call();

    // The fence anchors to the session's stable project root, not the per-call
    // cwd. Resolve via the shared anchor (cwd-walked state → global pointer →
    // git ancestor → cwd) so a cwd that drifted outside the project subtree
    // still recovers the right root.
    let sessions_dir = crate::trace::logger::global_sessions_dir();
    let (resolved_root, root_source) =
        SessionState::resolve_project_root_with_source(cwd, &input.session_id, &sessions_dir);
    let fence_root = resolved_root.display().to_string();
    // Only persist a TRUSTWORTHY root (existing state/pointer, or a real .git
    // ancestor). A bare-cwd fallback — a session whose first call already drifted
    // outside any repo — must not be persisted, or that wrong root would stick
    // for the whole session. For a trustworthy root, (re)write the pointer every
    // call so its mtime tracks live activity and cleanup_old_pointers never reaps
    // a long-running session's anchor.
    if root_source.is_trustworthy() {
        state.project_root.get_or_insert_with(|| fence_root.clone());
        SessionState::write_global_pointer(
            &sessions_dir,
            &input.session_id,
            Path::new(&fence_root),
        );
    }

    // If session was previously terminated, ask user before resuming
    if state.terminated {
        let reason = state
            .termination_reason
            .clone()
            .unwrap_or_else(|| "evasion detection".to_string());
        if state.is_approved("session-resume") {
            // User already approved resuming — clear terminated state
            state.terminated = false;
            state.termination_reason = None;
            state.termination_timestamp = None;
            state.suspicion_level = 0;
            state.warning_count = 0;
            state.block_history.clear();
            state.heightened_keywords.clear();
            state.heightened_anchors.clear();
            let _ = state.save(&state_dir);
            // Fall through to normal evaluation
        } else {
            state.set_pending_approval("session-resume");
            let _ = state.save(&state_dir);
            return PreToolResult {
                output: HookOutput::ask(&format!(
                    "🛡️ RAILGUARD is asking (not Claude Code's permission system).\n\
                     \n\
                     This session was previously terminated because:\n\
                     {}\n\
                     \n\
                     Approve to resume this session (threat state will be reset), \
                     or deny to keep it blocked.",
                    reason
                )),
                terminate: None,
            };
        }
    }

    // Extract command for Bash tools
    let command = if tool_name == "Bash" {
        tool_input
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    } else {
        String::new()
    };

    // === THREAT DETECTION (before policy evaluation) ===

    if tool_name == "Bash" && !command.is_empty() {
        // Tier 3: Behavioral evasion (check BEFORE new blocks)
        if let Some(tier) = check_behavioral_evasion(&state, &command) {
            let pattern_key = match &tier {
                ThreatTier::Tier3 { original_rule, .. } => format!("tier3:{}", original_rule),
                _ => "tier3:unknown".to_string(),
            };

            if state.is_approved(&pattern_key) {
                // User already approved this pattern this session — allow
                log_decision(
                    input,
                    policy,
                    tool_name,
                    &tool_input,
                    "allow",
                    Some("session-approved"),
                    start,
                );
                let _ = state.save(&state_dir);
                return PreToolResult {
                    output: HookOutput::allow(),
                    terminate: None,
                };
            } else {
                let keywords = extract_keywords(&command);
                let anchors = state.heightened_anchors.clone();
                state.record_block_anchored(&command, "behavioral-evasion", keywords, anchors, 3);
                state.set_pending_approval(&pattern_key);
                let _ = state.save(&state_dir);

                let cmd_preview: String = command.chars().take(120).collect();
                return PreToolResult {
                    output: HookOutput::ask(&format!(
                        "🛡️ RAILGUARD is asking (not Claude Code's permission system).\n\
                         \n\
                         Behavioral evasion detected: a previously blocked command was \
                         retried with different syntax.\n\
                         Command: {}{}\n\
                         \n\
                         If this is a legitimate retry, approve to allow it for the rest of this session.",
                        cmd_preview,
                        if command.len() > 120 { "..." } else { "" }
                    )),
                    terminate: None,
                };
            }
        }

        // Tier 1 & 2: Pattern-based evasion detection
        if let Some(tier) = classify_threat(&command) {
            match &tier {
                ThreatTier::Tier1 { pattern } => {
                    let pattern_key = format!("tier1:{}", pattern);

                    if state.is_approved(&pattern_key) {
                        log_decision(
                            input,
                            policy,
                            tool_name,
                            &tool_input,
                            "allow",
                            Some("session-approved"),
                            start,
                        );
                        let _ = state.save(&state_dir);
                        let _ = state.save(&state_dir);
                        return PreToolResult {
                            output: HookOutput::allow(),
                            terminate: None,
                        };
                    } else {
                        let keywords = extract_keywords(&command);
                        state.record_block(&command, pattern, keywords, 1);
                        state.set_pending_approval(&pattern_key);
                        let _ = state.save(&state_dir);

                        let cmd_preview: String = command.chars().take(120).collect();
                        return PreToolResult {
                            output: HookOutput::ask(&format!(
                                "🛡️ RAILGUARD is asking (not Claude Code's permission system).\n\
                                 \n\
                                 Evasion pattern detected: {}\n\
                                 Command: {}{}\n\
                                 \n\
                                 This looks like it could be an obfuscation technique \
                                 (e.g. using chr(), base64, eval to construct commands at runtime). \
                                 If this is legitimate, approve to allow this pattern for the rest of this session.",
                                pattern,
                                cmd_preview,
                                if command.len() > 120 { "..." } else { "" }
                            )),
                            terminate: None,
                        };
                    }
                }

                ThreatTier::Tier2 { pattern } => {
                    let pattern_key = format!("tier2:{}", pattern);

                    if state.is_approved(&pattern_key) {
                        log_decision(
                            input,
                            policy,
                            tool_name,
                            &tool_input,
                            "allow",
                            Some("session-approved"),
                            start,
                        );
                        let _ = state.save(&state_dir);
                        return PreToolResult {
                            output: HookOutput::allow(),
                            terminate: None,
                        };
                    } else if state.warning_count >= 1 {
                        // Second occurrence: ask user instead of terminating
                        let keywords = extract_keywords(&command);
                        state.record_block(&command, pattern, keywords, 2);
                        state.set_pending_approval(&pattern_key);
                        let _ = state.save(&state_dir);

                        let cmd_preview: String = command.chars().take(120).collect();
                        return PreToolResult {
                            output: HookOutput::ask(&format!(
                                "🛡️ RAILGUARD is asking (not Claude Code's permission system).\n\
                                 \n\
                                 Repeated suspicious pattern: {}\n\
                                 Command: {}{}\n\
                                 \n\
                                 This pattern was seen before in this session. \
                                 Approve to allow it for the rest of this session.",
                                pattern,
                                cmd_preview,
                                if command.len() > 120 { "..." } else { "" }
                            )),
                            terminate: None,
                        };
                    } else {
                        // First occurrence: warn and continue to policy evaluation
                        state.record_warning();
                        log_decision(
                            input,
                            policy,
                            tool_name,
                            &tool_input,
                            "warn",
                            Some(&pattern_key),
                            start,
                        );
                    }
                }

                ThreatTier::Tier3 { .. } => {
                    // Tier 3 is handled above (behavioral check)
                }
            }
        }
    }

    // Evaluate hard policy blocks before the path fence. An outside-project
    // prompt must never downgrade a command that policy says is forbidden.
    let mut decision = evaluate(policy, tool_name, &tool_input);
    if tool_name == "Bash" {
        if let Decision::Block { rule, .. } = &decision {
            // The built-in settings tamper rule exists to stop writes to
            // Claude Code settings. A command that only reads them, or only
            // names the path in a data position (a heredoc body headed for a
            // data sink, a grep pattern), cannot write them and is waived.
            // The path fence still applies afterwards.
            if rule == "railguard-tamper-settings"
                && rule_regex(policy, rule)
                    .is_some_and(|re| is_inert_settings_mention(&command, &re))
            {
                decision = Decision::Allow;
            }
        }
    }
    if let Decision::Block { rule, message } = &decision {
        if tool_name == "Bash" && !command.is_empty() {
            let keywords = extract_keywords(&command);
            record_policy_block(&mut state, policy, &command, rule, keywords);
        }
        let _ = state.save(&state_dir);
        log_decision(
            input,
            policy,
            tool_name,
            &tool_input,
            "block",
            Some(rule),
            start,
        );
        return PreToolResult {
            output: HookOutput::deny(&format!("⛔ Railguard BLOCKED: {}", message)),
            terminate: None,
        };
    }

    // === MEMORY GUARD (before path fence, since ~/.claude is denied) ===

    if tool_name == "Bash" && memory_guard::is_memory_delete_command(&command) {
        let paths = evasion::extract_paths_from_command(&command);
        if paths
            .iter()
            .any(|path| memory_guard::is_memory_container_root(path))
        {
            let _ = state.save(&state_dir);
            log_decision(
                input,
                policy,
                tool_name,
                &tool_input,
                "block",
                Some("memory-container-root"),
                start,
            );
            return PreToolResult {
                output: HookOutput::deny(
                    "⛔ Railguard: Memory Safety: deleting ~/.claude or ~/.claude/projects is blocked.",
                ),
                terminate: None,
            };
        }
    }

    if policy.memory.enabled {
        // For Bash commands, check if they touch memory paths
        let memory_file_paths: Vec<String> = if tool_name == "Bash" {
            tool_input
                .get("command")
                .and_then(|v| v.as_str())
                .map(|cmd| {
                    let paths = evasion::extract_paths_from_command(cmd);
                    paths
                        .into_iter()
                        .filter(|path| memory_guard::is_memory_path(path))
                        .collect()
                })
                .unwrap_or_default()
        } else {
            extract_file_path(tool_name, &tool_input)
                .filter(|path| memory_guard::is_memory_path(path))
                .into_iter()
                .collect()
        };

        if let Some(mem_path) = memory_file_paths.first() {
            let result = memory_guard::check_memory_write(
                &policy.memory,
                tool_name,
                mem_path,
                &tool_input,
                &input.session_id,
                cwd,
            );
            match result {
                MemoryDecision::Allow => {
                    // Memory guard approved — skip path fence for this path
                    log_decision(
                        input,
                        policy,
                        tool_name,
                        &tool_input,
                        "allow",
                        Some("memory-guard"),
                        start,
                    );
                    let _ = state.save(&state_dir);

                    // Still do snapshot before Write/Edit
                    if policy.snapshot.enabled
                        && policy.snapshot.tools.iter().any(|t| t == tool_name)
                    {
                        if let Some(file_path) =
                            tool_input.get("file_path").and_then(|v| v.as_str())
                        {
                            // Anchor snapshots at the stable fence_root, not the
                            // per-call cwd: `railguard rollback` reads them from
                            // the project root, so a cwd-drifted Write/Edit's
                            // backup must still land under the project.
                            let snap_dir = Path::new(&fence_root).join(&policy.snapshot.directory);
                            let tool_use_id = input.tool_use_id.as_deref().unwrap_or("unknown");
                            let _ = capture_snapshot(
                                &snap_dir,
                                &input.session_id,
                                tool_use_id,
                                file_path,
                            );
                        }
                    }

                    return PreToolResult {
                        output: HookOutput::allow(),
                        terminate: None,
                    };
                }
                MemoryDecision::Block(reason) => {
                    let _ = state.save(&state_dir);
                    log_decision(
                        input,
                        policy,
                        tool_name,
                        &tool_input,
                        "block",
                        Some("memory-guard"),
                        start,
                    );
                    return PreToolResult {
                        output: HookOutput::deny(&format!("⛔ Railguard: {}", reason)),
                        terminate: None,
                    };
                }
                MemoryDecision::Approve(reason) => {
                    if tool_name == "Bash" && memory_guard::is_memory_delete_command(&command) {
                        let snap_dir = Path::new(&fence_root).join(&policy.snapshot.directory);
                        let tool_use_id = input.tool_use_id.as_deref().unwrap_or("unknown");
                        for path in &memory_file_paths {
                            let files = match memory_guard::files_to_snapshot(path) {
                                Ok(files) => files,
                                Err(error) => {
                                    return memory_snapshot_failure(
                                        input,
                                        policy,
                                        tool_name,
                                        &tool_input,
                                        &mut state,
                                        &state_dir,
                                        start,
                                        &error,
                                    );
                                }
                            };
                            for file in files {
                                if let Err(error) = capture_snapshot(
                                    &snap_dir,
                                    &input.session_id,
                                    tool_use_id,
                                    &file,
                                ) {
                                    return memory_snapshot_failure(
                                        input,
                                        policy,
                                        tool_name,
                                        &tool_input,
                                        &mut state,
                                        &state_dir,
                                        start,
                                        &error,
                                    );
                                }
                            }
                        }
                    }
                    let _ = state.save(&state_dir);
                    log_decision(
                        input,
                        policy,
                        tool_name,
                        &tool_input,
                        "approve",
                        Some("memory-guard"),
                        start,
                    );
                    return PreToolResult {
                        output: HookOutput::ask(&format!(
                            "🛡️ RAILGUARD is asking (not Claude Code's permission system).\n\
                             \n\
                             {}\n\
                             \n\
                             Railguard's memory guard requires approval for this memory change.",
                            reason
                        )),
                        terminate: None,
                    };
                }
            }
        }
    }

    // === PATH FENCE ===

    if tool_name == "Bash" {
        if let Some(cmd) = tool_input.get("command").and_then(|v| v.as_str()) {
            let paths = evasion::extract_paths_from_command(cmd);
            for path in &paths {
                match check_path(&policy.fence, path, &fence_root) {
                    PathCheck::Allow => {}
                    PathCheck::Denied(reason) => {
                        let keywords = extract_keywords(cmd);
                        state.record_block_anchored(
                            cmd,
                            "path-fence",
                            keywords,
                            anchors_from(cmd, [path.clone()]),
                            0,
                        );
                        let _ = state.save(&state_dir);
                        log_decision(
                            input,
                            policy,
                            tool_name,
                            &tool_input,
                            "block",
                            Some("path-fence"),
                            start,
                        );
                        return PreToolResult {
                            output: HookOutput::deny(&reason),
                            terminate: None,
                        };
                    }
                    PathCheck::OutsideProject(reason) => {
                        if is_read_only_command(cmd) || is_safe_worktree_removal(cmd) {
                            // Read-only commands and Git-safe worktree removal
                            // may operate outside the project without a prompt.
                        } else {
                            let _ = state.save(&state_dir);
                            log_decision(
                                input,
                                policy,
                                tool_name,
                                &tool_input,
                                "approve",
                                Some("path-fence"),
                                start,
                            );
                            return PreToolResult {
                                output: HookOutput::ask(&format!(
                                    "🛡️ RAILGUARD is asking (not Claude Code's permission system).\n\
                                     \n\
                                     {}\n\
                                     \n\
                                     Railguard's path fence requires approval for commands that \
                                     access files outside the project directory.",
                                    reason
                                )),
                                terminate: None,
                            };
                        }
                    }
                }
            }
        }
    } else if let Some(file_path) = extract_file_path(tool_name, &tool_input) {
        match check_path(&policy.fence, &file_path, &fence_root) {
            PathCheck::Allow => {}
            PathCheck::Denied(reason) => {
                let _ = state.save(&state_dir);
                log_decision(
                    input,
                    policy,
                    tool_name,
                    &tool_input,
                    "block",
                    Some("path-fence"),
                    start,
                );
                return PreToolResult {
                    output: HookOutput::deny(&reason),
                    terminate: None,
                };
            }
            PathCheck::OutsideProject(reason) => {
                if is_read_only_tool(tool_name) {
                    // Read-only tools outside project are fine
                } else {
                    let _ = state.save(&state_dir);
                    log_decision(
                        input,
                        policy,
                        tool_name,
                        &tool_input,
                        "approve",
                        Some("path-fence"),
                        start,
                    );
                    return PreToolResult {
                        output: HookOutput::ask(&format!(
                            "🛡️ RAILGUARD is asking (not Claude Code's permission system).\n\
                             \n\
                             {}\n\
                             \n\
                             Railguard's path fence requires approval for writes outside the project directory.",
                            reason
                        )),
                        terminate: None,
                    };
                }
            }
        }
    }

    // === POLICY EVALUATION (allowlist → blocklist → approve) ===

    match &decision {
        Decision::Allow => {
            // Coordination: acquire file lock for Write/Edit
            if matches!(tool_name, "Write" | "Edit") {
                if let Some(file_path) = tool_input.get("file_path").and_then(|v| v.as_str()) {
                    if let Some(deny_msg) =
                        crate::coord::context::check_file_conflict(file_path, &input.session_id)
                    {
                        log_decision(
                            input,
                            policy,
                            tool_name,
                            &tool_input,
                            "block",
                            Some("file-lock"),
                            start,
                        );
                        let _ = state.save(&state_dir);
                        return PreToolResult {
                            output: HookOutput::deny(&deny_msg),
                            terminate: None,
                        };
                    }
                }
            }

            // Snapshot before Write/Edit (if enabled)
            if policy.snapshot.enabled && policy.snapshot.tools.iter().any(|t| t == tool_name) {
                if let Some(file_path) = tool_input.get("file_path").and_then(|v| v.as_str()) {
                    // Anchor snapshots at the stable fence_root (see above): keeps
                    // backups under the project root that `railguard rollback` reads.
                    let snap_dir = Path::new(&fence_root).join(&policy.snapshot.directory);
                    let tool_use_id = input.tool_use_id.as_deref().unwrap_or("unknown");
                    if let Err(e) =
                        capture_snapshot(&snap_dir, &input.session_id, tool_use_id, file_path)
                    {
                        // silently ignore — stderr causes "hook error" in Claude Code
                        let _ = e;
                    }
                }
            }

            log_decision(input, policy, tool_name, &tool_input, "allow", None, start);
            let _ = state.save(&state_dir);
            PreToolResult {
                output: HookOutput::allow(),
                terminate: None,
            }
        }
        Decision::Block { rule, message } => {
            // Record block for behavioral tracking (Tier 3)
            if tool_name == "Bash" && !command.is_empty() {
                let keywords = extract_keywords(&command);
                record_policy_block(&mut state, policy, &command, rule, keywords);
            }
            let _ = state.save(&state_dir);
            log_decision(
                input,
                policy,
                tool_name,
                &tool_input,
                "block",
                Some(rule),
                start,
            );
            PreToolResult {
                output: HookOutput::deny(&format!("⛔ Railguard BLOCKED: {}", message)),
                terminate: None,
            }
        }
        Decision::Approve { rule, message } => {
            // Don't record a block for user-approved commands — the user is
            // explicitly consenting, so a similar follow-up command is not evasion.
            // Recording a block here would enter heightened state and cause false
            // Tier 3 triggers on legitimate repeated commands (e.g. fly ssh).
            let _ = state.save(&state_dir);
            log_decision(
                input,
                policy,
                tool_name,
                &tool_input,
                "approve",
                Some(rule),
                start,
            );
            PreToolResult {
                output: HookOutput::ask(&format!(
                    "🛡️ RAILGUARD is asking (not Claude Code's permission system).\n\
                     \n\
                     Rule: {} — {}\n\
                     \n\
                     This command matched a Railguard policy rule that requires human approval.",
                    rule, message
                )),
                terminate: None,
            }
        }
    }
}

fn log_decision(
    input: &HookInput,
    policy: &Policy,
    tool_name: &str,
    tool_input: &serde_json::Value,
    decision: &str,
    rule: Option<&str>,
    start: Instant,
) {
    if !policy.trace.enabled {
        return;
    }

    let trace_dir = crate::trace::logger::global_trace_dir();
    let input_summary = summarize_input(tool_name, tool_input);

    let entry = TraceEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        session_id: input.session_id.clone(),
        event: "PreToolUse".to_string(),
        tool: tool_name.to_string(),
        input_summary,
        decision: decision.to_string(),
        rule: rule.map(|s| s.to_string()),
        duration_ms: start.elapsed().as_millis() as u64,
    };

    if let Err(e) = log_trace(&trace_dir, &input.session_id, &entry) {
        let _ = e;
    }
}

/// Returns true if the tool is read-only (doesn't modify files).
fn is_read_only_tool(tool_name: &str) -> bool {
    matches!(tool_name, "Read" | "Glob" | "Grep")
}

/// Returns true if a bash command is read-only (cannot create or modify files).
///
/// Used only to waive the path-fence *prompt*: a command that can't write
/// outside the project shouldn't trigger an "approve?" on path-shaped text it
/// merely contains (sed/awk regex addresses, jq's `//` operator, URLs).
/// Reducing those false prompts is the point — prompt fatigue trains the human
/// to rubber-stamp everything. Since extraction became shell-word-level
/// (issue #17) most such text never reaches the fence; this waiver remains as
/// second-line defense for words that are wholly path-shaped yet still data
/// (a bare `'/foo/p'` sed program).
///
/// The check is conservative and inspects *every* segment of a compound
/// command. Looking at only the first token let `cd repo && sed -n '/fn/p' f`
/// slip through as non-read-only and get fenced on the `/fn` regex address.
/// Denied-path access is evaluated separately and is NOT waived here, so a
/// read of `~/.ssh` stays blocked regardless of this result.
fn is_read_only_command(cmd: &str) -> bool {
    // Heredoc bodies that only reach data sinks are prose, not commands, and
    // stderr / `/dev/null` redirects write no file. Neither may disqualify.
    let cmd = strip_harmless_redirects(&strip_data_heredocs(cmd));

    // Any remaining output redirect writes a file — never read-only. Checked up
    // front so a navigation prefix can't launder it, e.g.
    // `cd /tmp && echo x > ~/outside`.
    if cmd.contains('>') {
        return false;
    }

    // Every segment of a compound command (`&&`, `||`, `;`, `|`, newline) must
    // itself be read-only.
    segments(&cmd).into_iter().all(is_read_only_segment)
}

/// Only tools that inspect/read. A tool earns a spot here only if it cannot
/// create or modify a file without a shell redirect — and redirects are
/// rejected separately. Deliberately EXCLUDED, even though they are common in
/// read-only invocations: interpreters (`python`, `node`, `ruby`), `go`/`rustc`,
/// version control (`git`), and package managers (`cargo`, `npm`, `npx`,
/// `yarn`, `pnpm`, `bun`), and `xargs` (it runs an arbitrary downstream
/// command, e.g. `xargs rm`). Writing is a normal mode of operation for all of
/// these and their read-vs-write intent cannot be told from the leading token
/// (`git log` vs `git checkout`, `python -c "print(1)"` vs
/// `python -c "open(p,'w')"`), so they must keep prompting when they name a
/// path outside the project. Do not re-add them.
const READ_ONLY_COMMANDS: &[&str] = &[
    "find",
    "ls",
    "cat",
    "head",
    "tail",
    "less",
    "more",
    "wc",
    "file",
    "stat",
    "du",
    "df",
    "which",
    "whereis",
    "type",
    "grep",
    "rg",
    "ag",
    "ack",
    "fd",
    "tree",
    "realpath",
    "readlink",
    "basename",
    "dirname",
    "diff",
    "md5",
    "shasum",
    "sha256sum",
    "md5sum",
    "xxd",
    "hexdump",
    "strings",
    "jq",
    "yq",
    "sort",
    "uniq",
    "tr",
    "cut",
    "awk",
    "sed",
    "pwd",
    "env",
    "printenv",
    "uname",
    "whoami",
    "id",
    "date",
    "cal",
    "echo",
    "printf",
    "test",
    "[",
];

/// Heredoc consumers that treat their input purely as data. A body one of these
/// reads (`cat > notes.md <<'EOF'`, `grep -f - <<EOF`, `jq . <<EOF`) can name
/// any path without acting on it. Everything else — interpreters, shells,
/// `awk`, `sed`, `xargs`, unknown tools — is assumed to execute its input.
const HEREDOC_DATA_SINKS: &[&str] = &[
    "cat",
    "tee",
    "head",
    "tail",
    "wc",
    "grep",
    "rg",
    "sort",
    "uniq",
    "cut",
    "tr",
    "jq",
    "yq",
    "less",
    "more",
    "diff",
    "md5sum",
    "sha256sum",
    "shasum",
];

/// One segment is read-only when its command word is a read-only tool used
/// without a write-mode flag. `cd`/`pushd`/`popd` are navigation and don't
/// disqualify.
fn is_read_only_segment(seg: &str) -> bool {
    let tok = leading_command(seg);
    matches!(tok, "cd" | "pushd" | "popd")
        || (READ_ONLY_COMMANDS.contains(&tok) && !has_write_mode(tok, seg))
}

/// The command word of a segment: the first token that is not a transparent
/// wrapper (`rtk`, `rtk proxy`) or a `VAR=value` prefix.
fn leading_command(seg: &str) -> &str {
    seg.split_whitespace()
        .find(|tok| !matches!(*tok, "rtk" | "proxy") && !is_env_assignment(tok))
        .unwrap_or("")
}

fn is_env_assignment(tok: &str) -> bool {
    tok.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty() && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
    })
}

/// Drop stderr and `/dev/null` redirects (`2>&1`, `2>/dev/null`, `>/dev/null`):
/// they write no file and must not disqualify a read-only command.
fn strip_harmless_redirects(cmd: &str) -> String {
    Regex::new(r"[0-9]?>>?\s*(&[0-9]+|/dev/null)")
        .expect("static regex")
        .replace_all(cmd, " ")
        .into_owned()
}

/// Split a compound command at `;`, `|`, `&`, and newlines outside quotes, so a
/// connector inside a quoted program (`grep 'a|b'`, `-m "x; y"`) stays in its
/// segment. Segments are trimmed; empty ones are dropped.
fn segments(cmd: &str) -> Vec<&str> {
    split_outside_quotes(cmd, |b, i| {
        usize::from(matches!(b[i], b';' | b'|' | b'&' | b'\n'))
    })
    .into_iter()
    .map(|(_, piece)| piece.trim())
    .filter(|piece| !piece.is_empty())
    .collect()
}

/// Split `s` wherever `sep_len` reports a separator (its length in bytes) at an
/// unquoted position. Returns each piece with its byte offset in `s`.
fn split_outside_quotes(s: &str, sep_len: impl Fn(&[u8], usize) -> usize) -> Vec<(usize, &str)> {
    let b = s.as_bytes();
    let (mut in_single, mut in_double) = (false, false);
    let mut pieces = Vec::new();
    let (mut start, mut i) = (0, 0);
    while i < b.len() {
        match b[i] {
            b'\\' if !in_single => {
                i += 2;
                continue;
            }
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            _ if !in_single && !in_double => {
                let n = sep_len(b, i);
                if n > 0 {
                    pieces.push((start, &s[start..i]));
                    i += n;
                    start = i;
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }
    pieces.push((start, &s[start..]));
    pieces
}

/// Remove the bodies of heredocs whose pipeline only feeds data sinks (the
/// terminator line goes with them). A body an interpreter, shell, or unknown
/// tool consumes is code and stays verbatim, as does every operator line.
fn strip_data_heredocs(cmd: &str) -> String {
    let mut kept: Vec<&str> = Vec::new();
    // (delimiter, `<<-` strips leading tabs, body is data)
    let mut open: Option<(String, bool, bool)> = None;
    for line in cmd.split('\n') {
        if let Some((delim, strip_tabs, is_data)) = &open {
            let candidate = if *strip_tabs {
                line.trim_start_matches('\t')
            } else {
                line
            };
            if !*is_data {
                kept.push(line);
            }
            if candidate == delim {
                open = None;
            }
            continue;
        }
        kept.push(line);
        if let Some((op_start, delim, strip_tabs)) = find_heredoc_operator(line) {
            let is_data = heredoc_feeds_data_sinks(line, op_start);
            open = Some((delim, strip_tabs, is_data));
        }
    }
    kept.join("\n")
}

/// The first unquoted heredoc operator on a line: its byte offset, delimiter,
/// and whether it is the tab-stripping `<<-` form. Here-strings (`<<<`) and
/// quoted `<<` are not operators.
fn find_heredoc_operator(line: &str) -> Option<(usize, String, bool)> {
    let b = line.as_bytes();
    let (mut in_single, mut in_double) = (false, false);
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' if !in_single => {
                i += 2;
                continue;
            }
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'<' if !in_single && !in_double && b.get(i + 1) == Some(&b'<') => {
                if b.get(i + 2) == Some(&b'<') {
                    i += 3; // here-string
                    continue;
                }
                let mut j = i + 2;
                let strip_tabs = b.get(j) == Some(&b'-');
                if strip_tabs {
                    j += 1;
                }
                while matches!(b.get(j), Some(b' ') | Some(b'\t')) {
                    j += 1;
                }
                let rest = &line[j..];
                let delim: String = match rest.as_bytes().first() {
                    Some(b'\'') => rest[1..].split('\'').next().unwrap_or("").to_string(),
                    Some(b'"') => rest[1..].split('"').next().unwrap_or("").to_string(),
                    _ => rest
                        .trim_start_matches('\\')
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect(),
                };
                if !delim.is_empty() {
                    return Some((i, delim, strip_tabs));
                }
                i += 2;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// True when every stage of the pipeline that owns the heredoc operator at
/// `op_start` is a data sink. The pipeline is the `;` / `&&` / `||` / `&`
/// delimited chunk of the line containing the operator, split on `|`.
fn heredoc_feeds_data_sinks(line: &str, op_start: usize) -> bool {
    let list_sep = |b: &[u8], i: usize| -> usize {
        match b[i] {
            b';' => 1,
            b'&' | b'|' if b.get(i + 1) == Some(&b[i]) => 2,
            // A lone `&` backgrounds a command unless it belongs to a redirect
            // (`2>&1`, `&>`).
            b'&' if i > 0 && b[i - 1] != b'>' && b.get(i + 1) != Some(&b'>') => 1,
            _ => 0,
        }
    };
    let chunk = split_outside_quotes(line, list_sep)
        .into_iter()
        .rev()
        .find(|(start, _)| *start <= op_start)
        .map(|(_, piece)| piece)
        .unwrap_or(line);
    split_outside_quotes(chunk, |b, i| usize::from(b[i] == b'|'))
        .into_iter()
        .map(|(_, stage)| stage.trim())
        .filter(|stage| !stage.is_empty())
        .all(|stage| HEREDOC_DATA_SINKS.contains(&leading_command(stage)))
}

fn has_write_mode(tool: &str, segment: &str) -> bool {
    let args: Vec<_> = segment.split_whitespace().skip(1).collect();
    match tool {
        "find" => args
            .iter()
            .any(|arg| matches!(*arg, "-delete" | "-exec" | "-execdir" | "-ok" | "-okdir")),
        "sed" => args.iter().any(|arg| {
            (arg.starts_with("-i") && !arg.starts_with("--"))
                || *arg == "--in-place"
                || arg.starts_with("--in-place=")
        }),
        "yq" => args.iter().any(|arg| matches!(*arg, "-i" | "--inplace")),
        "sort" | "uniq" => args.iter().any(|arg| {
            *arg == "-o"
                || *arg == "--output"
                || arg.starts_with("-o")
                || arg.starts_with("--output=")
        }),
        "xxd" => args.iter().any(|arg| matches!(*arg, "-r" | "-revert")),
        _ => false,
    }
}

/// The regex of a named blocklist rule (built-ins are prepended to the list).
fn rule_regex(policy: &Policy, name: &str) -> Option<Regex> {
    policy
        .blocklist
        .iter()
        .find(|r| r.name == name)
        .and_then(|r| Regex::new(&r.pattern).ok())
}

/// Record a policy block for Tier 3, anchored on the words of the text the
/// rule matched, over the same normalized variants the matcher uses.
fn record_policy_block(
    state: &mut SessionState,
    policy: &Policy,
    command: &str,
    rule: &str,
    keywords: Vec<String>,
) {
    let matched: Vec<String> = rule_regex(policy, rule)
        .map(|re| {
            evasion::normalize_command(command)
                .iter()
                .flat_map(|variant| {
                    re.find_iter(variant)
                        .map(|m| m.as_str().to_string())
                        .collect::<Vec<_>>()
                })
                .collect()
        })
        .unwrap_or_default();
    state.record_block_anchored(command, rule, keywords, anchors_from(command, matched), 0);
}

/// Keywords of the `matched` texts that also occur in `command`: the words a
/// retry must reuse to count as one. A word present only in an expanded or
/// decoded variant cannot recur in a retry's raw text and is dropped, so such
/// a block falls back to the keyword-only check.
fn anchors_from(command: &str, matched: impl IntoIterator<Item = String>) -> Vec<String> {
    let lower = command.to_lowercase();
    let mut anchors: Vec<String> = matched
        .into_iter()
        .flat_map(|text| extract_keywords(&text))
        .filter(|word| lower.contains(&word.to_lowercase()))
        .collect();
    anchors.sort();
    anchors.dedup();
    anchors
}

/// The settings tamper rule exists to stop writes. A mention of the settings
/// path is inert when every raw segment the rule matches is read-only, after
/// heredoc bodies that only reach data sinks are removed. So a grep for the
/// path inside a `cd .. && ..; ls` chain passes, and so does a note about the
/// file written through `cat > notes.md <<'EOF'`, while `cp`, `tee`, `sed -i`,
/// an interpreter heredoc, or an output redirect on a matching segment still
/// blocks. Substitutions outside single quotes disqualify because they can
/// smuggle a write through a read-only command line, e.g.
/// `cat "$(cp evil.json ~/.claude/settings.json)"`. If the rule fired only
/// through a normalized variant and the raw text never matches, the block
/// stands.
fn is_inert_settings_mention(cmd: &str, rule: &Regex) -> bool {
    if !rule.is_match(cmd) || has_substitution(cmd) {
        return false;
    }
    let code = strip_harmless_redirects(&strip_data_heredocs(cmd));
    segments(&code)
        .into_iter()
        .filter(|seg| rule.is_match(seg))
        .all(|seg| !seg.contains('>') && is_read_only_segment(seg))
}

/// `$(`, `<(`, or a backtick outside single quotes.
fn has_substitution(cmd: &str) -> bool {
    let b = cmd.as_bytes();
    let mut in_single = false;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\'' => in_single = !in_single,
            b'\\' if !in_single => i += 1,
            b'`' if !in_single => return true,
            b'$' | b'<' if !in_single && b.get(i + 1) == Some(&b'(') => return true,
            _ => {}
        }
        i += 1;
    }
    false
}

/// A non-force worktree removal is guarded by Git itself: Git refuses to
/// remove a dirty worktree. Waive only the outside-project prompt for a single,
/// unchained command; denied paths and hard policy blocks still run first.
fn is_safe_worktree_removal(cmd: &str) -> bool {
    if cmd.contains("$(")
        || cmd
            .chars()
            .any(|character| matches!(character, ';' | '|' | '&' | '>' | '<' | '`' | '\n'))
    {
        return false;
    }

    let words: Vec<_> = cmd.split_whitespace().collect();
    words.len() >= 4
        && words[..3] == ["git", "worktree", "remove"]
        && !words[3..].iter().any(|word| {
            *word == "--force"
                || (word.starts_with('-') && !word.starts_with("--") && word[1..].contains('f'))
        })
}

#[allow(clippy::too_many_arguments)]
fn memory_snapshot_failure(
    input: &HookInput,
    policy: &Policy,
    tool_name: &str,
    tool_input: &serde_json::Value,
    state: &mut SessionState,
    state_dir: &Path,
    start: Instant,
    error: &str,
) -> PreToolResult {
    let _ = state.save(state_dir);
    log_decision(
        input,
        policy,
        tool_name,
        tool_input,
        "block",
        Some("memory-snapshot"),
        start,
    );
    PreToolResult {
        output: HookOutput::deny(&format!(
            "⛔ Railguard: Memory Safety: deletion blocked because the pre-approval snapshot failed: {error}"
        )),
        terminate: None,
    }
}

fn summarize_input(tool_name: &str, tool_input: &serde_json::Value) -> String {
    match tool_name {
        "Bash" => tool_input
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown command)")
            .chars()
            .take(200)
            .collect(),
        "Write" | "Edit" | "Read" => tool_input
            .get("file_path")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown path)")
            .to_string(),
        _ => serde_json::to_string(tool_input)
            .unwrap_or_default()
            .chars()
            .take(200)
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tamper_rule() -> Regex {
        Regex::new(r"\.claude/settings\.json").unwrap()
    }

    #[test]
    fn data_heredoc_body_and_terminator_are_dropped() {
        let cmd = "cat > ~/.claude/notes.md <<'MD'\nEdit ~/.claude/settings.json next.\nMD\nls";
        assert_eq!(
            strip_data_heredocs(cmd),
            "cat > ~/.claude/notes.md <<'MD'\nls"
        );
        let piped = "grep -f - f <<EOF\npattern\nEOF";
        assert_eq!(strip_data_heredocs(piped), "grep -f - f <<EOF");
    }

    #[test]
    fn code_heredoc_stays_verbatim() {
        for cmd in [
            "python3 - <<'PY'\nopen(p, 'w')\nPY",
            "cat <<'EOF' | bash\ncp a b\nEOF",
            "awk -f - x <<EOF\n{ print }\nEOF",
        ] {
            assert_eq!(strip_data_heredocs(cmd), cmd, "{cmd}");
        }
    }

    #[test]
    fn dash_heredoc_strips_leading_tabs_from_terminator() {
        let cmd = "cat <<-EOF\n\tbody\n\tEOF\necho done";
        assert_eq!(strip_data_heredocs(cmd), "cat <<-EOF\necho done");
    }

    #[test]
    fn quoted_operator_and_here_string_are_not_heredocs() {
        for cmd in [
            "echo 'a << b'\nls",
            "echo \"<<EOF\"\nls",
            "grep x <<< 'a'\nls",
        ] {
            assert_eq!(strip_data_heredocs(cmd), cmd, "{cmd}");
        }
    }

    #[test]
    fn segments_split_outside_quotes_only() {
        assert_eq!(segments("grep 'a|b' f; ls"), ["grep 'a|b' f", "ls"]);
        assert_eq!(segments("a && b || c\nd"), ["a", "b", "c", "d"]);
        assert_eq!(segments("echo \"x; y\" | wc"), ["echo \"x; y\"", "wc"]);
    }

    #[test]
    fn leading_command_skips_wrappers_and_env() {
        assert_eq!(leading_command("rtk proxy sed -n 1p f"), "sed");
        assert_eq!(leading_command("FOO=1 rtk grep x"), "grep");
        assert_eq!(leading_command("cd x"), "cd");
        assert_eq!(leading_command(""), "");
    }

    #[test]
    fn read_only_command_tolerates_harmless_shapes() {
        for cmd in [
            "grep -n hooks f 2>/dev/null | head",
            "cat f 2>&1",
            "ls >/dev/null; pwd",
            "rtk proxy sed -n '1p' f",
            "grep -f - f <<EOF\npattern\nEOF",
            "cd repo && grep 'a|b' f",
        ] {
            assert!(is_read_only_command(cmd), "{cmd}");
        }
    }

    #[test]
    fn read_only_command_rejects_writes() {
        for cmd in [
            "cat f > out",
            "ls\nrm -rf x",
            "rtk sed -i 's/a/b/' f",
            "python3 - <<'PY'\nprint(1)\nPY",
            "cat <<EOF | bash\nls\nEOF",
        ] {
            assert!(!is_read_only_command(cmd), "{cmd}");
        }
    }

    #[test]
    fn settings_mentions_in_data_positions_are_inert() {
        let rule = tamper_rule();
        for cmd in [
            "cat > ~/.claude/notes.md <<'MD'\nEdit ~/.claude/settings.json to add the hook.\nMD",
            "cd ~/.claude && grep -rn 'Modify `~/.claude/settings.json`' docs 2>/dev/null | head -5; echo done; ls docs",
            "grep -n hooks ~/.claude/settings.json 2>/dev/null",
            "cat ~/.claude/settings.json 2>&1 | head -3",
            "rtk grep -n hooks ~/.claude/settings.json",
            "jq .hooks ~/.claude/settings.json",
        ] {
            assert!(is_inert_settings_mention(cmd, &rule), "{cmd}");
        }
    }

    #[test]
    fn settings_writes_are_not_inert() {
        let rule = tamper_rule();
        for cmd in [
            "cp evil.json ~/.claude/settings.json",
            "cat <<'EOF' > ~/.claude/settings.json\n{}\nEOF",
            "cat <<'EOF' | bash\ncp /tmp/evil.json ~/.claude/settings.json\nEOF",
            "python3 - <<'PY'\nopen('/home/u/.claude/settings.json', 'w').write('{}')\nPY",
            "echo '{}' | tee ~/.claude/settings.json",
            "grep hooks ~/.claude/settings.json; sed -i 's/a/b/' ~/.claude/settings.json",
            "cat \"$(cp evil.json ~/.claude/settings.json)\"",
            "cat `echo ~/.claude/settings.json`",
            "cat <(cp evil.json ~/.claude/settings.json)",
            // Matched only through a normalized variant: the block stands.
            "cat ~/.claude/sett\"\"ings.json",
        ] {
            assert!(!is_inert_settings_mention(cmd, &rule), "{cmd}");
        }
    }

    #[test]
    fn substitution_inside_single_quotes_is_text() {
        assert!(!has_substitution("grep '$(x)' f"));
        assert!(!has_substitution("grep '`x`' f"));
        assert!(has_substitution("grep \"$(x)\" f"));
        assert!(has_substitution("cat `x`"));
        assert!(has_substitution("cat <(x)"));
        assert!(!has_substitution("cat \\`x"));
    }

    #[test]
    fn anchors_are_matched_words_present_in_the_command() {
        assert_eq!(
            anchors_from("cat ~/.ssh/id_rsa", ["~/.ssh/id_rsa".to_string()]),
            ["ssh/id_rsa"]
        );
        // Deduplicated and sorted.
        assert_eq!(
            anchors_from(
                "terraform destroy; terraform destroy",
                [
                    "terraform destroy".to_string(),
                    "terraform destroy".to_string()
                ],
            ),
            ["destroy", "terraform"]
        );
        // Words only present in an expanded or decoded variant are dropped.
        assert!(
            anchors_from("cat $HOME/.ssh/id_rsa", ["/home/u/.ssh/id_rsa".to_string()]).is_empty()
        );
        assert!(anchors_from(
            "echo dGVy | base64 -d | sh",
            ["terraform destroy".to_string()]
        )
        .is_empty());
    }
}
