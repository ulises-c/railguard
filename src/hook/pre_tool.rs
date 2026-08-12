use std::path::Path;
use std::time::Instant;

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
            state.heightened_until_call = None;
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
                state.record_ask(&command, "behavioral-evasion", keywords, 3);
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
                        return PreToolResult {
                            output: HookOutput::allow(),
                            terminate: None,
                        };
                    } else {
                        let keywords = extract_keywords(&command);
                        state.record_ask(&command, pattern, keywords, 1);
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
                        state.record_ask(&command, pattern, keywords, 2);
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

    // === MEMORY GUARD (before path fence, since ~/.claude is denied) ===

    if policy.memory.enabled {
        // For Bash commands, check if they touch memory paths
        let memory_file_path = if tool_name == "Bash" {
            tool_input
                .get("command")
                .and_then(|v| v.as_str())
                .and_then(|cmd| {
                    let paths = evasion::extract_paths_from_command(cmd);
                    paths.into_iter().find(|p| memory_guard::is_memory_path(p))
                })
        } else {
            extract_file_path(tool_name, &tool_input).filter(|p| memory_guard::is_memory_path(p))
        };

        if let Some(ref mem_path) = memory_file_path {
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
                             Railguard's memory guard requires approval for behavioral memory writes.",
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
                        state.record_block(cmd, "path-fence", keywords, 0);
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
                        if is_read_only_command(cmd) {
                            // Read-only commands outside project are fine
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

    let decision = evaluate(policy, tool_name, &tool_input);

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
                state.record_block(&command, rule, keywords, 0);
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
    // An output redirect writes a file — never read-only. Checked up front so a
    // navigation prefix can't launder it, e.g. `cd /tmp && echo x > ~/outside`.
    if cmd.contains('>') {
        return false;
    }

    // Only tools that inspect/read. A tool earns a spot here only if it cannot
    // create or modify a file without a shell redirect — and redirects are
    // already rejected by the `>` check above. Deliberately EXCLUDED, even
    // though they are common in read-only invocations: interpreters (`python`,
    // `node`, `ruby`), `go`/`rustc`, version control (`git`), and package
    // managers (`cargo`, `npm`, `npx`, `yarn`, `pnpm`, `bun`), and `xargs`
    // (it runs an arbitrary downstream command, e.g. `xargs rm`). Writing is a
    // normal mode of operation for all of these and their read-vs-write intent
    // cannot be told from the leading token (`git log` vs `git checkout`,
    // `python -c "print(1)"` vs `python -c "open(p,'w')"`), so they must keep
    // prompting when they name a path outside the project. Do not re-add them.
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

    // Every segment of a compound command (`&&`, `||`, `;`, `|`) must itself be
    // read-only. `cd`/`pushd`/`popd` are navigation and don't disqualify.
    // (Split is connector-naive; a connector char inside a quoted program at
    // worst yields a non-read-only verdict — more fencing, never less.)
    cmd.split([';', '|', '&'])
        .map(str::trim)
        .filter(|seg| !seg.is_empty())
        .all(|seg| {
            let tok = seg.split(char::is_whitespace).next().unwrap_or("");
            matches!(tok, "cd" | "pushd" | "popd") || READ_ONLY_COMMANDS.contains(&tok)
        })
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
