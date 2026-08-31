use std::path::Path;
use std::time::Instant;

use crate::block::evasion;
use crate::block::matcher::restrictiveness;
use crate::fence::path::{absolutize_from, check_path_from, extract_file_paths, PathCheck};
use crate::memory::guard as memory_guard;
use crate::policy::engine::evaluate;
use crate::policy::protected;
use crate::snapshot::capture::capture_snapshot;
use crate::threat::classifier::{
    check_behavioral_evasion, classify_threat, extract_keywords, ThreatTier,
};
use crate::threat::state::SessionState;
use crate::trace::logger::log_trace;
use crate::types::{
    Decision, HookClient, HookInput, HookOutput, MemoryDecision, Policy, TraceEntry,
};

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
pub fn handle(input: &HookInput, policy: &Policy, client: HookClient) -> PreToolResult {
    let start = Instant::now();
    let tool_name = input.tool_name.as_deref().unwrap_or("unknown");
    let tool_input = input.tool_input.clone().unwrap_or_default();
    let file_paths = extract_file_paths(tool_name, &tool_input);
    let cwd = Path::new(&input.cwd);

    // Load persistent session state (walk up — the shell cwd persists across
    // tool calls and may have drifted below the project root)
    let state_dir = SessionState::locate_state_dir(cwd, &input.session_id);
    let mut state = SessionState::load(&state_dir, &input.session_id);
    // A pending approval is NOT resolved here. The arrival of a later tool call
    // says nothing about what the human answered — someone who clicks deny also
    // goes on working — so inferring approval from it turned every denial into a
    // session-wide allow. `PostToolUse` for the same `tool_use_id` is the only
    // signal that distinguishes the two, and post_tool resolves it there.
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
            state.clear_termination();
            let _ = state.save(&state_dir);
            // Fall through to normal evaluation
        } else {
            if client.supports_interactive_approval() {
                state.set_pending_approval("session-resume", input.tool_use_id.as_deref());
            }
            let _ = state.save(&state_dir);
            return PreToolResult {
                output: HookOutput::approval_required(
                    client,
                    &format!(
                        "🛡️ RAILGUARD is asking (not Claude Code's permission system).\n\
                     \n\
                     This session was previously terminated because:\n\
                     {}\n\
                     \n\
                     Approve to resume this session (threat state will be reset), \
                     or deny to keep it blocked.",
                        reason
                    ),
                ),
                terminate: None,
            };
        }
    }

    // The shell command this call will run. `Bash` names it directly; a
    // shell-capable MCP tool carries one under its own argument name. Both must
    // reach the fence, the blocklist, and the threat classifier — gating those
    // on the literal name "Bash" left `mcp__*__execute_command` ungoverned.
    let command =
        crate::fence::path::extract_shell_command(tool_name, &tool_input).unwrap_or_default();
    let runs_shell_command = !command.is_empty();

    // An approval is weaker than a deny or a block, so no stage may answer the
    // whole call with one. Every stage that wants to ask parks its message here
    // and carries on; it is emitted at the very end, and only if nothing stricter
    // outranked it. First writer wins, which puts the threat detector's specific
    // explanation ahead of the fence's more generic one.
    let mut deferred_ask: Option<String> = None;
    // Set when the human already approved this evasion pattern earlier in the
    // session. The threat detector is then satisfied and stops asking, but the
    // later stages still get their say — and a block recorded downstream must not
    // be attributed to a pattern the human explicitly waved through, or the
    // session enters heightened state and Tier 3 starts firing on ordinary work.
    let mut threat_pattern_approved = false;

    // === THREAT DETECTION (before policy evaluation) ===

    if runs_shell_command {
        // Tier 3: Behavioral evasion (check BEFORE new blocks)
        if let Some(tier) = check_behavioral_evasion(&state, &command) {
            let pattern_key = match &tier {
                ThreatTier::Tier3 { original_rule, .. } => format!("tier3:{}", original_rule),
                _ => "tier3:unknown".to_string(),
            };

            if state.is_approved(&pattern_key) {
                threat_pattern_approved = true;
            } else {
                let keywords = extract_keywords(&command);
                state.record_block(&command, "behavioral-evasion", keywords, 3);
                if client.supports_interactive_approval() {
                    state.set_pending_approval(&pattern_key, input.tool_use_id.as_deref());
                }
                let _ = state.save(&state_dir);

                let cmd_preview: String = command.chars().take(120).collect();
                return PreToolResult {
                    output: HookOutput::approval_required(client, &format!(
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
                        threat_pattern_approved = true;
                    } else {
                        let keywords = extract_keywords(&command);
                        state.record_block(&command, pattern, keywords, 1);
                        if client.supports_interactive_approval() {
                            state.set_pending_approval(&pattern_key, input.tool_use_id.as_deref());
                        }
                        let _ = state.save(&state_dir);

                        let cmd_preview: String = command.chars().take(120).collect();
                        return PreToolResult {
                            output: HookOutput::approval_required(client, &format!(
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
                        threat_pattern_approved = true;
                    } else if state.warning_count >= 1 {
                        // Second occurrence: ask user instead of terminating
                        let keywords = extract_keywords(&command);
                        state.record_block(&command, pattern, keywords, 2);
                        if client.supports_interactive_approval() {
                            state.set_pending_approval(&pattern_key, input.tool_use_id.as_deref());
                        }
                        let _ = state.save(&state_dir);

                        let cmd_preview: String = command.chars().take(120).collect();
                        return PreToolResult {
                            output: HookOutput::approval_required(
                                client,
                                &format!(
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
                            ),
                            ),
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

    // The guard's verdict is combined at the end rather than returned here, and
    // it is taken over EVERY memory path rather than the first. Returning on the
    // first match decided the whole call from one path: a call naming a memory
    // file and `/etc/shadow` was answered by the memory file alone, and the
    // denied path was never examined. Its `Allow` still has to suppress the fence
    // — memory lives under `~/.claude`, which is denied — but only for the memory
    // paths themselves, never for the rest of the call.
    let mut memory_decision = Decision::Allow;
    let mut fence_exempt: Vec<String> = Vec::new();

    if policy.memory.enabled {
        let memory_paths: Vec<String> = if runs_shell_command {
            evasion::extract_paths_from_command(&command)
                .into_iter()
                .filter(|p| memory_guard::is_memory_path(p))
                .collect()
        } else {
            file_paths
                .iter()
                .filter(|path| memory_guard::is_memory_path(path))
                .cloned()
                .collect()
        };

        for mem_path in &memory_paths {
            let result = memory_guard::check_memory_write(
                &policy.memory,
                tool_name,
                mem_path,
                &tool_input,
                &input.session_id,
                cwd,
            );
            let as_decision = match result {
                MemoryDecision::Allow => {
                    fence_exempt.push(mem_path.clone());
                    Decision::Allow
                }
                MemoryDecision::Block(reason) => Decision::Block {
                    rule: "memory-guard".to_string(),
                    message: reason,
                },
                MemoryDecision::Approve(reason) => Decision::Approve {
                    rule: "memory-guard".to_string(),
                    message: reason,
                },
            };
            if restrictiveness(&as_decision) > restrictiveness(&memory_decision) {
                memory_decision = as_decision;
            }
        }
    }

    // === PATH FENCE ===

    // An outside-project path asks for approval, which is *weaker* than a deny or
    // a block. Returning it the moment it was found meant the rest of the call
    // went unexamined: `["/var/tmp/benign", "/etc/passwd"]` prompted about
    // `/var/tmp` and never looked at `/etc`, and approving the prompt authorized
    // the whole call. Hold it here and emit it only once every stricter stage has
    // run. A `Denied` still returns immediately — deny is maximal, so nothing
    // later can outrank it.

    if runs_shell_command {
        {
            let cmd = command.as_str();
            let paths = evasion::extract_paths_from_command(cmd);
            for path in &paths {
                if fence_exempt.contains(path) {
                    continue;
                }
                match check_path_from(&policy.fence, path, &fence_root, &input.cwd) {
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
                        // Read-only commands outside the project are fine.
                        if !is_read_only_command(cmd) && deferred_ask.is_none() {
                            deferred_ask = Some(format!(
                                "🛡️ RAILGUARD is asking (not Claude Code's permission system).\n\
                                 \n\
                                 {}\n\
                                 \n\
                                 Railguard's path fence requires approval for commands that \
                                 access files outside the project directory.",
                                reason
                            ));
                        }
                    }
                }
            }
        }
    }

    // Not an `else`: a tool can carry both a shell command and path arguments,
    // and both deserve the fence. Bash is excluded because its paths were
    // already checked above, from the command itself.
    if tool_name != "Bash" {
        for file_path in &file_paths {
            if fence_exempt.contains(file_path) {
                continue;
            }
            match check_path_from(&policy.fence, file_path, &fence_root, &input.cwd) {
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
                    if !is_read_only_tool(tool_name) && deferred_ask.is_none() {
                        deferred_ask = Some(format!(
                                "🛡️ RAILGUARD is asking (not Claude Code's permission system).\n\
                                 \n\
                                 {}\n\
                                 \n\
                                 Railguard's path fence requires approval for writes outside the project directory.",
                            reason
                        ));
                    }
                }
            }
        }
    }

    // === PROTECTED RESOURCES (decided ahead of the policy) ===

    // Self-protection is never waived outright. Exempting read-only callers
    // handed `railguard.yaml` to any allowlisted program with a write mode —
    // `sed -i` and `sort -o` both returned allow. Every call is judged instead,
    // and a caller that provably cannot write a file has its verdict softened
    // one notch, so reading policy stays frictionless while every write
    // mechanism, enumerated or not, is at minimum surfaced to the human.
    //
    // Paths come from the protection-specific extractor because the fence's set
    // filters out project-relative values as harmless — true of the fence, false
    // here, since Railguard's own policy, state, and snapshots live inside the
    // project and `railguard.yaml` is the ordinary way to spell the file. A shell
    // command contributes the paths it names, extracted the same way the fence
    // extracts them.
    let mut protected_paths =
        crate::fence::path::extract_paths_for_protection(tool_name, &tool_input);
    if runs_shell_command {
        protected_paths.extend(evasion::extract_paths_from_command(&command));
        protected_paths.extend(protected::command_path_candidates(&command));
    }
    let read_only_caller = if command.is_empty() {
        is_read_only_call(tool_name, &tool_input)
    } else {
        cannot_write_any_file(&command)
    };

    // Resources are matched by resolved identity, so a symlink or a `..` detour
    // lands on the same canonical path and a filename inside a comment resolves to
    // nothing. Railguard's own subcommands are commands rather than resources, so
    // they are still recognized in the command text.
    let mut protected_decision = protected::check_paths(
        protected_paths.iter().map(String::as_str),
        &input.cwd,
        &fence_root,
    );
    let by_command = protected::check_commands(&command);
    if restrictiveness(&by_command) > restrictiveness(&protected_decision) {
        protected_decision = by_command;
    }
    let protected_decision = soften_if_read_only(protected_decision, read_only_caller);

    // === POLICY EVALUATION (allowlist → blocklist → approve) ===

    // Both stages always run, and the stricter verdict wins. A protected-resource
    // hit must still outrank a policy an agent managed to write — the allowlist is
    // evaluated first during normal evaluation, so it could otherwise allow the
    // write that produced it — but emitting protection *instead of* the policy
    // threw the blocklist away. Because `railguard-protect-policy` matches command
    // text, appending `# railguard.yaml` to any blocked command downgraded it to an
    // approval, and mislabeled the prompt as a policy edit while the human was in
    // fact authorizing the blocked command.
    // A human-approved evasion pattern suppresses the blocklist, because that is
    // exactly what the approval was for: these patterns are blocklisted *and*
    // flagged by the classifier, so an approval that still hit the blocklist
    // would be meaningless. It licenses nothing else — the protected-resource
    // check, the fence, and the memory guard all still apply below, so approving
    // `rev … | sh` once no longer also approves a write to `railguard.yaml`.
    let policy_decision = if threat_pattern_approved {
        Decision::Allow
    } else {
        evaluate(policy, tool_name, &tool_input)
    };
    let mut decision = if restrictiveness(&protected_decision) >= restrictiveness(&policy_decision)
    {
        protected_decision
    } else {
        policy_decision
    };

    // The memory guard's verdict, held from above, joins the same lattice.
    if restrictiveness(&memory_decision) > restrictiveness(&decision) {
        decision = memory_decision;
    }

    // Every built-in rule is scoped to `tool: "Bash"`, so a shell command
    // arriving under some other tool name matched nothing. Re-evaluate the
    // extracted command as if it were Bash and keep the stricter of the two —
    // `railguard uninstall` must not become allowed by being wrapped in an MCP
    // tool call.
    //
    // Re-evaluating only when the first decision was Allow broke that promise:
    // a tool-specific *approve* rule matching a call that carries `terraform
    // destroy` kept its Approve and never consulted the Bash blocklist,
    // downgrading an unconditional block into something a human can wave
    // through. Compare both and keep the most restrictive.
    if runs_shell_command && tool_name != "Bash" {
        let as_bash = evaluate(
            policy,
            "Bash",
            &serde_json::json!({ "command": command.clone() }),
        );
        if restrictiveness(&as_bash) > restrictiveness(&decision) {
            decision = as_bash;
        }
    }

    // The held fence approval, now that every stricter stage has run. Anything
    // that outranks it — a protected-resource hit, a blocklist match, an as-Bash
    // block — is emitted by the match below instead, so an approval can no longer
    // be the whole answer to a call that also earned a deny.
    if let Some(message) = deferred_ask {
        if matches!(decision, Decision::Allow) {
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
                output: HookOutput::approval_required(client, &message),
                terminate: None,
            };
        }
    }

    match &decision {
        Decision::Allow => {
            // Lock identity and snapshot manifests outlive this call, so they
            // must not depend on the cwd of whoever reads them later. Patch
            // paths are typically relative: recording a bare `file.txt` meant
            // `railguard rollback`, run from anywhere else, resolved it against
            // its own cwd and restored over a different file — or deleted one,
            // for an entry marked as newly created. Two sessions could likewise
            // hold what each believed was the lock for the same file.
            let recorded_paths: Vec<String> = file_paths
                .iter()
                .map(|file_path| absolutize_from(file_path, &input.cwd))
                .collect();

            // Coordination: acquire file lock for Write/Edit
            if is_file_edit_tool(tool_name) {
                let mut acquired: Vec<&String> = Vec::new();
                for file_path in &recorded_paths {
                    if let Some(deny_msg) =
                        crate::coord::context::check_file_conflict(file_path, &input.session_id)
                    {
                        // The call is being denied, so release what this patch
                        // already locked instead of stranding those files.
                        for locked in acquired {
                            crate::coord::lock::release(locked, &input.session_id);
                        }
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
                    acquired.push(file_path);
                }
            }

            // Snapshot before Write/Edit (if enabled)
            if snapshot_enabled_for(policy, tool_name) {
                capture_file_snapshots(input, policy, &fence_root, &recorded_paths);
            }

            log_decision(input, policy, tool_name, &tool_input, "allow", None, start);
            let _ = state.save(&state_dir);
            PreToolResult {
                output: HookOutput::allow_for(client),
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
                output: HookOutput::approval_required(
                    client,
                    &format!(
                        "🛡️ RAILGUARD is asking (not Claude Code's permission system).\n\
                     \n\
                     Rule: {} — {}\n\
                     \n\
                     This command matched a Railguard policy rule that requires human approval.",
                        rule, message
                    ),
                ),
                terminate: None,
            }
        }
    }
}

fn is_file_edit_tool(tool_name: &str) -> bool {
    matches!(tool_name, "Write" | "Edit" | "apply_patch")
}

fn snapshot_enabled_for(policy: &Policy, tool_name: &str) -> bool {
    policy.snapshot.enabled
        && (policy.snapshot.tools.iter().any(|tool| tool == tool_name)
            || (tool_name == "apply_patch"
                && policy
                    .snapshot
                    .tools
                    .iter()
                    .any(|tool| matches!(tool.as_str(), "Write" | "Edit"))))
}

fn capture_file_snapshots(
    input: &HookInput,
    policy: &Policy,
    fence_root: &str,
    file_paths: &[String],
) {
    let snap_dir = Path::new(fence_root).join(&policy.snapshot.directory);
    let tool_use_id = input.tool_use_id.as_deref().unwrap_or("unknown");
    for file_path in file_paths {
        if let Err(error) = capture_snapshot(&snap_dir, &input.session_id, tool_use_id, file_path) {
            let _ = error;
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

/// Whether a non-shell call only inspects. Beyond the three literal names, an
/// unrecognized tool qualifies when its payload carries no contents to write and
/// its name holds no mutating verb.
///
/// Recognizing only the literal names made
/// `mcp__filesystem__read_file {"path": "railguard.yaml"}` a hard denial on Codex
/// once unknown tools started reaching self-protection — a stricter answer with no
/// safety gained, on a path whose own rule exists to stop *modification*, and with
/// no approval to appeal to on that client.
///
/// A hostile MCP server could name a write tool `read_file`, but the installed
/// server set is the human's configuration rather than the agent's, and this only
/// softens a verdict by one notch in either direction.
fn is_read_only_call(tool_name: &str, tool_input: &serde_json::Value) -> bool {
    if is_read_only_tool(tool_name) {
        return true;
    }
    const MUTATING_TOKENS: &[&str] = &[
        "write", "create", "delete", "remove", "put", "patch", "edit", "update", "move", "rename",
        "truncate", "append", "mkdir", "chmod", "exec", "run", "install", "upload", "save", "set",
        "copy", "sync", "push",
    ];
    let lowered = tool_name.to_ascii_lowercase();
    if MUTATING_TOKENS.iter().any(|verb| lowered.contains(verb)) {
        return false;
    }
    !crate::fence::path::carries_content(tool_input)
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

    // Constructs that introduce a command somewhere this function does not look.
    // `segments` splits on `; | & \n \r` and then trusts each segment's leading
    // token, so anything that runs a program from *inside* an argument is
    // invisible to it: `echo $(cp /dev/null railguard.yaml)` reads as a bare
    // `echo`. There is no way to enumerate the programs reachable that way, so
    // the construct itself disqualifies the command.
    //
    // `$((` is arithmetic, not a command, and `echo $((100 / 4))` is ordinary
    // work — so `$(` only counts when the next character is not another paren.
    if cmd.contains('`') || cmd.contains("<(") || contains_command_substitution(cmd) {
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
    //
    // Also excluded: `less`/`more` (a pager runs `LESSOPEN` and `!cmd`), and
    // `fd`/`rg`/`ag`/`ack`. Those four are searchers whose read invocations are
    // perfectly ordinary, but each delegates to an arbitrary program
    // (`fd --exec`, `rg --pre`, `ack --pager`) and their flag surfaces are large
    // and churn upstream, so no list of theirs stays true. `grep` covers the same
    // ground and has no execution mode. Do not re-add them.
    //
    // Some entries in the table CAN write given the right flag or operand —
    // `sed -i`, `sort -o`, `uniq IN OUT`, `find -delete`, `xxd IN OUT`, `yq -i`,
    // `awk system()`, `env CMD`, `tree -o`. They stay listed because their read
    // invocations are ordinary enough that fencing them is real prompt fatigue
    // (see tests/path_fence_false_positives.rs), so each carries the terms on
    // which it is read-only instead.

    // Every segment of a compound command (`&&`, `||`, `;`, `|`, newline) must
    // itself be read-only. `cd`/`pushd`/`popd` are navigation and don't
    // disqualify. (Split is connector-naive; a connector char inside a quoted
    // program at worst yields a non-read-only verdict — more fencing, never
    // less.) A newline is as much a separator as `;`: omitting it let a
    // read-only first line vouch for a mutating second one, and
    // `extract_shell_command` joins multi-argument MCP payloads with `\n`.
    segments(cmd).all(|seg| {
        let mut words = seg.split_whitespace();
        let tok = words.next().unwrap_or("");
        if matches!(tok, "cd" | "pushd" | "popd") {
            return true;
        }
        let args: Vec<&str> = words.collect();
        invocation_is_read_only(tok, &args)
    })
}

/// `$(cmd)` but not `$((1 + 2))`. Arithmetic expansion is ordinary work and
/// appears in the false-positive suite; command substitution runs a program.
fn contains_command_substitution(cmd: &str) -> bool {
    let bytes = cmd.as_bytes();
    cmd.match_indices("$(")
        .any(|(i, _)| bytes.get(i + 2) != Some(&b'('))
}

fn segments(cmd: &str) -> impl Iterator<Item = &str> {
    cmd.split([';', '|', '&', '\n', '\r'])
        .map(str::trim)
        .filter(|seg| !seg.is_empty())
}

/// What keeps a program in the read-only set honest.
enum Inertness {
    /// Reviewed: no mode of this program writes a file or runs another program,
    /// whatever flags it is handed.
    Always,
    /// Reviewed: read-only only on these terms.
    OnlyWith(Guard),
}

/// The terms on which a write-capable program is still a read.
struct Guard {
    /// Flags that keep the invocation read-only. Anything else disqualifies it, so
    /// a flag added upstream tomorrow fails closed and costs at most a prompt.
    safe_flags: &'static [&'static str],
    /// Of those, the flags that consume the next token as their value, so it is
    /// not miscounted as an operand — `xxd -l 100 file` names one file, not two.
    value_flags: &'static [&'static str],
    /// How many non-flag operands are inputs. A synopsis ending in `[outfile]`
    /// writes its last operand: `xxd IN OUT` and `uniq IN OUT` each truncate OUT
    /// with no flag and no redirect in sight. `usize::MAX` means every operand is
    /// an input.
    max_operands: usize,
}

/// THE read-only set. There is exactly one list, and every entry states what makes
/// it safe.
///
/// The previous shape kept membership and flag rules in two separate lists, and a
/// program present in the first but absent from the second was silently treated as
/// inert. That is how `tree -o FILE` — a documented write flag — classified as
/// read-only and waived both the fence and self-protection. One table with a
/// mandatory verdict per entry makes that particular omission unrepresentable:
/// adding a program forces someone to say why it is safe.
const READ_ONLY: &[(&str, Inertness)] = &[
    // ── Inert: no write or execution mode at any flag ────────────────────────
    ("ls", Inertness::Always),
    ("cat", Inertness::Always),
    ("head", Inertness::Always),
    ("tail", Inertness::Always),
    ("wc", Inertness::Always),
    ("file", Inertness::Always),
    ("stat", Inertness::Always),
    ("du", Inertness::Always),
    ("df", Inertness::Always),
    ("which", Inertness::Always),
    ("whereis", Inertness::Always),
    ("type", Inertness::Always),
    ("grep", Inertness::Always),
    ("realpath", Inertness::Always),
    ("readlink", Inertness::Always),
    ("basename", Inertness::Always),
    ("dirname", Inertness::Always),
    ("diff", Inertness::Always),
    ("md5", Inertness::Always),
    ("md5sum", Inertness::Always),
    ("shasum", Inertness::Always),
    ("sha256sum", Inertness::Always),
    ("hexdump", Inertness::Always),
    ("strings", Inertness::Always),
    ("jq", Inertness::Always),
    ("tr", Inertness::Always),
    ("cut", Inertness::Always),
    ("pwd", Inertness::Always),
    ("printenv", Inertness::Always),
    ("uname", Inertness::Always),
    ("whoami", Inertness::Always),
    ("id", Inertness::Always),
    ("date", Inertness::Always),
    ("cal", Inertness::Always),
    ("echo", Inertness::Always),
    ("printf", Inertness::Always),
    ("test", Inertness::Always),
    ("[", Inertness::Always),
    // ── Write-capable, allowed only on stated terms ──────────────────────────
    (
        "sed",
        Inertness::OnlyWith(Guard {
            safe_flags: &[
                "-n",
                "-e",
                "-f",
                "-E",
                "-r",
                "-s",
                "-u",
                "-z",
                "--quiet",
                "--silent",
                "--expression",
                "--file",
                "--regexp-extended",
                "--separate",
                "--unbuffered",
                "--null-data",
                "--posix",
                "--debug",
                "--sandbox",
            ],
            value_flags: &["-e", "-f", "--expression", "--file"],
            max_operands: usize::MAX,
        }),
    ),
    (
        "sort",
        Inertness::OnlyWith(Guard {
            safe_flags: &[
                "-b",
                "-c",
                "-C",
                "-d",
                "-f",
                "-g",
                "-h",
                "-i",
                "-k",
                "-M",
                "-n",
                "-r",
                "-R",
                "-s",
                "-t",
                "-u",
                "-V",
                "-z",
                "--check",
                "--dictionary-order",
                "--ignore-case",
                "--general-numeric-sort",
                "--human-numeric-sort",
                "--ignore-leading-blanks",
                "--key",
                "--month-sort",
                "--numeric-sort",
                "--random-sort",
                "--reverse",
                "--stable",
                "--field-separator",
                "--unique",
                "--version-sort",
                "--zero-terminated",
                "--parallel",
                "--buffer-size",
                "--temporary-directory",
            ],
            value_flags: &[
                "-k",
                "-t",
                "--key",
                "--field-separator",
                "--parallel",
                "--buffer-size",
                "--temporary-directory",
            ],
            max_operands: usize::MAX,
        }),
    ),
    (
        "uniq",
        Inertness::OnlyWith(Guard {
            safe_flags: &[
                "-c",
                "-d",
                "-D",
                "-f",
                "-i",
                "-s",
                "-u",
                "-w",
                "-z",
                "--count",
                "--repeated",
                "--all-repeated",
                "--skip-fields",
                "--ignore-case",
                "--skip-chars",
                "--unique",
                "--check-chars",
                "--zero-terminated",
                "--group",
            ],
            value_flags: &[
                "-f",
                "-s",
                "-w",
                "--skip-fields",
                "--skip-chars",
                "--check-chars",
            ],
            // `uniq [INPUT [OUTPUT]]`
            max_operands: 1,
        }),
    ),
    (
        "find",
        Inertness::OnlyWith(Guard {
            safe_flags: &[
                "-name",
                "-iname",
                "-path",
                "-ipath",
                "-lname",
                "-ilname",
                "-regex",
                "-iregex",
                "-regextype",
                "-type",
                "-xtype",
                "-maxdepth",
                "-mindepth",
                "-depth",
                "-mount",
                "-xdev",
                "-size",
                "-empty",
                "-perm",
                "-user",
                "-group",
                "-uid",
                "-gid",
                "-nouser",
                "-nogroup",
                "-newer",
                "-anewer",
                "-cnewer",
                "-mtime",
                "-atime",
                "-ctime",
                "-mmin",
                "-amin",
                "-cmin",
                "-used",
                "-links",
                "-inum",
                "-samefile",
                "-true",
                "-false",
                "-not",
                "-and",
                "-or",
                "-a",
                "-o",
                "-print",
                "-print0",
                "-printf",
                "-ls",
                "-prune",
                "-quit",
                "-follow",
                "-daystart",
                "-readable",
                "-writable",
                "-executable",
                "-noleaf",
                "-ignore_readdir_race",
                "-noignore_readdir_race",
                "-P",
                "-L",
                "-H",
                "-D",
            ],
            value_flags: &[
                "-name",
                "-iname",
                "-path",
                "-ipath",
                "-lname",
                "-ilname",
                "-regex",
                "-iregex",
                "-regextype",
                "-type",
                "-xtype",
                "-maxdepth",
                "-mindepth",
                "-size",
                "-perm",
                "-user",
                "-group",
                "-uid",
                "-gid",
                "-newer",
                "-anewer",
                "-cnewer",
                "-mtime",
                "-atime",
                "-ctime",
                "-mmin",
                "-amin",
                "-cmin",
                "-used",
                "-links",
                "-inum",
                "-samefile",
                "-printf",
                "-D",
            ],
            max_operands: usize::MAX,
        }),
    ),
    (
        "xxd",
        Inertness::OnlyWith(Guard {
            // `-o` is xxd's *offset*, not an output file.
            safe_flags: &[
                "-a", "-b", "-c", "-C", "-E", "-e", "-g", "-i", "-l", "-o", "-p", "-s", "-u", "-R",
            ],
            value_flags: &["-c", "-g", "-l", "-o", "-s", "-R"],
            // `xxd [options] [infile [outfile]]`
            max_operands: 1,
        }),
    ),
    (
        "awk",
        Inertness::OnlyWith(Guard {
            safe_flags: &[
                "-F",
                "-v",
                "-f",
                "-e",
                "--field-separator",
                "--assign",
                "--file",
                "--source",
                "--posix",
                "--traditional",
                "--re-interval",
            ],
            value_flags: &[
                "-F",
                "-v",
                "-f",
                "-e",
                "--field-separator",
                "--assign",
                "--file",
                "--source",
            ],
            max_operands: usize::MAX,
        }),
    ),
    (
        "yq",
        Inertness::OnlyWith(Guard {
            safe_flags: &[
                "-r",
                "-o",
                "-p",
                "-P",
                "-n",
                "-e",
                "-N",
                "--output-format",
                "--input-format",
                "--prettyPrint",
                "--no-colors",
                "--raw-output",
                "--exit-status",
                "--null-input",
            ],
            value_flags: &["-o", "-p", "--output-format", "--input-format"],
            max_operands: usize::MAX,
        }),
    ),
    (
        "env",
        Inertness::OnlyWith(Guard {
            safe_flags: &[
                "-i",
                "-u",
                "-0",
                "--ignore-environment",
                "--unset",
                "--null",
            ],
            value_flags: &["-u", "--unset"],
            max_operands: usize::MAX,
        }),
    ),
    (
        "tree",
        Inertness::OnlyWith(Guard {
            // `-o FILE` redirects tree's output into FILE, truncating it.
            safe_flags: &[
                "-a",
                "-d",
                "-l",
                "-f",
                "-x",
                "-L",
                "-R",
                "-P",
                "-I",
                "-N",
                "-q",
                "-p",
                "-u",
                "-g",
                "-s",
                "-h",
                "-D",
                "-F",
                "-i",
                "-r",
                "-t",
                "-c",
                "-v",
                "-U",
                "-X",
                "-J",
                "-Q",
                "-n",
                "-C",
                "-H",
                "-T",
                "--ignore-case",
                "--matchdirs",
                "--noreport",
                "--charset",
                "--si",
                "--du",
                "--timefmt",
                "--inodes",
                "--device",
                "--sort",
                "--dirsfirst",
                "--filesfirst",
                "--nolinks",
                "--version",
                "--help",
            ],
            value_flags: &[
                "-L",
                "-P",
                "-I",
                "-H",
                "-T",
                "--charset",
                "--timefmt",
                "--sort",
            ],
            max_operands: usize::MAX,
        }),
    ),
];

fn read_only_terms(tok: &str) -> Option<&'static Inertness> {
    READ_ONLY
        .iter()
        .find(|(name, _)| *name == tok)
        .map(|(_, terms)| terms)
}

/// Whether this one invocation is provably a read. A program absent from the
/// table is not read-only — the default is restrictive by construction.
fn invocation_is_read_only(tok: &str, args: &[&str]) -> bool {
    match read_only_terms(tok) {
        None => false,
        Some(Inertness::Always) => true,
        Some(Inertness::OnlyWith(guard)) => guard_permits(tok, guard, args),
    }
}

fn guard_permits(tok: &str, guard: &Guard, args: &[&str]) -> bool {
    let mut operands: Vec<&str> = Vec::new();
    let mut expect_value = false;

    for arg in args {
        if expect_value {
            expect_value = false;
            continue;
        }
        if *arg == "--" {
            continue;
        }
        if arg.starts_with('-') && arg.len() > 1 {
            // A flag may carry its value inline (`--key=1`, `-i.bak`), so compare
            // the name only. Short groups (`-ni`) are checked letter by letter,
            // since sed's in-place flag hides happily inside one.
            let name = arg.split('=').next().unwrap_or(arg);
            let recognized = if name.starts_with("--") {
                guard.safe_flags.contains(&name)
            } else {
                name.chars()
                    .skip(1)
                    .all(|ch| guard.safe_flags.contains(&format!("-{}", ch).as_str()))
            };
            if !recognized {
                return false;
            }
            if !arg.contains('=') && guard.value_flags.contains(&name) {
                expect_value = true;
            }
            continue;
        }
        operands.push(arg);
    }

    if operands.len() > guard.max_operands {
        return false;
    }

    match tok {
        // GNU sed's `w FILE` and `s///w FILE` write with no flag and no redirect.
        "sed" => !operands.iter().any(|program| sed_program_writes(program)),
        // `system()` runs an arbitrary command. A `print >` redirect is already
        // rejected by the `>` check.
        "awk" => !args.iter().any(|a| a.contains("system(")),
        // `env FOO=1 cmd` runs an arbitrary downstream program; only assignments
        // and flags are inert.
        "env" => !operands.iter().any(|a| !a.contains('=')),
        _ => true,
    }
}

/// Whether a sed program contains a write command.
///
/// Conservative: a `w` or `W` in command position — starting the program, or after
/// `;`, `{`, `}`, or the closing `/` of a substitution — followed by whitespace and
/// a filename. A false positive here costs a prompt, so erring toward yes is right.
fn sed_program_writes(program: &str) -> bool {
    for (i, ch) in program.char_indices() {
        if ch != 'w' && ch != 'W' {
            continue;
        }
        let in_command_position = match program[..i].chars().next_back() {
            None => true,
            Some(prev) => matches!(prev, ';' | '{' | '}' | '/'),
        };
        if !in_command_position {
            continue;
        }
        let rest = &program[i + ch.len_utf8()..];
        if rest.starts_with(char::is_whitespace) && !rest.trim().is_empty() {
            return true;
        }
    }
    false
}

/// Stricter than [`is_read_only_command`]: every segment must name a program that
/// is inert at *any* flags.
///
/// The two questions carry different risk. Waiving the fence for a misjudged
/// command skips a prompt on a path outside the project. Waiving self-protection
/// for one hands over `railguard.yaml`, so a program whose flags we had to reason
/// about at all must not be able to buy that waiver.
fn cannot_write_any_file(cmd: &str) -> bool {
    is_read_only_command(cmd)
        && segments(cmd).all(|seg| {
            let tok = seg.split_whitespace().next().unwrap_or("");
            matches!(read_only_terms(tok), Some(Inertness::Always))
                || matches!(tok, "cd" | "pushd" | "popd")
        })
}

/// One notch down the restrictiveness lattice for a caller that cannot write:
/// a block becomes an approval, an approval becomes an allow.
///
/// Reading `railguard.yaml` is not a threat; writing it is. Routing every call
/// through the guard without this turned `grep -rn '\.railguard' src/` into an
/// unappealable deny, since the state rule's action is `block` — and on Codex
/// there is no approval path to appeal to at all.
fn soften_if_read_only(decision: Decision, read_only: bool) -> Decision {
    if !read_only {
        return decision;
    }
    match decision {
        Decision::Block { rule, message } => Decision::Approve { rule, message },
        Decision::Approve { .. } | Decision::Allow => Decision::Allow,
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
        // Log paths only, never the patch body — a patch carries file contents,
        // and the trace is a long-lived audit log.
        "Write" | "Edit" | "Read" | "apply_patch" => {
            let paths = extract_file_paths(tool_name, tool_input);
            if paths.is_empty() {
                "(unknown path)".to_string()
            } else {
                paths.join(", ")
            }
        }
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
    use crate::types::{FenceConfig, MemoryConfig, SnapshotConfig, TraceConfig};
    use serde_json::json;

    fn codex_input(cwd: &Path, session_id: &str, command: &str) -> HookInput {
        HookInput {
            session_id: session_id.to_string(),
            cwd: cwd.display().to_string(),
            hook_event_name: "PreToolUse".to_string(),
            tool_name: Some("Bash".to_string()),
            tool_input: Some(json!({"command": command})),
            tool_use_id: Some("call-1".to_string()),
            tool_response: None,
            timestamp: None,
            model: Some("gpt-codex".to_string()),
        }
    }

    fn quiet_policy() -> Policy {
        Policy {
            version: 1,
            blocklist: vec![],
            approve: vec![],
            allowlist: vec![],
            fence: FenceConfig {
                enabled: false,
                ..Default::default()
            },
            trace: TraceConfig {
                enabled: false,
                ..Default::default()
            },
            snapshot: SnapshotConfig {
                enabled: false,
                ..Default::default()
            },
            memory: MemoryConfig {
                enabled: false,
                ..Default::default()
            },
        }
    }

    #[test]
    fn codex_does_not_auto_approve_after_approval_denial() {
        let dir = tempfile::tempdir().unwrap();
        let input = codex_input(dir.path(), "codex-no-auto-approve", "rev <<< x | sh");

        for _ in 0..2 {
            let result = handle(&input, &quiet_policy(), HookClient::Codex);
            assert_eq!(
                result
                    .output
                    .hook_specific_output
                    .unwrap()
                    .permission_decision,
                Some("deny".to_string())
            );
        }

        let state_dir = SessionState::locate_state_dir(dir.path(), &input.session_id);
        let state = SessionState::load(&state_dir, &input.session_id);
        assert!(state.session_approvals.is_empty());
        assert!(state.pending_approval.is_none());
    }
}
