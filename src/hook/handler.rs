use std::io::{Read, Write};
use std::path::Path;

use crate::hook::{post_tool, pre_tool, session};
use crate::policy::loader::load_policy_or_defaults;
use crate::threat::killer::terminate_session;
use crate::threat::state::SessionState;
use crate::types::{HookClient, HookInput, HookOutput};

/// Main hook entry point. Reads JSON from stdin, dispatches to the right handler.
pub fn run(event: &str, client: HookClient) -> i32 {
    // Read stdin
    let mut input_str = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input_str) {
        eprintln!("railguard: failed to read stdin: {}", e);
        return 0; // Don't block on read errors
    }

    // Parse input
    let input: HookInput = match serde_json::from_str(&input_str) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("railguard: failed to parse hook input: {}", e);
            return 0; // Don't block on parse errors
        }
    };
    let client = client.resolve(&input);

    // Load policy anchored at the session's stable project root, not the
    // per-call cwd. The shell cwd drifts as the agent cd's around; resolving
    // policy from a cwd outside the project tree finds no config (the walk-up
    // search comes up empty) and silently falls back to empty defaults,
    // dropping the project's allowed_paths and making the fence prompt for
    // paths the policy actually permits. Anchoring at the project root keeps
    // the policy — and the fence it feeds — stable for the whole session.
    let cwd = Path::new(&input.cwd);
    let sessions_dir = crate::trace::logger::global_sessions_dir();
    let project_root = SessionState::resolve_project_root(cwd, &input.session_id, &sessions_dir);
    let policy = load_policy_or_defaults(&project_root);

    // Dispatch
    match event {
        "PreToolUse" => {
            // Self-integrity check: verify hooks haven't been tampered with
            if let Some(output) = check_hook_integrity(client) {
                if let Ok(json) = serde_json::to_string(&output) {
                    let _ = std::io::stdout().write_all(json.as_bytes());
                    let _ = std::io::stdout().write_all(b"\n");
                    let _ = std::io::stdout().flush();
                }
                if client == HookClient::Claude {
                    eprintln!(
                        "\n\x1b[1;31m⚠️  RAILGUARD INTEGRITY VIOLATION\x1b[0m\n\
                         \x1b[31m   Railguard hooks have been removed or modified in ~/.claude/settings.json.\n\
                         \x1b[31m   This may indicate the agent tampered with its own guardrails.\n\
                         \x1b[31m   All tool calls are blocked until hooks are restored.\n\
                         \x1b[31m   Run: railguard install\x1b[0m\n"
                    );
                }
                return 0;
            }

            let result = pre_tool::handle(&input, &policy, client);

            // Write output to stdout
            if let Ok(json) = serde_json::to_string(&result.output) {
                let _ = std::io::stdout().write_all(json.as_bytes());
                let _ = std::io::stdout().write_all(b"\n");
                let _ = std::io::stdout().flush();
            }

            // If termination requested, flush output first then kill
            if let Some(req) = result.terminate {
                let state_dir =
                    crate::threat::state::SessionState::locate_state_dir(cwd, &input.session_id);
                let trace_dir = crate::trace::logger::global_trace_dir();
                let mut state = req.state;
                terminate_session(&mut state, &req.tier, &req.command, &state_dir, &trace_dir);
                // terminate_session sends SIGTERM to parent — exit cleanly
                std::process::exit(0);
            }

            0
        }
        "PostToolUse" => {
            post_tool::handle(&input, &policy);
            0
        }
        "SessionStart" => {
            let output = session::handle(&input, &policy);
            if let Ok(json) = serde_json::to_string(&output) {
                let _ = std::io::stdout().write_all(json.as_bytes());
                let _ = std::io::stdout().write_all(b"\n");
                let _ = std::io::stdout().flush();
            }
            0
        }
        _ => {
            eprintln!("railguard: unknown event: {}", event);
            0
        }
    }
}

/// Verify that Railguard's hooks are still present in ~/.claude/settings.json.
/// Returns Some(deny output) if hooks have been tampered with, None if OK.
///
/// Logic: If settings.json has hook entries for OTHER events but NOT PreToolUse
/// with railguard, that indicates tampering (someone selectively removed railguard).
/// If hooks is empty or missing entirely, we assume railguard isn't installed yet
/// (the fact we're running means Claude Code is calling us — don't block).
fn check_hook_integrity(client: HookClient) -> Option<HookOutput> {
    let home = dirs::home_dir()?;
    let settings_path = match client {
        HookClient::Auto => return None,
        HookClient::Claude => home.join(".claude").join("settings.json"),
        HookClient::Codex => home.join(".codex").join("hooks.json"),
    };

    let content = std::fs::read_to_string(&settings_path).ok()?;
    let settings: serde_json::Value = serde_json::from_str(&content).ok()?;

    let hooks = settings.get("hooks").and_then(|h| h.as_object())?;

    // If hooks is empty, not installed yet — not tampered
    if hooks.is_empty() {
        return None;
    }

    // Hooks exist but check if railguard is still among them
    let has_railguard = hooks.values().any(|entries| {
        let json_str = serde_json::to_string(entries).unwrap_or_default();
        json_str.contains("railguard")
    });

    if !has_railguard {
        // Hooks exist for other things but railguard was removed — tampering
        return Some(HookOutput::deny(&format!(
            "⛔ RAILGUARD INTEGRITY VIOLATION: Hooks removed from {}. \
             All tool calls blocked. The agent may have tampered with its own guardrails. \
             Run 'railguard install' to restore protection.",
            settings_path.display(),
        )));
    }

    // Railguard hooks present — check PreToolUse specifically
    let has_pre_tool = hooks
        .get("PreToolUse")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter().any(|entry| {
                let json_str = serde_json::to_string(entry).unwrap_or_default();
                json_str.contains("railguard")
            })
        })
        .unwrap_or(false);

    if !has_pre_tool {
        return Some(HookOutput::deny(&format!(
            "⛔ RAILGUARD INTEGRITY VIOLATION: PreToolUse hook removed from {}. \
             All tool calls blocked. Run 'railguard install' to restore protection.",
            settings_path.display(),
        )));
    }

    None
}
