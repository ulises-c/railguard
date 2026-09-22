use std::path::Path;
use std::time::Instant;

use crate::fence::path::extract_file_paths;
use crate::threat::state::SessionState;
use crate::trace::logger::log_trace;
use crate::types::{HookInput, Policy, TraceEntry};

/// Promote the pending approval if this completion is the one we asked about.
fn resolve_approval_on_completion(input: &HookInput) {
    let cwd = Path::new(&input.cwd);
    let state_dir = SessionState::locate_state_dir(cwd, &input.session_id);
    let mut state = SessionState::load(&state_dir, &input.session_id);
    if state.resolve_pending_approval_for(input.tool_use_id.as_deref()) {
        let _ = state.save(&state_dir);
    }
}

/// Handle a PostToolUse event.
/// Logs the completed tool call for tracing.
pub fn handle(input: &HookInput, policy: &Policy) {
    // Before the trace guard: this is enforcement, not observability.
    //
    // Reaching PostToolUse is the proof that PreToolUse's `ask` was answered
    // *yes* — a denied call never runs, so it never gets here. Resolving the
    // pending approval anywhere else means guessing, and the previous guess ("a
    // later tool call arrived, so they must have approved") turned every denial
    // into a session-wide allow for that pattern.
    resolve_approval_on_completion(input);

    if !policy.trace.enabled {
        return;
    }

    let start = Instant::now();
    let tool_name = input.tool_name.as_deref().unwrap_or("unknown");
    let tool_input = input.tool_input.clone().unwrap_or_default();

    let input_summary = match tool_name {
        "Bash" => tool_input
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)")
            .chars()
            .take(200)
            .collect(),
        "Write" | "Edit" | "Read" => tool_input
            .get("file_path")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)")
            .to_string(),
        _ => serde_json::to_string(&tool_input)
            .unwrap_or_default()
            .chars()
            .take(200)
            .collect(),
    };

    let trace_dir = crate::trace::logger::global_trace_dir();

    let entry = TraceEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        session_id: input.session_id.clone(),
        event: "PostToolUse".to_string(),
        tool: tool_name.to_string(),
        input_summary,
        decision: "completed".to_string(),
        rule: None,
        duration_ms: start.elapsed().as_millis() as u64,
    };

    if let Err(e) = log_trace(&trace_dir, &input.session_id, &entry) {
        let _ = e;
    }

    // Update heartbeat on file locks for Write/Edit
    if matches!(tool_name, "Write" | "Edit" | "apply_patch") {
        for file_path in extract_file_paths(tool_name, &tool_input) {
            crate::coord::lock::heartbeat(&file_path, &input.session_id);
        }
    }
}
