use std::path::Path;

use crate::memory::guard as memory_guard;
use crate::threat::killer::format_restart_warning;
use crate::threat::state::SessionState;
use crate::trace::logger::log_trace;
use crate::types::{HookInput, HookOutput, Policy, TraceEntry};
use crate::update;

/// How many flagged files the SessionStart warning names inline.
const MEMORY_WARNING_SAMPLE: usize = 3;

/// Format the memory-integrity warning injected at SessionStart.
///
/// Only a sample of the flagged files is named. This fires on every session
/// start and the list grows with the number of flagged files, so a full
/// enumeration turns into a large block of agent context that gates nothing —
/// the summary line already points at `railguard memory verify`, which prints
/// the complete list on demand.
fn format_memory_warning(warnings: &[String]) -> String {
    let mut msg = format!(
        "⚠️ Railguard Memory: {} memory file(s) have integrity issues. Run `railguard memory verify` for details.",
        warnings.len()
    );
    for w in warnings.iter().take(MEMORY_WARNING_SAMPLE) {
        msg.push_str(&format!("\n  • {}", w));
    }
    let remaining = warnings.len().saturating_sub(MEMORY_WARNING_SAMPLE);
    if remaining > 0 {
        msg.push_str(&format!("\n  • …and {} more", remaining));
    }
    msg
}

/// Handle a SessionStart event.
/// Logs the session initialization and warns about previous terminations.
/// Returns a HookOutput with optional update notification.
pub fn handle(input: &HookInput, policy: &Policy) -> HookOutput {
    let cwd = Path::new(&input.cwd);

    // Check for updates (at most once per week)
    let update_message = update::check_for_update(cwd);

    // Anchor the session: the path fence evaluates against this root for the
    // whole session, immune to shell cwd drift from cd's into subdirectories.
    // Persist the anchor ONLY when cwd is inside a real git project — a launch
    // dir outside any repo (~, /tmp, a scratch dir) is an untrustworthy bare
    // cwd that must not become the sticky session anchor, or it would drop the
    // real project's allowed_paths once the agent cd's into the actual project.
    // This mirrors the trustworthiness gate in pre_tool::handle.
    let sessions_dir = crate::trace::logger::global_sessions_dir();
    if let Some(project_root) = SessionState::anchor_to_persist(cwd) {
        let state_dir = project_root.join(".railguard/state");
        let mut state = SessionState::load(&state_dir, &input.session_id);
        state.project_root = Some(project_root.display().to_string());
        let _ = state.save(&state_dir);
        SessionState::write_global_pointer(&sessions_dir, &input.session_id, &project_root);
    }
    SessionState::cleanup_old_pointers(&sessions_dir);

    // Local-state housekeeping is keyed off the best-effort project root even
    // when no anchor was persisted (a non-repo launch dir still has a state dir).
    let project_root = SessionState::find_project_root(cwd);
    let state_dir = project_root.join(".railguard/state");

    // Check for recently terminated sessions and warn
    let terminated = SessionState::find_recent_terminations(&state_dir);
    if !terminated.is_empty() {
        for state in &terminated {
            let warning = format_restart_warning(state);
            eprintln!("{}", warning);
            eprintln!();
        }
    }

    // Clean up old state files (>24h)
    SessionState::cleanup_old_states(&state_dir);

    if policy.trace.enabled {
        let trace_dir = crate::trace::logger::global_trace_dir();

        let entry = TraceEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            session_id: input.session_id.clone(),
            event: "SessionStart".to_string(),
            tool: "-".to_string(),
            input_summary: format!("Session started in {}", input.cwd),
            decision: "allow".to_string(),
            rule: None,
            duration_ms: 0,
        };

        if let Err(e) = log_trace(&trace_dir, &input.session_id, &entry) {
            let _ = e;
        }
    }

    // Verify memory integrity (if enabled)
    let memory_message = if policy.memory.enabled && policy.memory.verify_on_read {
        let warnings = memory_guard::verify_memory_integrity(cwd);
        if warnings.is_empty() {
            None
        } else {
            Some(format_memory_warning(&warnings))
        }
    } else {
        None
    };

    // Release any stale locks from a previous run of this session
    crate::coord::lock::release_all(&input.session_id);

    // Build combined session message
    let coord_message = crate::coord::context::session_context_message(&input.session_id);

    let messages: Vec<String> = [update_message, coord_message, memory_message]
        .into_iter()
        .flatten()
        .collect();

    let combined = if messages.is_empty() {
        None
    } else {
        Some(messages.join("\n\n"))
    };

    match combined {
        Some(msg) => HookOutput::session_message(&msg),
        None => HookOutput::noop(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn warnings(n: usize) -> Vec<String> {
        (0..n)
            .map(|i| {
                format!(
                    "~/.claude/projects/p{}/memory/file_{}.md: no provenance record",
                    i, i
                )
            })
            .collect()
    }

    #[test]
    fn names_every_file_when_under_the_sample_size() {
        let msg = format_memory_warning(&warnings(2));
        assert!(msg.contains("2 memory file(s)"));
        assert!(msg.contains("file_0.md"));
        assert!(msg.contains("file_1.md"));
        assert!(!msg.contains("and 0 more"));
    }

    #[test]
    fn caps_the_list_and_counts_the_remainder() {
        let msg = format_memory_warning(&warnings(24));
        // The true count still leads the message; only the listing is capped.
        assert!(msg.contains("24 memory file(s)"));
        assert_eq!(msg.matches("  • ").count(), MEMORY_WARNING_SAMPLE + 1);
        assert!(msg.contains("…and 21 more"));
        assert!(!msg.contains("file_23.md"));
    }

    #[test]
    fn stays_bounded_as_the_flagged_count_grows() {
        // The point of the cap: message size must not track the file count.
        let small = format_memory_warning(&warnings(5)).len();
        let huge = format_memory_warning(&warnings(500)).len();
        assert!(
            huge - small < 40,
            "message grew {} bytes between 5 and 500 flagged files",
            huge - small
        );
    }

    #[test]
    fn always_points_at_the_command_that_prints_the_full_list() {
        for n in [1, 3, 4, 100] {
            assert!(format_memory_warning(&warnings(n)).contains("railguard memory verify"));
        }
    }
}
