use crate::block::matcher::{match_rules, restrictiveness};
use crate::types::{Decision, Rule};

/// Resources whose modification disarms Railguard: every policy filename the
/// loader will read, the agent hook configuration that causes the hook to run at
/// all, and the on-disk state and snapshots that block history and rollback
/// depend on.
///
/// Scoping self-protection to `Write` and `Edit`, where it used to live, left
/// every other write mechanism open — a Bash redirect (`printf … > railguard.yaml`)
/// and any filesystem-capable MCP tool both rewrote the policy unattended. The
/// policy is reloaded on every hook invocation, so one such write disabled the
/// fence for the very next tool call.
///
/// These rules are matched against the call's own text rather than dispatched by
/// tool name, so a tool nobody has heard of is covered on the same terms as
/// `Write`.
fn rules() -> Vec<Rule> {
    vec![
        Rule {
            name: "railguard-protect-policy".to_string(),
            tool: "*".to_string(),
            pattern: r"\brailguard(\.local)?\.ya?ml\b".to_string(),
            action: "approve".to_string(),
            message: Some("Modifying Railguard policy requires human approval".to_string()),
        },
        Rule {
            name: "railguard-protect-hooks".to_string(),
            tool: "*".to_string(),
            pattern: r"\.(claude[/\\]settings\.json|codex[/\\](hooks\.json|config\.toml))"
                .to_string(),
            action: "block".to_string(),
            message: Some("Blocked: agents cannot modify Railguard hook settings".to_string()),
        },
        Rule {
            name: "railguard-protect-state".to_string(),
            tool: "*".to_string(),
            pattern: r"\.railguard([/\\]|$)".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: agents cannot modify Railguard state or snapshots".to_string()),
        },
    ]
}

/// Worst decision across every value a call carries — its shell command, if any,
/// and each path it names, however that path was extracted.
///
/// Callers must evaluate this *before* [`crate::policy::engine::evaluate`] and
/// let a non-`Allow` result stand. Ordering is not cosmetic: normal evaluation
/// consults the allowlist first, so a single injected
/// `{tool: "*", pattern: "", action: allow}` rule matches every command and
/// voids the built-in rules that would otherwise stop the follow-up. A guard
/// that ran inside the policy could be waved through by the very policy write it
/// is meant to prevent.
///
/// Values are matched individually and the most restrictive wins, so a patch
/// cannot hide a protected path behind a benign one.
pub fn check<'a>(values: impl IntoIterator<Item = &'a str>) -> Decision {
    let rules = rules();
    let mut worst = Decision::Allow;
    for value in values {
        if value.is_empty() {
            continue;
        }
        let decision = match_rules(value, &rules);
        if restrictiveness(&decision) > restrictiveness(&worst) {
            worst = decision;
        }
    }
    worst
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_of(decision: &Decision) -> &str {
        match decision {
            Decision::Block { rule, .. } | Decision::Approve { rule, .. } => rule,
            Decision::Allow => "allow",
        }
    }

    #[test]
    fn policy_write_needs_approval_from_any_vector() {
        // Bash redirect, MCP path argument, and Write file_path are one gap.
        for value in [
            "printf 'fence: {enabled: false}' > railguard.yaml",
            "/home/u/project/railguard.yaml",
            "/home/u/project/.railguard.local.yaml",
            "subdir/railguard.yml",
            "tee .railguard.yaml",
        ] {
            let decision = check([value]);
            assert!(
                matches!(decision, Decision::Approve { .. }),
                "expected approval for {value:?}, got {decision:?}"
            );
            assert_eq!(rule_of(&decision), "railguard-protect-policy");
        }
    }

    #[test]
    fn hook_config_and_state_are_blocked() {
        for value in [
            "/home/u/.claude/settings.json",
            "/home/u/.codex/hooks.json",
            "/home/u/.codex/config.toml",
            "rm -rf .railguard",
            "/home/u/project/.railguard/state",
        ] {
            let decision = check([value]);
            assert!(
                matches!(decision, Decision::Block { .. }),
                "expected block for {value:?}, got {decision:?}"
            );
        }
    }

    #[test]
    fn ordinary_paths_are_untouched() {
        for value in [
            "src/main.rs",
            "notes.txt",
            "/home/u/project/README.md",
            "cargo test",
            // Near-misses that must not trip the guard.
            "myrailguard.yaml.bak",
            "docs/railguardian.md",
            "src/railguard_config.rs",
        ] {
            assert!(
                matches!(check([value]), Decision::Allow),
                "expected allow for {value:?}"
            );
        }
    }

    #[test]
    fn state_pattern_does_not_swallow_the_policy_file() {
        // `.railguard.local.yaml` must read as the policy file (approve), not as
        // the state directory (block) — the two patterns overlap on the prefix.
        let decision = check(["/home/u/project/.railguard.local.yaml"]);
        assert_eq!(rule_of(&decision), "railguard-protect-policy");
    }

    #[test]
    fn worst_value_wins_across_a_multi_path_call() {
        // An approve-level path must not mask a block-level one in the same call.
        let decision = check(["railguard.yaml", "/home/u/.claude/settings.json"]);
        assert!(matches!(decision, Decision::Block { .. }));
    }
}
