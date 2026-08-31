use crate::block::matcher::{match_rules, restrictiveness};
use crate::fence::path::absolutize_from;
use crate::types::{Decision, Rule};
use std::path::{Path, PathBuf};

/// A resource whose modification disarms Railguard, and what touching it costs.
struct Resource {
    path: PathBuf,
    /// True when everything *under* `path` is protected too.
    is_tree: bool,
    rule: &'static str,
    block: bool,
    message: &'static str,
}

/// Every resource whose modification disarms Railguard, as canonical absolute
/// paths.
///
/// This used to be a set of regexes matched against raw command text, which was
/// wrong in both directions at once. It missed anything that reached a protected
/// file without naming it — an in-project symlink pointing at the policy meant
/// `Write policy-link` rewrote `railguard.yaml` unrecorded — and it missed the
/// installed executable entirely. Meanwhile it fired on any command that merely
/// *mentioned* a filename, so appending `# railguard.yaml` to a blocked command
/// downgraded it to an approval labelled as a policy edit.
///
/// Comparing resolved identities fixes both: a symlink and a `..` detour land on
/// the same canonical path, and a filename inside a comment resolves to nothing.
fn resources(project_root: &Path) -> Vec<Resource> {
    let mut out = Vec::new();
    let mut push =
        |path: PathBuf, is_tree: bool, rule: &'static str, block: bool, message: &'static str| {
            out.push(Resource {
                path,
                is_tree,
                rule,
                block,
                message,
            });
        };

    const POLICY_MSG: &str = "Modifying Railguard policy requires human approval";
    for name in [
        "railguard.yaml",
        "railguard.yml",
        "railguard.local.yaml",
        ".railguard.local.yaml",
    ] {
        push(
            project_root.join(name),
            false,
            "railguard-protect-policy",
            false,
            POLICY_MSG,
        );
    }

    push(
        project_root.join(".railguard"),
        true,
        "railguard-protect-state",
        true,
        "Blocked: agents cannot modify Railguard state or snapshots",
    );

    if let Some(home) = dirs::home_dir() {
        for name in ["railguard.yaml", "railguard.yml"] {
            push(
                home.join(name),
                false,
                "railguard-protect-policy",
                false,
                POLICY_MSG,
            );
        }
        const HOOK_MSG: &str = "Blocked: agents cannot modify Railguard hook settings";
        push(
            home.join(".claude").join("settings.json"),
            false,
            "railguard-protect-hooks",
            true,
            HOOK_MSG,
        );
        for name in ["hooks.json", "config.toml"] {
            push(
                home.join(".codex").join(name),
                false,
                "railguard-protect-hooks",
                true,
                HOOK_MSG,
            );
        }
    }

    // The binary the hook actually runs. A truncated or overwritten executable is
    // the strongest possible disarm: the installer's own note says a hook that
    // fails or times out does not block the tool call, so a corrupted binary is a
    // silent fail-open. The old default rule matched only `rm|unlink|mv` against a
    // hard-coded `.cargo/bin/railguard`, missing `cp`, `install`, `truncate`,
    // redirects, `Write`, and every install location but one.
    const BINARY_MSG: &str = "Blocked: agents cannot modify the Railguard binary";
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            push(
                dir.join("railguard-shell"),
                false,
                "railguard-protect-binary",
                true,
                BINARY_MSG,
            );
        }
        push(exe, false, "railguard-protect-binary", true, BINARY_MSG);
    }

    out
}

/// Worst decision across every path a call names, compared by resolved identity.
///
/// Callers must evaluate this *before* [`crate::policy::engine::evaluate`] and let
/// a non-`Allow` result stand. Ordering is not cosmetic: normal evaluation consults
/// the allowlist first, so a single injected `{tool: "*", pattern: "", action:
/// allow}` rule matches every command and voids the built-in rules that would
/// otherwise stop the follow-up. A guard that ran inside the policy could be waved
/// through by the very policy write it is meant to prevent.
///
/// Every resource is compared against every path and the most restrictive verdict
/// wins. Returning the first match instead let a `.railguard` deletion be reported
/// — and authorized — as a policy edit, purely because the policy rule was listed
/// first.
pub fn check_paths<'a>(
    candidates: impl IntoIterator<Item = &'a str>,
    call_cwd: &str,
    project_root: &str,
) -> Decision {
    let resources = resources(Path::new(&absolutize_from(project_root, call_cwd)));
    let mut worst = Decision::Allow;

    for candidate in candidates {
        if candidate.trim().is_empty() {
            continue;
        }
        let resolved = PathBuf::from(absolutize_from(candidate, call_cwd));
        for resource in &resources {
            let target = PathBuf::from(absolutize_from(
                &resource.path.display().to_string(),
                call_cwd,
            ));
            let hit = if resource.is_tree {
                resolved.starts_with(&target)
            } else {
                resolved == target
            };
            if !hit {
                continue;
            }
            let decision = if resource.block {
                Decision::Block {
                    rule: resource.rule.to_string(),
                    message: resource.message.to_string(),
                }
            } else {
                Decision::Approve {
                    rule: resource.rule.to_string(),
                    message: resource.message.to_string(),
                }
            };
            if restrictiveness(&decision) > restrictiveness(&worst) {
                worst = decision;
            }
        }
    }

    worst
}

/// Every word of a shell command that could name a file.
///
/// Over-collecting is safe here and under-collecting is not. Candidates are
/// compared by resolved identity, so a word like `s/true/false/` simply resolves to
/// a path that is not protected — while a bare `railguard.yaml`, which the fence's
/// extractor skips because a project-relative name cannot escape the project, is
/// exactly the operand that matters to self-protection.
pub fn command_path_candidates(command: &str) -> Vec<String> {
    command
        .split_whitespace()
        .map(|word| {
            word.trim_matches(|c| matches!(c, '\'' | '"' | '`' | ';' | ',' | '(' | ')' | '{' | '}'))
        })
        .filter(|word| !word.is_empty() && !word.starts_with('-'))
        .map(str::to_string)
        .collect()
}

/// Railguard's own subcommands, which are commands rather than resources and so
/// still have to be recognized in command text.
///
/// These live here rather than in the defaults because `merge_with_defaults` lets
/// any policy suppress a default rule by reusing its name, and a rule a hostile
/// policy can name away is not a kill switch. Text matching remains defeatable by
/// one level of indirection (`R=$BIN; $R resume`), so treat this as defense in
/// depth — the real boundary for `resume` is the out-of-band confirmation dialog.
fn command_rules() -> Vec<Rule> {
    vec![
        Rule {
            name: "railguard-protect-uninstall".to_string(),
            tool: "*".to_string(),
            pattern: r"\brailguard\s+uninstall\b".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: agents cannot uninstall Railguard".to_string()),
        },
        Rule {
            name: "railguard-protect-resume".to_string(),
            tool: "*".to_string(),
            pattern: r"\brailguard\s+resume\b".to_string(),
            action: "block".to_string(),
            message: Some(
                "Blocked: clearing a terminated session is a human action — run \
                 `railguard resume` in your own terminal"
                    .to_string(),
            ),
        },
        Rule {
            name: "railguard-protect-update".to_string(),
            tool: "*".to_string(),
            pattern: r"\brailguard\s+update\b".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: replacing the Railguard binary is a human action".to_string()),
        },
    ]
}

/// Worst decision across the command text a call carries, for Railguard's own
/// subcommands only.
pub fn check_commands(command: &str) -> Decision {
    if command.trim().is_empty() {
        return Decision::Allow;
    }
    match_rules(command, &command_rules())
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

    fn project() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("railguard.yaml"), "version: 1\n").unwrap();
        std::fs::create_dir_all(dir.path().join(".railguard/state")).unwrap();
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("README.md"), "hi").unwrap();
        dir
    }

    fn check_in(dir: &tempfile::TempDir, value: &str) -> Decision {
        let root = dir.path().to_str().unwrap();
        check_paths([value], root, root)
    }

    #[test]
    fn policy_write_needs_approval_from_any_vector() {
        let dir = project();
        for value in [
            "railguard.yaml",
            "./railguard.yaml",
            "sub/../railguard.yaml",
        ] {
            let decision = check_in(&dir, value);
            assert!(
                matches!(decision, Decision::Approve { .. }),
                "expected approval for {value:?}, got {decision:?}"
            );
            assert_eq!(rule_of(&decision), "railguard-protect-policy");
        }
    }

    /// A symlink is the same resource under a different name.
    #[cfg(unix)]
    #[test]
    fn a_symlink_to_the_policy_is_the_policy() {
        let dir = project();
        std::os::unix::fs::symlink(
            dir.path().join("railguard.yaml"),
            dir.path().join("link.yaml"),
        )
        .unwrap();
        assert!(matches!(
            check_in(&dir, "link.yaml"),
            Decision::Approve { .. }
        ));
    }

    #[test]
    fn state_tree_is_blocked() {
        let dir = project();
        for value in [".railguard", ".railguard/state", ".railguard/state/x.json"] {
            assert!(
                matches!(check_in(&dir, value), Decision::Block { .. }),
                "expected block for {value:?}"
            );
        }
    }

    /// The policy file and the state directory share a prefix as *text* but are
    /// different paths, so identity comparison cannot confuse them.
    #[test]
    fn the_state_tree_does_not_swallow_the_local_policy_file() {
        let dir = project();
        std::fs::write(dir.path().join(".railguard.local.yaml"), "").unwrap();
        assert_eq!(
            rule_of(&check_in(&dir, ".railguard.local.yaml")),
            "railguard-protect-policy"
        );
    }

    #[test]
    fn ordinary_paths_are_untouched() {
        let dir = project();
        for value in [
            "src/main.rs",
            "README.md",
            "myrailguard.yaml.bak",
            "docs/railguardian.md",
        ] {
            assert!(
                matches!(check_in(&dir, value), Decision::Allow),
                "expected allow for {value:?}"
            );
        }
    }

    /// Merely naming a protected file in a comment resolves to no path at all, so
    /// it can no longer mask a stricter decision elsewhere in the call.
    #[test]
    fn mentioning_the_policy_file_is_not_touching_it() {
        assert!(matches!(
            check_commands("terraform destroy # see railguard.yaml"),
            Decision::Allow
        ));
    }

    #[test]
    fn railguard_subcommands_are_blocked_in_command_text() {
        for command in [
            "railguard uninstall",
            "railguard resume",
            "railguard resume --session other",
            "railguard update",
        ] {
            assert!(
                matches!(check_commands(command), Decision::Block { .. }),
                "expected block for {command:?}"
            );
        }
    }

    #[test]
    fn worst_value_wins_across_a_multi_path_call() {
        let dir = project();
        let root = dir.path().to_str().unwrap();
        // A policy approve and a state block in one call: the block must win,
        // whichever order they arrive in.
        for pair in [
            ["railguard.yaml", ".railguard/state/x.json"],
            [".railguard/state/x.json", "railguard.yaml"],
        ] {
            let decision = check_paths(pair, root, root);
            assert_eq!(rule_of(&decision), "railguard-protect-state");
        }
    }
}
