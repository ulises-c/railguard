use regex::Regex;

use crate::block::evasion::normalize_command;
use crate::types::{Decision, Rule};

pub fn rule_applies_to_tool(rule_tool: &str, tool_name: &str) -> bool {
    rule_tool == "*"
        || rule_tool == tool_name
        || (tool_name == "apply_patch" && matches!(rule_tool, "Write" | "Edit"))
}

/// Match a command against a list of rules.
/// Normalizes the command first to defeat evasion attempts.
pub fn match_rules(command: &str, rules: &[Rule]) -> Decision {
    let variants = normalize_command(command);

    for rule in rules {
        let re = match Regex::new(&rule.pattern) {
            Ok(r) => r,
            Err(_) => continue,
        };

        for variant in &variants {
            if re.is_match(variant) {
                let message = rule
                    .message
                    .clone()
                    .unwrap_or_else(|| format!("Matched rule: {}", rule.name));

                return match rule.action.as_str() {
                    "block" => Decision::Block {
                        rule: rule.name.clone(),
                        message,
                    },
                    "approve" => Decision::Approve {
                        rule: rule.name.clone(),
                        message,
                    },
                    _ => Decision::Block {
                        rule: rule.name.clone(),
                        message,
                    },
                };
            }
        }
    }

    Decision::Allow
}

/// Check if a tool + input combination matches any rule.
/// For non-Bash tools, checks tool_input JSON fields against patterns.
pub fn evaluate_tool(tool_name: &str, tool_input: &serde_json::Value, rules: &[Rule]) -> Decision {
    let applicable_rules: Vec<&Rule> = rules
        .iter()
        .filter(|r| rule_applies_to_tool(&r.tool, tool_name))
        .collect();

    if applicable_rules.is_empty() {
        return Decision::Allow;
    }

    // For Bash tool, match against the command string
    if tool_name == "Bash" {
        if let Some(cmd) = tool_input.get("command").and_then(|v| v.as_str()) {
            let owned_rules: Vec<Rule> = applicable_rules.into_iter().cloned().collect();
            return match_rules(cmd, &owned_rules);
        }
    }

    // For Write/Edit/Read tools, match against file_path
    if matches!(tool_name, "Write" | "Edit" | "Read" | "apply_patch") {
        let paths = crate::fence::path::extract_file_paths(tool_name, tool_input);
        if !paths.is_empty() {
            for rule in &applicable_rules {
                let re = match Regex::new(&rule.pattern) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                if paths.iter().any(|path| re.is_match(path)) {
                    let message = rule
                        .message
                        .clone()
                        .unwrap_or_else(|| format!("Matched rule: {}", rule.name));
                    return match rule.action.as_str() {
                        "block" => Decision::Block {
                            rule: rule.name.clone(),
                            message,
                        },
                        "approve" => Decision::Approve {
                            rule: rule.name.clone(),
                            message,
                        },
                        _ => Decision::Block {
                            rule: rule.name.clone(),
                            message,
                        },
                    };
                }
            }
            return Decision::Allow;
        }
    }

    // For tools without dedicated handling, serialize the entire input and match
    let input_str = serde_json::to_string(tool_input).unwrap_or_default();
    for rule in &applicable_rules {
        let re = match Regex::new(&rule.pattern) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if re.is_match(&input_str) {
            let message = rule
                .message
                .clone()
                .unwrap_or_else(|| format!("Matched rule: {}", rule.name));
            return match rule.action.as_str() {
                "block" => Decision::Block {
                    rule: rule.name.clone(),
                    message,
                },
                "approve" => Decision::Approve {
                    rule: rule.name.clone(),
                    message,
                },
                _ => Decision::Block {
                    rule: rule.name.clone(),
                    message,
                },
            };
        }
    }

    Decision::Allow
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_rule(name: &str, pattern: &str, action: &str) -> Rule {
        Rule {
            name: name.to_string(),
            tool: "Bash".to_string(),
            pattern: pattern.to_string(),
            action: action.to_string(),
            message: None,
        }
    }

    #[test]
    fn test_block_terraform_destroy() {
        let rules = vec![make_rule("no-destroy", r"terraform\s+destroy", "block")];
        let decision = match_rules("terraform destroy", &rules);
        assert!(matches!(decision, Decision::Block { .. }));
    }

    #[test]
    fn test_allow_safe_command() {
        let rules = vec![make_rule("no-destroy", r"terraform\s+destroy", "block")];
        let decision = match_rules("npm test", &rules);
        assert!(matches!(decision, Decision::Allow));
    }

    #[test]
    fn test_approve_rule() {
        let rules = vec![make_rule("prod-db", r"psql.*prod", "approve")];
        let decision = match_rules("psql -h prod-db.example.com", &rules);
        assert!(matches!(decision, Decision::Approve { .. }));
    }

    #[test]
    fn test_evaluate_bash_tool() {
        let rules = vec![make_rule("no-destroy", r"terraform\s+destroy", "block")];
        let input = json!({"command": "terraform destroy"});
        let decision = evaluate_tool("Bash", &input, &rules);
        assert!(matches!(decision, Decision::Block { .. }));
    }

    #[test]
    fn test_evaluate_write_tool() {
        let rules = vec![Rule {
            name: "no-ssh".to_string(),
            tool: "Write".to_string(),
            pattern: r"\.ssh".to_string(),
            action: "block".to_string(),
            message: Some("Cannot write to .ssh directory".to_string()),
        }];
        let input = json!({"file_path": "/home/user/.ssh/authorized_keys", "content": "key"});
        let decision = evaluate_tool("Write", &input, &rules);
        assert!(matches!(decision, Decision::Block { .. }));
    }

    #[test]
    fn test_write_content_mentioning_pattern_allowed() {
        let rules = vec![Rule {
            name: "railguard-config-edit".to_string(),
            tool: "Write".to_string(),
            pattern: r"railguard\.yaml".to_string(),
            action: "approve".to_string(),
            message: None,
        }];
        let input = json!({
            "file_path": "/tmp/notes.md",
            "content": "the allowed_paths workaround in railguard.yaml can be dropped"
        });
        let decision = evaluate_tool("Write", &input, &rules);
        assert!(matches!(decision, Decision::Allow));
    }

    #[test]
    fn test_codex_apply_patch_uses_write_and_edit_rules() {
        let rules = vec![Rule {
            name: "railguard-config-edit".to_string(),
            tool: "Write".to_string(),
            pattern: r"railguard\.yaml".to_string(),
            action: "approve".to_string(),
            message: None,
        }];
        let input = json!({
            "command": "*** Begin Patch\n*** Update File: railguard.yaml\n@@\n-old\n+new\n*** End Patch"
        });
        let decision = evaluate_tool("apply_patch", &input, &rules);
        assert!(matches!(decision, Decision::Approve { .. }));
    }

    #[test]
    fn test_unhandled_tool_matches_serialized_input() {
        let rules = vec![Rule {
            name: "no-internal-fetch".to_string(),
            tool: "WebFetch".to_string(),
            pattern: r"internal\.example\.com".to_string(),
            action: "block".to_string(),
            message: None,
        }];
        let input = json!({"url": "https://internal.example.com/secrets"});
        let decision = evaluate_tool("WebFetch", &input, &rules);
        assert!(matches!(decision, Decision::Block { .. }));
    }

    #[test]
    fn test_evasion_blocked() {
        let rules = vec![make_rule("no-destroy", r"terraform\s+destroy", "block")];
        // Base64 encoded "terraform destroy"
        let decision = match_rules(
            "echo dGVycmFmb3JtIGRlc3Ryb3k= | base64 --decode | sh",
            &rules,
        );
        assert!(matches!(decision, Decision::Block { .. }));
    }

    #[test]
    fn test_evasion_shell_wrapper() {
        let rules = vec![make_rule("no-rm", r"rm\s+-rf\s+/", "block")];
        let decision = match_rules(r#"sh -c "rm -rf /""#, &rules);
        assert!(matches!(decision, Decision::Block { .. }));
    }
}
