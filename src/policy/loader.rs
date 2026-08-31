use std::path::{Path, PathBuf};

use crate::types::Policy;

/// Find railguard.yaml by walking up from the given directory.
pub fn find_policy_file(start_dir: &Path) -> Option<PathBuf> {
    let mut current = start_dir.to_path_buf();
    loop {
        let candidate = current.join("railguard.yaml");
        if candidate.exists() {
            return Some(candidate);
        }
        let candidate = current.join("railguard.yml");
        if candidate.exists() {
            return Some(candidate);
        }
        let candidate = current.join(".railguard.yaml");
        if candidate.exists() {
            return Some(candidate);
        }
        if !current.pop() {
            break;
        }
    }
    None
}

/// Load and parse policy from a YAML file.
pub fn load_policy(path: &Path) -> Result<Policy, String> {
    let contents =
        std::fs::read_to_string(path).map_err(|e| format!("Failed to read policy: {}", e))?;
    let policy: Policy =
        serde_yaml::from_str(&contents).map_err(|e| format!("Failed to parse policy: {}", e))?;
    validate_policy(&policy)?;
    Ok(policy)
}

/// Load policy from directory, or return defaults if no file found.
/// Always merges built-in defaults — user rules are additive.
pub fn load_policy_or_defaults(cwd: &Path) -> Policy {
    let mut policy = match find_policy_file(cwd) {
        Some(path) => match load_policy(&path) {
            Ok(policy) => merge_with_defaults(policy),
            Err(e) => {
                eprintln!("railguard: warning: {}", e);
                default_policy()
            }
        },
        None => default_policy(),
    };
    apply_local_overrides(&mut policy, cwd);
    policy
}

/// Project-local, additive override file. Distinct from the `.railguard.yaml`
/// full-policy file that `find_policy_file` resolves.
const LOCAL_OVERRIDE_FILE: &str = ".railguard.local.yaml";

#[derive(Default, serde::Deserialize)]
struct LocalOverride {
    #[serde(default)]
    fence: LocalFenceOverride,
}

#[derive(Default, serde::Deserialize)]
struct LocalFenceOverride {
    #[serde(default)]
    allowed_paths: Vec<String>,
}

/// Walk up from `start_dir` for a project-local override file.
fn find_local_override_file(start_dir: &Path) -> Option<PathBuf> {
    let mut current = start_dir.to_path_buf();
    loop {
        let candidate = current.join(LOCAL_OVERRIDE_FILE);
        if candidate.exists() {
            return Some(candidate);
        }
        if !current.pop() {
            break;
        }
    }
    None
}

/// Apply a project-local `.railguard.local.yaml`. It may only *add* entries to
/// `fence.allowed_paths`; it cannot touch `denied_paths` or any other policy.
/// Honored only when the base policy opted in with `fence.allow_local_overrides:
/// true`, so a cloned or hostile repo cannot self-grant filesystem access. Even
/// when honored, denied paths still take precedence in the fence check, so the
/// override can never expose `~/.ssh`, `/etc`, etc.
fn apply_local_overrides(policy: &mut Policy, cwd: &Path) {
    if !policy.fence.allow_local_overrides {
        return;
    }
    let Some(path) = find_local_override_file(cwd) else {
        return;
    };
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("railguard: warning: cannot read {}: {}", path.display(), e);
            return;
        }
    };
    let overrides: LocalOverride = match serde_yaml::from_str(&contents) {
        Ok(o) => o,
        Err(e) => {
            eprintln!(
                "railguard: warning: ignoring invalid {}: {}",
                path.display(),
                e
            );
            return;
        }
    };
    for p in overrides.fence.allowed_paths {
        if !policy.fence.allowed_paths.contains(&p) {
            policy.fence.allowed_paths.push(p);
        }
    }
}

/// Merge user policy with built-in defaults.
/// Built-in rules are always prepended — users can override with allowlist.
/// Rules are split by action: "block" → blocklist, "approve" → approve list.
fn merge_with_defaults(mut policy: Policy) -> Policy {
    let defaults = crate::policy::defaults::default_blocklist();

    let user_rule_names: std::collections::HashSet<String> = policy
        .blocklist
        .iter()
        .chain(policy.approve.iter())
        .map(|r| r.name.clone())
        .collect();

    // Split defaults by action, excluding user-overridden rules
    let mut default_block = Vec::new();
    let mut default_approve = Vec::new();
    for rule in defaults {
        if user_rule_names.contains(&rule.name) {
            continue;
        }
        if rule.action == "approve" {
            default_approve.push(rule);
        } else {
            default_block.push(rule);
        }
    }

    // Prepend defaults before user rules
    default_block.append(&mut policy.blocklist);
    policy.blocklist = default_block;

    default_approve.append(&mut policy.approve);
    policy.approve = default_approve;

    policy
}

/// Default policy with built-in rules.
pub fn default_policy() -> Policy {
    let all_rules = crate::policy::defaults::default_blocklist();
    let (approve, blocklist): (Vec<_>, Vec<_>) =
        all_rules.into_iter().partition(|r| r.action == "approve");
    Policy {
        version: 1,
        blocklist,
        approve,
        allowlist: vec![],
        fence: Default::default(),
        trace: Default::default(),
        snapshot: Default::default(),
        memory: Default::default(),
    }
}

/// Validate that all regex patterns in the policy compile.
fn validate_policy(policy: &Policy) -> Result<(), String> {
    let all_rules = policy
        .blocklist
        .iter()
        .chain(policy.approve.iter())
        .chain(policy.allowlist.iter());

    for rule in all_rules {
        regex::Regex::new(&rule.pattern)
            .map_err(|e| format!("Invalid regex in rule '{}': {}", rule.name, e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_load_default_policy() {
        let policy = default_policy();
        assert!(!policy.blocklist.is_empty());
        assert!(policy.fence.enabled);
        assert!(policy.trace.enabled);
        assert!(policy.snapshot.enabled);
    }

    #[test]
    fn test_load_yaml_policy() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
blocklist:
  - name: test-rule
    tool: Bash
    pattern: "dangerous_command"
    action: block
    message: "Blocked for testing"
fence:
  enabled: true
  denied_paths:
    - "~/.ssh"
"#;
        let path = dir.path().join("railguard.yaml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(yaml.as_bytes()).unwrap();

        let policy = load_policy(&path).unwrap();
        assert_eq!(policy.blocklist.len(), 1);
        assert_eq!(policy.blocklist[0].name, "test-rule");
    }

    #[test]
    fn test_find_policy_file_walks_up() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("a/b/c");
        std::fs::create_dir_all(&sub).unwrap();

        let yaml_path = dir.path().join("railguard.yaml");
        std::fs::write(&yaml_path, "version: 1\n").unwrap();

        let found = find_policy_file(&sub);
        assert_eq!(found, Some(yaml_path));
    }

    #[test]
    fn test_invalid_regex_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
blocklist:
  - name: bad-regex
    tool: Bash
    pattern: "[invalid"
    action: block
"#;
        let path = dir.path().join("railguard.yaml");
        std::fs::write(&path, yaml).unwrap();

        let result = load_policy(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_local_override_adds_allowed_paths_when_opted_in() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("railguard.yaml"),
            "version: 1\nfence:\n  enabled: true\n  allow_local_overrides: true\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join(".railguard.local.yaml"),
            "fence:\n  allowed_paths:\n    - \"~/notes\"\n",
        )
        .unwrap();

        let policy = load_policy_or_defaults(dir.path());
        assert!(policy.fence.allowed_paths.iter().any(|p| p == "~/notes"));
    }

    #[test]
    fn test_local_override_honored_by_default() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("railguard.yaml"),
            "version: 1\nfence:\n  enabled: true\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join(".railguard.local.yaml"),
            "fence:\n  allowed_paths:\n    - \"~/notes\"\n",
        )
        .unwrap();

        let policy = load_policy_or_defaults(dir.path());
        assert!(policy.fence.allowed_paths.iter().any(|p| p == "~/notes"));
    }

    #[test]
    fn test_local_override_ignored_when_opted_out() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("railguard.yaml"),
            "version: 1\nfence:\n  enabled: true\n  allow_local_overrides: false\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join(".railguard.local.yaml"),
            "fence:\n  allowed_paths:\n    - \"~/notes\"\n",
        )
        .unwrap();

        let policy = load_policy_or_defaults(dir.path());
        assert!(!policy.fence.allowed_paths.iter().any(|p| p == "~/notes"));
    }

    #[test]
    fn test_local_override_cannot_weaken_denied_paths() {
        // Even opted in, the override only adds allowed_paths; denies are untouched.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("railguard.yaml"),
            "version: 1\nfence:\n  enabled: true\n  allow_local_overrides: true\n  denied_paths:\n    - \"~/.ssh\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join(".railguard.local.yaml"),
            "fence:\n  allowed_paths:\n    - \"~/.ssh\"\n  denied_paths: []\n",
        )
        .unwrap();

        let policy = load_policy_or_defaults(dir.path());
        assert!(policy.fence.denied_paths.iter().any(|p| p == "~/.ssh"));
    }
}
