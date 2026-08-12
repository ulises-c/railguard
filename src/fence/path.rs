use std::path::Path;

use crate::types::FenceConfig;

/// Appended to out-of-allowlist fence prompts (never to hard denials): these
/// are candidates for a policy allowlist entry, not safety blocks, so nudge
/// toward requesting the modification instead of repeated one-off approvals.
const ALLOWLIST_NUDGE: &str = " If this path is needed regularly, ask the human to allow it: add it to fence.allowed_paths in the project's .railguard.local.yaml (additive-only; denies always win) or in the global railguard.yaml. Details: `railguard guide`.";

/// Result of a path fence check.
#[derive(Debug, PartialEq)]
pub enum PathCheck {
    /// Path is allowed — no fence issue.
    Allow,
    /// Path is in an explicitly denied location (e.g. ~/.ssh, /etc) — hard block.
    Denied(String),
    /// Path is outside the project directory but not explicitly denied — ask the user.
    OutsideProject(String),
}

/// Check if a file path is allowed by the fence configuration.
///
/// All paths are canonicalized before checking — this resolves:
/// - Relative traversal (../)
/// - Symlinks pointing to denied locations
/// - Home directory expansions (~, $HOME)
pub fn check_path(config: &FenceConfig, file_path: &str, cwd: &str) -> PathCheck {
    check_path_from(config, file_path, cwd, cwd)
}

/// Same as [`check_path`], but resolves relative paths against `call_cwd` while
/// still measuring containment against `project_root`.
///
/// The two differ once the agent's shell has cd'd away from the project root.
/// Resolving `../etc/passwd` against the root instead of the shell's real cwd
/// yields a different file than the command actually touches, which can miss an
/// explicitly denied path entirely.
pub fn check_path_from(
    config: &FenceConfig,
    file_path: &str,
    project_root: &str,
    call_cwd: &str,
) -> PathCheck {
    if !config.enabled {
        return PathCheck::Allow;
    }

    // Always allow /dev/* paths — they're not real files
    if is_dev_path(file_path) {
        return PathCheck::Allow;
    }

    // `~user/...` — another account's home. Bash performs this expansion, so
    // leaving it unresolved meant the value stayed *relative*, was joined onto
    // the cwd, resolved inside the project, and passed: `cat ~someone/.ssh/id_rsa`
    // read the key. Resolving it is only a heuristic (see `expand_path`), and the
    // denied-path list is written against the *current* user's home, so a
    // resolved `~other/.ssh` would not match `~/.ssh` either. An agent has no
    // routine reason to reach into another account's home, so this is a hard
    // denial rather than an approval prompt — which, for a read-only command,
    // would be waived anyway.
    if let Some(user) = other_user_home(file_path) {
        return PathCheck::Denied(format!(
            "Path Fence: '{}' reaches into another user's home directory (~{})",
            file_path, user
        ));
    }

    let cwd = project_root;
    let expanded = expand_path(file_path);
    let resolved = if Path::new(&expanded).is_absolute() {
        expanded
    } else {
        Path::new(call_cwd).join(expanded).display().to_string()
    };
    let canonical = canonicalize_best_effort(&resolved);
    let cwd_canonical = canonicalize_best_effort(project_root);

    // Check explicit denied paths first (canonicalize each)
    for denied in &config.denied_paths {
        let denied_canonical = canonicalize_best_effort(&expand_path(denied));
        if path_starts_with(&canonical, &denied_canonical) {
            return PathCheck::Denied(format!(
                "Path Fence: '{}' is in denied path '{}'",
                file_path, denied
            ));
        }
    }

    // If allowed_paths is non-empty, the path must be in the project directory or one of the allowed paths
    if !config.allowed_paths.is_empty() {
        // Project directory is always implicitly allowed
        if path_starts_with(&canonical, &cwd_canonical) {
            return PathCheck::Allow;
        }
        for allowed in &config.allowed_paths {
            let allowed_canonical = canonicalize_best_effort(&expand_path(allowed));
            if path_starts_with(&canonical, &allowed_canonical) {
                return PathCheck::Allow;
            }
        }
        return PathCheck::OutsideProject(format!(
            "Path Fence: '{}' is not in any allowed path.{}",
            file_path, ALLOWLIST_NUDGE
        ));
    }

    // Default behavior: path outside the project directory needs approval
    if !path_starts_with(&canonical, &cwd_canonical) {
        return PathCheck::OutsideProject(format!(
            "Path Fence: '{}' is outside project directory '{}'.{}",
            file_path, cwd, ALLOWLIST_NUDGE
        ));
    }

    PathCheck::Allow
}

/// Canonicalize a path, resolving symlinks and ../
/// If the file doesn't exist yet, canonicalize the deepest existing ancestor
/// and append the remaining components.
fn canonicalize_best_effort(path: &str) -> String {
    let p = Path::new(path);

    // Try full canonicalization first (resolves symlinks + ../)
    if let Ok(canonical) = p.canonicalize() {
        return canonical.display().to_string();
    }

    // File doesn't exist — walk up until we find an existing ancestor
    let mut components: Vec<String> = Vec::new();
    let mut current = p.to_path_buf();
    loop {
        if current.exists() {
            if let Ok(canonical) = current.canonicalize() {
                let mut result = canonical;
                for component in components.iter().rev() {
                    result = result.join(component);
                }
                return result.display().to_string();
            }
            break;
        }
        if let Some(file_name) = current.file_name() {
            components.push(file_name.to_string_lossy().to_string());
        }
        if !current.pop() {
            break;
        }
    }

    // Fallback: return the original path
    path.to_string()
}

/// The account named by a `~user` prefix, if the path uses one. The current
/// user's own `~` and `~/…` are not this, and neither is a bare `~`.
fn other_user_home(path: &str) -> Option<String> {
    let rest = path.trim().strip_prefix('~')?;
    if rest.is_empty() || rest.starts_with('/') {
        return None;
    }
    Some(rest.split('/').next().unwrap_or(rest).to_string())
}

/// Check if a path is a /dev/* device path (always allowed).
fn is_dev_path(path: &str) -> bool {
    let p = path.trim();
    p == "/dev/null"
        || p == "/dev/stdin"
        || p == "/dev/stdout"
        || p == "/dev/stderr"
        || p == "/dev/tty"
        || p.starts_with("/dev/fd/")
}

/// Expand ~ to home directory and resolve relative paths.
fn expand_path(path: &str) -> String {
    // Trim first: `Path::is_absolute` is false for " /home/x", which would make
    // the caller resolve an absolute path as project-relative and let it through.
    // Strip a file:// scheme for the same reason — some MCP servers pass URIs.
    let path = path.trim();
    let path = path
        .strip_prefix("file://localhost")
        .or_else(|| path.strip_prefix("file://"))
        .unwrap_or(path);
    if path.starts_with("~/") || path == "~" {
        if let Some(home) = dirs::home_dir() {
            return format!("{}{}", home.display(), &path[1..]);
        }
    }
    // `~user/...`. Bash performs this expansion, so leaving it unexpanded meant
    // the value stayed *relative*, got joined onto the cwd, resolved inside the
    // project, and passed the fence — `cat ~someone/.ssh/id_rsa` read the key.
    // Sibling-of-home is a heuristic (wrong for accounts outside the usual home
    // parent, e.g. ~root), but it always yields an absolute path outside the
    // project, so an inexact guess fails toward an approval prompt rather than a
    // silent allow.
    if let Some(rest) = path.strip_prefix('~') {
        if !rest.is_empty() && !rest.starts_with('/') {
            let (user, tail) = match rest.find('/') {
                Some(index) => (&rest[..index], &rest[index..]),
                None => (rest, ""),
            };
            if let Some(home) = dirs::home_dir() {
                if let Some(home_parent) = home.parent() {
                    return format!("{}{}", home_parent.join(user).display(), tail);
                }
            }
        }
    }
    // `${HOME}` as well as `$HOME`: the brace form is ordinary shell syntax and
    // skipping it left the same hole on the Write/Edit and MCP paths.
    for var in ["${HOME}", "$HOME"] {
        if path.starts_with(var) {
            if let Some(home) = dirs::home_dir() {
                return path.replacen(var, &home.display().to_string(), 1);
            }
        }
    }
    path.to_string()
}

/// Check if a path starts with a prefix (directory containment).
fn path_starts_with(path: &str, prefix: &str) -> bool {
    let path = Path::new(path);
    let prefix = Path::new(prefix);
    path.starts_with(prefix)
}

/// Extract the file path from a tool input, regardless of tool type.
pub fn extract_file_path(tool_name: &str, tool_input: &serde_json::Value) -> Option<String> {
    extract_file_paths(tool_name, tool_input).into_iter().next()
}

pub fn extract_file_paths(tool_name: &str, tool_input: &serde_json::Value) -> Vec<String> {
    match tool_name {
        "Write" | "Edit" | "Read" => tool_input
            .get("file_path")
            .and_then(|v| v.as_str())
            .map(|s| vec![s.to_string()])
            .unwrap_or_default(),
        "apply_patch" => tool_input
            .get("command")
            .and_then(|v| v.as_str())
            .map(extract_paths_from_patch)
            .unwrap_or_default(),
        "Bash" => {
            let Some(cmd) = tool_input.get("command").and_then(|v| v.as_str()) else {
                return vec![];
            };
            extract_path_from_command(cmd).into_iter().collect()
        }
        // Unrecognized tool — most importantly MCP tools, which Codex and Claude
        // Code both surface as `mcp__server__tool` and route through PreToolUse.
        // Returning nothing here used to skip the fence entirely, so a
        // filesystem-capable MCP server could write a denied path unchecked.
        _ => extract_paths_from_unknown_tool(tool_input),
    }
}

/// Nouns that mark an argument as naming a filesystem location. Matched against
/// individual key *tokens* rather than whole key spellings, so `sourcePath`,
/// `source_path`, `source-path`, and `SourcePaths` are all equivalent — a list
/// of full spellings is a list of the ones someone thought of, and the ones they
/// missed are the bypass.
const PATH_KEY_TOKENS: &[&str] = &[
    "path",
    "paths",
    "file",
    "files",
    "filename",
    "filenames",
    "dir",
    "dirs",
    "directory",
    "directories",
    "folder",
    "folders",
    "target",
    "targets",
    "destination",
    "destinations",
    "dest",
    "source",
    "sources",
    "src",
    "output",
    "outputs",
    "input",
    "inputs",
    "location",
    "locations",
    "uri",
    "url",
    "notebook",
    "root",
    "cwd",
];

/// Keys whose values are file *contents* rather than locations. Without this,
/// a C file starting with a block comment or any argument holding a leading
/// slash would be fenced as if it were a path.
const CONTENT_KEY_TOKENS: &[&str] = &[
    "content",
    "contents",
    "text",
    "body",
    "data",
    "oldtext",
    "newtext",
    "old",
    "new",
    "patch",
    "diff",
    "message",
    "description",
    "query",
];

/// Split a key into lowercase tokens across `_`, `-`, `.`, and camelCase humps.
pub(crate) fn key_tokens(key: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut prev_lower = false;
    for ch in key.chars() {
        if ch == '_' || ch == '-' || ch == '.' || ch == ' ' {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            prev_lower = false;
            continue;
        }
        if ch.is_ascii_uppercase() && prev_lower && !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
        }
        prev_lower = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        current.push(ch.to_ascii_lowercase());
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn is_path_key(key: &str) -> bool {
    let tokens = key_tokens(key);
    // A content key wins even when it also carries a path noun, so `patch_text`
    // and `new_file_content` stay out of the fence.
    if tokens
        .iter()
        .any(|t| CONTENT_KEY_TOKENS.contains(&t.as_str()))
    {
        return false;
    }
    tokens.iter().any(|t| PATH_KEY_TOKENS.contains(&t.as_str()))
}

/// Best-effort path harvest from an arbitrary tool input. Walks the whole JSON
/// value so nested argument objects and arrays of paths are covered.
///
/// Deliberately conservative in what it *treats* as a path (absolute, `~`, or
/// `$HOME`-rooted strings only) but exhaustive in where it looks. A value that
/// is merely project-relative resolves inside the project and passes the fence
/// anyway, so skipping those costs no enforcement while avoiding prompts on
/// ordinary non-path strings.
fn extract_paths_from_unknown_tool(tool_input: &serde_json::Value) -> Vec<String> {
    let mut found = Vec::new();
    harvest_paths(tool_input, false, &mut found);
    found
}

/// `under_path_key` marks a value reached *directly* from a path-named key —
/// through arrays, which inherit their key, but never through a nested object.
/// Letting it stick to every descendant meant `{"files":[{"path":…,
/// "content":"/* header */"}]}` fenced the file's contents as a path; on Codex
/// that is an unappealable denial of an ordinary batch write.
fn harvest_paths(value: &serde_json::Value, under_path_key: bool, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s)
            if under_path_key && looks_like_path(s) && !out.iter().any(|seen| seen == s) =>
        {
            out.push(s.clone());
        }
        serde_json::Value::Array(items) => {
            for item in items {
                harvest_paths(item, under_path_key, out);
            }
        }
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                harvest_paths(val, is_path_key(key), out);
            }
        }
        _ => {}
    }
}

/// Values worth handing to the fence: anything rooted (`/`, `~`, `$HOME`) plus
/// any relative path with a `..` component, since those escape the project once
/// resolved against the calling cwd. A bare `notes.txt` or `src/main.rs` cannot
/// escape, so the fence has nothing to say about it and skipping those keeps
/// ordinary string arguments from producing prompts.
fn looks_like_path(value: &str) -> bool {
    let value = value.trim();
    let value = value
        .strip_prefix("file://localhost")
        .or_else(|| value.strip_prefix("file://"))
        .unwrap_or(value);
    // Any `~` form, not just `~/` — `~user/...` is a real absolute location once
    // the shell expands it, and treating it as an ordinary relative string is
    // what let it resolve inside the project.
    let rooted = value.starts_with('/')
        || value.starts_with('~')
        || value.starts_with("$HOME")
        || value.starts_with("${HOME}");
    rooted || escapes_upward(value)
}

/// True when the value has a `..` path component (`../x`, `a/../../x`, and the
/// Windows-style `..\x`), rather than merely containing the two characters —
/// `file..name` is not a traversal.
fn escapes_upward(value: &str) -> bool {
    value
        .split(['/', '\\'])
        .any(|component| component.trim() == "..")
}

/// Keys whose values are a shell command line rather than data.
const SHELL_COMMAND_KEY_TOKENS: &[&str] = &[
    "command", "commands", "cmd", "cmdline", "script", "shell", "argv",
];

/// The shell command a tool call will execute, if any.
///
/// `Bash` names it directly. Everything else is the reason this exists: a
/// shell-capable MCP server (`mcp__*__execute_command` and friends) runs
/// commands through PreToolUse like any other tool, but every built-in rule is
/// scoped to `tool: "Bash"` and the threat classifier is gated on the same name,
/// so those calls reached no fence, no blocklist, and no evasion detection.
///
/// Returns the joined command text so callers can run it through the Bash path.
/// Tools whose payload merely *looks* like a command are handled by their own
/// extractor and deliberately excluded: `apply_patch` keys its patch body under
/// `command`, and feeding a patch to the shell matcher would be nonsense.
pub fn extract_shell_command(tool_name: &str, tool_input: &serde_json::Value) -> Option<String> {
    match tool_name {
        "Bash" => tool_input
            .get("command")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        "Write" | "Edit" | "Read" | "apply_patch" => None,
        _ => {
            let mut found = Vec::new();
            harvest_commands(tool_input, false, &mut found);
            if found.is_empty() {
                None
            } else {
                // Multiple command-bearing arguments are checked as one blob:
                // every rule that matches any of them should still fire.
                Some(found.join("\n"))
            }
        }
    }
}

fn is_shell_command_key(key: &str) -> bool {
    key_tokens(key)
        .iter()
        .any(|t| SHELL_COMMAND_KEY_TOKENS.contains(&t.as_str()))
}

fn harvest_commands(value: &serde_json::Value, under_command_key: bool, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) if under_command_key && !s.trim().is_empty() => {
            out.push(s.clone());
        }
        // An argv array is one command split across elements (`["sh","-c","..."]`),
        // so join rather than treating each word as its own command.
        serde_json::Value::Array(items) if under_command_key => {
            let joined: Vec<String> = items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect();
            if !joined.is_empty() {
                out.push(joined.join(" "));
            }
            for item in items {
                if !item.is_string() {
                    harvest_commands(item, under_command_key, out);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                harvest_commands(item, false, out);
            }
        }
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                harvest_commands(val, is_shell_command_key(key), out);
            }
        }
        _ => {}
    }
}

fn extract_paths_from_patch(patch: &str) -> Vec<String> {
    const PREFIXES: &[&str] = &[
        "*** Add File: ",
        "*** Update File: ",
        "*** Delete File: ",
        "*** Move to: ",
    ];

    patch
        .lines()
        .filter_map(|line| {
            PREFIXES
                .iter()
                .find_map(|prefix| line.strip_prefix(prefix))
                .map(str::trim)
                .filter(|path| !path.is_empty())
                .map(str::to_string)
        })
        .collect()
}

/// Best-effort extraction of file paths from shell commands.
fn extract_path_from_command(cmd: &str) -> Option<String> {
    // Patterns like: cat /etc/passwd, vim ~/.bashrc, > /sensitive/file
    let patterns = [
        r"(?:cat|less|more|head|tail|vim|nano|vi)\s+(?:-\S+\s+)*(?:\d+\s+)?([/~]\S+)",
        r">\s*([/~]\S+)",
        r"(?:cp|mv|scp)\s+([/~]\S+)",
        r"(?:tee|dd\s+of=)([/~]\S+)",
    ];

    for pattern in &patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if let Some(caps) = re.captures(cmd) {
                if let Some(path) = caps.get(1) {
                    return Some(path.as_str().to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FenceConfig;

    fn default_fence(_cwd: &str) -> FenceConfig {
        FenceConfig {
            enabled: true,
            allowed_paths: vec![],
            denied_paths: vec![
                "~/.ssh".to_string(),
                "~/.aws".to_string(),
                "/etc".to_string(),
            ],
            allow_local_overrides: false,
            denied_paths_remove: vec![],
        }
    }

    #[test]
    fn test_denied_path_blocked() {
        let config = default_fence("/project");
        let home = dirs::home_dir().unwrap();
        let ssh_path = format!("{}/.ssh/authorized_keys", home.display());
        assert!(matches!(
            check_path(&config, &ssh_path, "/project"),
            PathCheck::Denied(_)
        ));
    }

    #[test]
    fn test_etc_blocked() {
        let config = default_fence("/project");
        assert!(matches!(
            check_path(&config, "/etc/passwd", "/project"),
            PathCheck::Denied(_)
        ));
    }

    #[test]
    fn test_project_path_allowed() {
        let config = default_fence("/project");
        assert_eq!(
            check_path(&config, "/project/src/main.rs", "/project"),
            PathCheck::Allow
        );
    }

    #[test]
    fn test_relative_project_path_allowed() {
        let config = default_fence("/project");
        assert_eq!(
            check_path(&config, "src/main.rs", "/project"),
            PathCheck::Allow
        );
    }

    #[test]
    fn test_relative_path_resolves_against_the_calling_cwd() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        let elsewhere = root.path().join("elsewhere");
        let secrets = elsewhere.join("secrets");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&secrets).unwrap();

        let config = FenceConfig {
            enabled: true,
            allowed_paths: vec![],
            denied_paths: vec![secrets.display().to_string()],
            allow_local_overrides: false,
            denied_paths_remove: vec![],
        };

        // The shell has cd'd out of the project. `secrets/key` names the denied
        // file relative to that cwd; resolving it against the project root
        // instead would point at a different file and miss the deny entirely.
        assert!(matches!(
            check_path_from(
                &config,
                "secrets/key",
                &project.display().to_string(),
                &elsewhere.display().to_string(),
            ),
            PathCheck::Denied(_)
        ));
    }

    #[test]
    fn test_fence_disabled() {
        let config = FenceConfig {
            enabled: false,
            allowed_paths: vec![],
            denied_paths: vec!["/etc".to_string()],
            allow_local_overrides: false,
            denied_paths_remove: vec![],
        };
        assert_eq!(
            check_path(&config, "/etc/passwd", "/project"),
            PathCheck::Allow
        );
    }

    #[test]
    fn test_outside_project_is_approve() {
        let config = FenceConfig {
            enabled: true,
            allowed_paths: vec![],
            denied_paths: vec![],
            allow_local_overrides: false,
            denied_paths_remove: vec![],
        };
        assert!(matches!(
            check_path(&config, "/other/file.txt", "/project"),
            PathCheck::OutsideProject(_)
        ));
    }

    #[test]
    fn test_allowed_paths_whitelist() {
        let config = FenceConfig {
            enabled: true,
            allowed_paths: vec!["/project".to_string(), "/tmp".to_string()],
            denied_paths: vec![],
            allow_local_overrides: false,
            denied_paths_remove: vec![],
        };
        assert_eq!(
            check_path(&config, "/project/src/main.rs", "/project"),
            PathCheck::Allow
        );
        assert_eq!(
            check_path(&config, "/tmp/test.txt", "/project"),
            PathCheck::Allow
        );
        assert!(matches!(
            check_path(&config, "/other/file.txt", "/project"),
            PathCheck::OutsideProject(_)
        ));
    }

    #[test]
    fn test_allowed_paths_implicitly_includes_cwd() {
        // When allowed_paths is set but doesn't include cwd, cwd should still be allowed
        let config = FenceConfig {
            enabled: true,
            allowed_paths: vec!["/tmp".to_string()],
            denied_paths: vec![],
            allow_local_overrides: false,
            denied_paths_remove: vec![],
        };
        assert_eq!(
            check_path(&config, "/project/src/main.rs", "/project"),
            PathCheck::Allow
        );
        assert_eq!(
            check_path(&config, "/tmp/test.txt", "/project"),
            PathCheck::Allow
        );
        assert!(matches!(
            check_path(&config, "/other/file.txt", "/project"),
            PathCheck::OutsideProject(_)
        ));
    }

    #[test]
    fn test_allowed_path_matches_deep_descendant() {
        // Issue #16: a path nested several levels under an allowed_paths entry
        // (e.g. the repo root under `~/github`) must be allowed, not prompted.
        let config = FenceConfig {
            enabled: true,
            allowed_paths: vec!["/home/u/github".to_string()],
            denied_paths: vec![],
            allow_local_overrides: false,
            denied_paths_remove: vec![],
        };
        assert_eq!(
            check_path(&config, "/home/u/github/railguard/src/main.rs", "/project"),
            PathCheck::Allow
        );
        assert!(matches!(
            check_path(&config, "/home/u/other/file.txt", "/project"),
            PathCheck::OutsideProject(_)
        ));
    }

    #[test]
    fn test_extract_path_from_bash() {
        assert_eq!(
            extract_path_from_command("cat /etc/passwd"),
            Some("/etc/passwd".to_string())
        );
        assert_eq!(
            extract_path_from_command("head -n 10 ~/.bashrc"),
            Some("~/.bashrc".to_string())
        );
        assert_eq!(
            extract_path_from_command("> /sensitive/output.txt"),
            Some("/sensitive/output.txt".to_string())
        );
    }

    #[test]
    fn test_extract_file_path_from_tool_input() {
        let input = serde_json::json!({"file_path": "/etc/passwd"});
        assert_eq!(
            extract_file_path("Read", &input),
            Some("/etc/passwd".to_string())
        );
    }

    #[test]
    fn mcp_tool_paths_reach_the_fence() {
        // Regression: unrecognized tools used to return no paths at all, so a
        // filesystem-capable MCP server could write a denied path unchecked.
        let input = serde_json::json!({
            "path": "~/.ssh/authorized_keys",
            "content": "ssh-rsa AAAA"
        });
        assert_eq!(
            extract_file_paths("mcp__filesystem__write_file", &input),
            vec!["~/.ssh/authorized_keys"]
        );
    }

    #[test]
    fn mcp_tool_paths_are_found_when_nested_or_listed() {
        let input = serde_json::json!({
            "args": { "target_file": "/etc/hosts" },
            "extra_paths": ["~/.aws/credentials", "relative/notes.txt"]
        });
        let paths = extract_file_paths("mcp__server__tool", &input);
        assert!(paths.contains(&"/etc/hosts".to_string()));
        assert!(paths.contains(&"~/.aws/credentials".to_string()));
        // Project-relative values resolve inside the project and need no fence entry.
        assert!(!paths.contains(&"relative/notes.txt".to_string()));
    }

    #[test]
    fn unknown_tool_non_path_strings_do_not_become_paths() {
        let input = serde_json::json!({"query": "SELECT 1", "limit": 10});
        assert!(extract_file_paths("mcp__db__query", &input).is_empty());
    }

    #[test]
    fn mcp_tool_relative_traversal_reaches_the_fence() {
        // Rooted-only detection left the obvious escape open: `../` resolves
        // against the calling cwd and lands wherever it likes.
        let input = serde_json::json!({"path": "../../.ssh/authorized_keys"});
        assert_eq!(
            extract_file_paths("mcp__fs__write", &input),
            vec!["../../.ssh/authorized_keys"]
        );
    }

    #[test]
    fn mcp_path_keys_match_regardless_of_spelling() {
        // A list of full key spellings is a list of the ones someone thought of;
        // camelCase compounds used to sail straight past the fence.
        for key in [
            "sourcePath",
            "targetFile",
            "outputPath",
            "destinationPath",
            "source_path",
            "target-file",
            "NotebookPath",
        ] {
            let input = serde_json::json!({ key: "/home/u/.ssh/authorized_keys" });
            assert_eq!(
                extract_file_paths("mcp__fs__write", &input),
                vec!["/home/u/.ssh/authorized_keys"],
                "key {} should be treated as a path",
                key
            );
        }
    }

    #[test]
    fn mcp_file_contents_are_not_treated_as_paths() {
        // A C file opening with a block comment, nested under a path-named key.
        let input = serde_json::json!({
            "files": [{"path": "src/a.c", "content": "/* header */"}]
        });
        assert!(extract_file_paths("mcp__fs__batch_write", &input).is_empty());
    }

    #[test]
    fn mcp_file_uri_and_padded_values_still_reach_the_fence() {
        for value in [
            "file:///home/u/.ssh/authorized_keys",
            " /home/u/.ssh/authorized_keys",
        ] {
            let input = serde_json::json!({ "path": value });
            assert!(
                !extract_file_paths("mcp__fs__write", &input).is_empty(),
                "{} should be treated as a path",
                value
            );
        }
    }

    #[test]
    fn unknown_tool_in_project_relative_paths_stay_quiet() {
        // These cannot escape the project, so they must not add fence prompts.
        let input = serde_json::json!({"path": "src/main.rs", "file": "notes..txt"});
        assert!(extract_file_paths("mcp__fs__write", &input).is_empty());
    }

    #[test]
    fn test_extract_file_paths_from_codex_patch() {
        let input = serde_json::json!({
            "command": "*** Begin Patch\n*** Update File: src/main.rs\n@@\n-old\n+new\n*** Add File: tests/new.rs\n+test\n*** Delete File: old.txt\n*** End Patch"
        });
        assert_eq!(
            extract_file_paths("apply_patch", &input),
            vec!["src/main.rs", "tests/new.rs", "old.txt"]
        );
    }
}
