use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

use crate::types::HookClient;

/// Get the path to Claude Code's user settings file.
pub fn claude_settings_path() -> PathBuf {
    let home = dirs::home_dir().expect("Could not determine home directory");
    home.join(".claude").join("settings.json")
}

pub fn codex_hooks_path() -> PathBuf {
    let home = dirs::home_dir().expect("Could not determine home directory");
    home.join(".codex").join("hooks.json")
}

/// Get the path to the railguard binary.
fn railguard_binary_path() -> String {
    std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "railguard".to_string())
}

/// Quote a path for the shell that runs hook commands.
///
/// Hook commands are executed through a shell, so an install path containing a
/// space would otherwise split into a bogus program name. The hook then fails to
/// spawn — and a failed PreToolUse hook does not block the tool call, so an
/// unquoted path silently disables enforcement.
fn shell_quote(value: &str) -> String {
    let safe = !value.is_empty()
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '/' | '.' | '_' | '-' | '+' | ':' | '=' | '@' | '%' | ',')
        });
    if safe {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// Get the path to the railguard-shell binary (sibling of the railguard binary).
fn railguard_shell_path() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|dir| dir.join("railguard-shell")))
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "railguard-shell".to_string())
}

/// The CLAUDE.md content that teaches Claude about Railguard.
const CLAUDE_MD_CONTENT: &str = include_str!("../../defaults/CLAUDE.md");

/// Marker used to identify Railguard's section in CLAUDE.md.
const CLAUDE_MD_MARKER_START: &str = "<!-- railguard:start -->";
const CLAUDE_MD_MARKER_END: &str = "<!-- railguard:end -->";

/// Enable "dangerously skip permissions" (bypass mode) in Claude Code settings.
/// Railguard replaces the built-in permission system, so bypass mode is safe.
pub fn enable_bypass_permissions() -> Result<String, String> {
    let settings_path = claude_settings_path();
    let mut settings = read_settings(&settings_path)?;

    let root = settings
        .as_object_mut()
        .ok_or("Settings is not a JSON object")?;

    let permissions = root.entry("permissions").or_insert_with(|| json!({}));

    let perms_obj = permissions
        .as_object_mut()
        .ok_or("permissions is not a JSON object")?;

    perms_obj.insert("defaultMode".to_string(), json!("bypassPermissions"));

    write_settings(&settings_path, &settings)?;

    Ok("Enabled bypass permissions mode in Claude Code".to_string())
}

/// Disable bypass permissions mode when Railguard is uninstalled.
/// Without Railguard, the user should go back to Claude Code's built-in permissions.
pub fn disable_bypass_permissions() -> Result<String, String> {
    let settings_path = claude_settings_path();
    if !settings_path.exists() {
        return Ok("No settings to restore".to_string());
    }

    let mut settings = read_settings(&settings_path)?;

    if let Some(perms) = settings
        .get_mut("permissions")
        .and_then(|p| p.as_object_mut())
    {
        // Only remove if it's set to bypassPermissions (don't touch other modes)
        if perms.get("defaultMode").and_then(|v| v.as_str()) == Some("bypassPermissions") {
            perms.remove("defaultMode");
        }
        if perms.is_empty() {
            settings.as_object_mut().unwrap().remove("permissions");
        }
    }

    write_settings(&settings_path, &settings)?;

    Ok("Disabled bypass permissions mode".to_string())
}

/// The leading program of a hook command, with surrounding quotes removed.
fn program_token(command: &str) -> &str {
    let trimmed = command.trim_start();
    for quote in ['"', '\''] {
        if let Some(rest) = trimmed.strip_prefix(quote) {
            return rest.split(quote).next().unwrap_or_default();
        }
    }
    trimmed.split_whitespace().next().unwrap_or_default()
}

/// True if a single hook handler invokes railguard's own hook entry point.
///
/// Matched on the program's file name rather than a substring search: a
/// bare `contains("railguard")` also matches unrelated commands that merely
/// live under a path containing the word, and deleting those on uninstall
/// would silently remove someone else's hook.
fn is_railguard_hook(hook: &Value) -> bool {
    hook.get("command")
        .and_then(Value::as_str)
        .is_some_and(|command| {
            let program = Path::new(program_token(command))
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_default();
            matches!(program.as_str(), "railguard" | "railguard.exe") && command.contains(" hook")
        })
}

/// True if a hooks-array entry is entirely railguard's.
///
/// A matcher group may hold several handlers. Only a group whose handlers are
/// *all* railguard's may be removed wholesale; a mixed group is pruned handler
/// by handler so a co-located third-party hook survives.
fn is_railguard_entry(entry: &Value) -> bool {
    entry
        .get("hooks")
        .and_then(Value::as_array)
        .is_some_and(|hooks| !hooks.is_empty() && hooks.iter().all(is_railguard_hook))
}

/// Drop railguard handlers from every entry, then drop entries left empty.
fn prune_railguard_handlers(entries: &mut Vec<Value>) {
    for entry in entries.iter_mut() {
        if let Some(handlers) = entry.get_mut("hooks").and_then(Value::as_array_mut) {
            handlers.retain(|hook| !is_railguard_hook(hook));
        }
    }
    entries.retain(|entry| match entry.get("hooks").and_then(Value::as_array) {
        Some(handlers) => !handlers.is_empty(),
        None => true,
    });
}

/// Add a railguard entry to an event's hook array, replacing any stale
/// railguard entry but preserving user-added hooks.
fn upsert_hook_entry(hooks_obj: &mut serde_json::Map<String, Value>, event: &str, entry: Value) {
    let event_hooks = hooks_obj.entry(event).or_insert_with(|| json!([]));
    if !event_hooks.is_array() {
        *event_hooks = json!([]);
    }
    let arr = event_hooks.as_array_mut().unwrap();
    prune_railguard_handlers(arr);
    arr.push(entry);
}

/// Install railguard hooks into Claude Code settings.
pub fn install_hooks() -> Result<String, String> {
    let settings_path = claude_settings_path();
    let mut settings = read_settings(&settings_path)?;
    let binary = railguard_binary_path();

    let hooks = settings
        .as_object_mut()
        .ok_or("Settings is not a JSON object")?
        .entry("hooks")
        .or_insert_with(|| json!({}));

    let hooks_obj = hooks.as_object_mut().ok_or("hooks is not a JSON object")?;

    upsert_client_hooks(hooks_obj, &binary, HookClient::Claude);

    // Set CLAUDE_CODE_SHELL to railguard-shell for OS-level sandboxing.
    // This makes every Bash tool call run through our sandboxed shell.
    let shell_binary = railguard_shell_path();
    if std::path::Path::new(&shell_binary).exists() {
        let env_obj = settings
            .as_object_mut()
            .unwrap()
            .entry("env")
            .or_insert_with(|| json!({}));

        if let Some(env_map) = env_obj.as_object_mut() {
            env_map.insert("CLAUDE_CODE_SHELL".to_string(), json!(shell_binary));
        }
    }

    write_settings(&settings_path, &settings)?;

    let codex_msg = install_codex_hooks(&binary)?;

    // Inject CLAUDE.md so Claude knows about Railguard
    let claude_md_msg = inject_claude_md()?;

    let sandbox_msg = if std::path::Path::new(&shell_binary).exists() {
        format!("\n  ✓ OS sandbox shell: {}", shell_binary)
    } else {
        "\n  ● OS sandbox: railguard-shell not found (run cargo install to build)".to_string()
    };

    Ok(format!(
        "Installed railguard hooks in {}\n  {} {}{}\n  {}",
        settings_path.display(),
        "✓",
        claude_md_msg,
        sandbox_msg,
        codex_msg
    ))
}

fn upsert_client_hooks(
    hooks_obj: &mut serde_json::Map<String, Value>,
    binary: &str,
    client: HookClient,
) {
    let client_name = match client {
        HookClient::Auto => "auto",
        HookClient::Claude => "claude",
        HookClient::Codex => "codex",
    };

    // A hook that times out is treated as a failed run and does NOT block the
    // tool call, so the budget has to cover the worst case (a patch touching
    // many files), not the typical one.
    let timeout_secs = 60;

    for event in ["PreToolUse", "PostToolUse", "SessionStart"] {
        let entry = json!({
            "matcher": "",
            "hooks": [{
                "type": "command",
                "command": format!("{} hook --client {} --event {}", shell_quote(binary), client_name, event),
                "timeout": timeout_secs
            }]
        });
        upsert_hook_entry(hooks_obj, event, entry);
    }
}

fn install_codex_hooks(binary: &str) -> Result<String, String> {
    let hooks_path = codex_hooks_path();
    let codex_dir = hooks_path
        .parent()
        .ok_or("Could not determine Codex config directory")?;
    if !codex_dir.exists() {
        return Ok("● Codex not detected; skipped ~/.codex/hooks.json".to_string());
    }

    let mut settings = read_settings(&hooks_path)?;
    let hooks = settings
        .as_object_mut()
        .ok_or("Codex hooks file is not a JSON object")?
        .entry("hooks")
        .or_insert_with(|| json!({}));
    let hooks_obj = hooks
        .as_object_mut()
        .ok_or("Codex hooks field is not a JSON object")?;
    upsert_client_hooks(hooks_obj, binary, HookClient::Codex);
    write_settings(&hooks_path, &settings)?;

    Ok(format!(
        "✓ Codex hooks: {} (review them with /hooks)",
        hooks_path.display()
    ))
}

/// Insert or replace the railguard section in CLAUDE.md `existing` content,
/// returning the full new file contents (with trailing newline). User content
/// before/after the markers is preserved and separated from the section by a
/// blank line, so the start marker never fuses onto a user's line.
fn upsert_railguard_section(existing: &str, marked_content: &str) -> String {
    if existing.contains(CLAUDE_MD_MARKER_START) {
        let before = existing
            .split(CLAUDE_MD_MARKER_START)
            .next()
            .unwrap_or("")
            .trim_end();
        let after = existing.split(CLAUDE_MD_MARKER_END).nth(1).unwrap_or("");
        let separator = if before.is_empty() { "" } else { "\n\n" };
        let updated = format!("{}{}{}{}", before, separator, marked_content, after);
        return updated.trim().to_string() + "\n";
    }
    let before = existing.trim_end();
    if before.is_empty() {
        format!("{}\n", marked_content)
    } else {
        format!("{}\n\n{}\n", before, marked_content)
    }
}

/// Strip the railguard section from CLAUDE.md `content`, rejoining surrounding
/// user content with a blank line. Returns `None` if no section marker present.
fn strip_railguard_section(content: &str) -> Option<String> {
    if !content.contains(CLAUDE_MD_MARKER_START) {
        return None;
    }
    let before = content
        .split(CLAUDE_MD_MARKER_START)
        .next()
        .unwrap_or("")
        .trim_end();
    let after = content
        .split(CLAUDE_MD_MARKER_END)
        .nth(1)
        .unwrap_or("")
        .trim_start();
    let cleaned = if before.is_empty() || after.is_empty() {
        format!("{}{}", before, after)
    } else {
        format!("{}\n\n{}", before, after)
    };
    Some(cleaned.trim().to_string() + "\n")
}

/// Inject Railguard instructions into the user's CLAUDE.md file.
/// This teaches Claude Code about rollback, context, and what's blocked.
fn inject_claude_md() -> Result<String, String> {
    let home = dirs::home_dir().ok_or("Could not determine home directory")?;
    let claude_md_path = home.join(".claude").join("CLAUDE.md");

    let marked_content = format!(
        "{}\n{}\n{}",
        CLAUDE_MD_MARKER_START, CLAUDE_MD_CONTENT, CLAUDE_MD_MARKER_END
    );

    if claude_md_path.exists() {
        let existing = fs::read_to_string(&claude_md_path)
            .map_err(|e| format!("Failed to read CLAUDE.md: {}", e))?;
        let had_section = existing.contains(CLAUDE_MD_MARKER_START);
        let updated = upsert_railguard_section(&existing, &marked_content);
        fs::write(&claude_md_path, updated)
            .map_err(|e| format!("Failed to update CLAUDE.md: {}", e))?;

        Ok(if had_section {
            "Updated Railguard instructions in ~/.claude/CLAUDE.md".to_string()
        } else {
            "Added Railguard instructions to ~/.claude/CLAUDE.md".to_string()
        })
    } else {
        // Create new file
        if let Some(parent) = claude_md_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create ~/.claude dir: {}", e))?;
        }
        fs::write(&claude_md_path, format!("{}\n", marked_content))
            .map_err(|e| format!("Failed to create CLAUDE.md: {}", e))?;

        Ok("Created ~/.claude/CLAUDE.md with Railguard instructions".to_string())
    }
}

/// Remove railguard hooks from Claude Code settings.
/// Requires explicit human confirmation via a native OS dialog.
pub fn uninstall_hooks() -> Result<String, String> {
    // Check if running interactively (a TTY is attached)
    // Agents pipe stdin, so this catches most automated attempts
    if !is_interactive_terminal() {
        return Err(
            "Railguard can only be uninstalled from an interactive terminal.\n  \
                    This prevents AI agents from removing their own guardrails."
                .to_string(),
        );
    }

    // Show native OS confirmation dialog — requires a real human to click through
    if !show_uninstall_confirmation()? {
        return Err("Uninstall cancelled by user".to_string());
    }

    let settings_path = claude_settings_path();

    if settings_path.exists() {
        let mut settings = read_settings(&settings_path)?;

        remove_railguard_hooks(&mut settings);

        // Remove CLAUDE_CODE_SHELL from env section
        if let Some(env_obj) = settings.get_mut("env").and_then(|e| e.as_object_mut()) {
            env_obj.remove("CLAUDE_CODE_SHELL");
            if env_obj.is_empty() {
                settings.as_object_mut().unwrap().remove("env");
            }
        }

        write_settings(&settings_path, &settings)?;

        // Disable bypass permissions — without Railguard, use built-in permissions
        let _ = disable_bypass_permissions();

        // Clean up CLAUDE.md
        remove_claude_md_section();
    }

    let codex_path = codex_hooks_path();
    if codex_path.exists() {
        let mut codex_hooks = read_settings(&codex_path)?;
        remove_railguard_hooks(&mut codex_hooks);
        write_settings(&codex_path, &codex_hooks)?;
    }

    Ok(format!(
        "Removed railguard hooks from {} and {}",
        settings_path.display(),
        codex_path.display()
    ))
}

fn remove_railguard_hooks(settings: &mut Value) {
    let Some(hooks) = settings.get_mut("hooks").and_then(Value::as_object_mut) else {
        return;
    };

    for event in ["PreToolUse", "PostToolUse", "SessionStart"] {
        let remove_event = hooks
            .get_mut(event)
            .and_then(Value::as_array_mut)
            .is_some_and(|entries| {
                prune_railguard_handlers(entries);
                entries.is_empty()
            });
        if remove_event {
            hooks.remove(event);
        }
    }
}

/// Remove Railguard section from CLAUDE.md during uninstall.
fn remove_claude_md_section() {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return,
    };
    let claude_md_path = home.join(".claude").join("CLAUDE.md");

    if !claude_md_path.exists() {
        return;
    }

    if let Ok(content) = fs::read_to_string(&claude_md_path) {
        if let Some(cleaned) = strip_railguard_section(&content) {
            let _ = fs::write(&claude_md_path, cleaned);
        }
    }
}

/// A confirmation the governed agent cannot answer: a native OS dialog.
///
/// Returns `None` when no dialog program exists, so a caller can refuse instead
/// of falling back to a terminal prompt. That distinction is the whole point — a
/// typed phrase is pipeable and a TTY can be manufactured with `script`, so
/// neither is an authentication boundary against something holding shell access.
pub fn confirm_via_dialog(message: &str, yes_label: &str) -> Option<bool> {
    if cfg!(target_os = "macos") {
        let script = format!(
            "display dialog \"{}\" buttons {{\"Cancel\", \"{}\"}} \
             default button \"Cancel\" with icon caution",
            message.replace('"', "'"),
            yes_label
        );
        let output = std::process::Command::new("osascript")
            .arg("-e")
            .arg(script)
            .output()
            .ok()?;
        return Some(output.status.success());
    }

    let zenity = vec![
        "--question".to_string(),
        format!("--text={}", message),
        format!("--ok-label={}", yes_label),
        "--cancel-label=Cancel".to_string(),
    ];
    let kdialog = vec![
        "--warningyesno".to_string(),
        message.to_string(),
        format!("--yes-label={}", yes_label),
        "--no-label=Cancel".to_string(),
    ];
    for (program, args) in [("zenity", zenity), ("kdialog", kdialog)] {
        if let Ok(output) = std::process::Command::new(program).args(&args).output() {
            return Some(output.status.success());
        }
    }
    None
}

/// Check if we're running in an interactive terminal (not piped by an agent).
fn is_interactive_terminal() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// Show a native OS confirmation dialog for uninstalling Railguard.
/// Returns true if the user confirmed, false if cancelled.
/// This is the key security boundary — an AI agent cannot click a GUI button.
fn show_uninstall_confirmation() -> Result<bool, String> {
    if cfg!(target_os = "macos") {
        show_macos_dialog()
    } else if cfg!(target_os = "windows") {
        show_windows_dialog()
    } else {
        show_linux_dialog()
    }
}

/// macOS: native dialog via osascript (AppleScript)
fn show_macos_dialog() -> Result<bool, String> {
    let script = r#"
        display dialog "Remove Railguard guardrails?\n\nClaude Code will run without restrictions until you reinstall.\n\nTo turn protection back on:\n  railguard install" with title "Railguard" with icon caution buttons {"Cancel", "Remove"} default button "Cancel" cancel button "Cancel"
    "#;

    let output = std::process::Command::new("osascript")
        .arg("-e")
        .arg(script.trim())
        .output()
        .map_err(|e| format!("Failed to show confirmation dialog: {}", e))?;

    // osascript returns exit code 1 if the user clicks Cancel
    Ok(output.status.success())
}

/// Windows: native dialog via PowerShell
fn show_windows_dialog() -> Result<bool, String> {
    let script = r#"
        Add-Type -AssemblyName System.Windows.Forms
        $result = [System.Windows.Forms.MessageBox]::Show(
            "Remove Railguard guardrails?`n`nClaude Code will run without restrictions until you reinstall.`n`nTo turn protection back on:`n  railguard install",
            "Railguard",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning,
            [System.Windows.Forms.MessageBoxDefaultButton]::Button2
        )
        if ($result -eq [System.Windows.Forms.DialogResult]::Yes) { exit 0 } else { exit 1 }
    "#;

    let output = std::process::Command::new("powershell")
        .arg("-NoProfile")
        .arg("-Command")
        .arg(script.trim())
        .output()
        .map_err(|e| format!("Failed to show confirmation dialog: {}", e))?;

    Ok(output.status.success())
}

/// Linux: try zenity (GNOME), then kdialog (KDE), then fall back to terminal prompt
fn show_linux_dialog() -> Result<bool, String> {
    // Try zenity first (GNOME/GTK)
    if let Ok(output) = std::process::Command::new("zenity")
        .arg("--question")
        .arg("--title=Railguard")
        .arg("--text=Remove Railguard guardrails?\n\nClaude Code will run without restrictions until you reinstall.\n\nTo turn protection back on: railguard install")
        .arg("--ok-label=Remove Protection")
        .arg("--cancel-label=Cancel")
        .arg("--icon-name=dialog-warning")
        .arg("--width=400")
        .output()
    {
        return Ok(output.status.success());
    }

    // Try kdialog (KDE)
    if let Ok(output) = std::process::Command::new("kdialog")
        .arg("--warningyesno")
        .arg("Remove Railguard guardrails?\n\nClaude Code will run without restrictions until you reinstall.\n\nTo turn protection back on: railguard install")
        .arg("--title")
        .arg("Railguard")
        .arg("--yes-label")
        .arg("Remove Protection")
        .arg("--no-label")
        .arg("Cancel")
        .output()
    {
        return Ok(output.status.success());
    }

    // Fallback: terminal confirmation with a hard-to-guess phrase
    show_terminal_confirmation()
}

/// Terminal fallback: require the user to type a specific phrase.
/// An agent could theoretically type this, but combined with the TTY check
/// and the self-protection blocklist rules, it's defense in depth.
fn show_terminal_confirmation() -> Result<bool, String> {
    use std::io::Write;

    eprintln!();
    eprintln!();
    eprintln!("  Remove Railguard guardrails?");
    eprintln!();
    eprintln!("  Claude Code will run without restrictions until you reinstall.");
    eprintln!("  To turn protection back on: railguard install");
    eprintln!();
    eprint!("  Type \"remove\" to confirm: ");
    std::io::stderr().flush().ok();

    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(|e| format!("Failed to read input: {}", e))?;

    Ok(input.trim() == "remove")
}

/// Check if railguard hooks are currently installed.
pub fn check_installed() -> Result<bool, String> {
    Ok(check_claude_installed()? || check_codex_installed()?)
}

pub fn check_claude_installed() -> Result<bool, String> {
    check_client_installed(&claude_settings_path())
}

pub fn check_codex_installed() -> Result<bool, String> {
    check_client_installed(&codex_hooks_path())
}

/// Whether Codex has hooks switched off wholesale via `[features] hooks = false`
/// in `~/.codex/config.toml`. A registered hook entry is inert in that state, so
/// reporting it as active would be a false assurance on a guardrail.
///
/// Returns `None` when the answer can't be established (no config file, or a
/// shape this crude scan doesn't understand) — callers should treat that as
/// "unknown", never as "enabled".
pub fn codex_hooks_feature_disabled() -> Option<bool> {
    let config = dirs::home_dir()?.join(".codex").join("config.toml");
    let contents = fs::read_to_string(config).ok()?;

    let mut in_features = false;
    for line in contents.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') {
            in_features = line == "[features]";
            continue;
        }
        if !in_features {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            if key.trim() == "hooks" {
                return match value.trim() {
                    "false" => Some(true),
                    "true" => Some(false),
                    _ => None,
                };
            }
        }
    }
    // No explicit setting found; Codex's own default governs.
    None
}

fn check_client_installed(path: &Path) -> Result<bool, String> {
    if !path.exists() {
        return Ok(false);
    }

    let settings = read_settings(path)?;
    Ok(settings
        .pointer("/hooks/PreToolUse")
        .and_then(Value::as_array)
        .is_some_and(|entries| entries.iter().any(is_railguard_entry)))
}

fn read_settings(path: &Path) -> Result<Value, String> {
    if !path.exists() {
        // Create parent directory and return empty object
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create settings dir: {}", e))?;
        }
        return Ok(json!({}));
    }

    let content =
        fs::read_to_string(path).map_err(|e| format!("Failed to read settings: {}", e))?;

    serde_json::from_str(&content).map_err(|e| format!("Failed to parse settings: {}", e))
}

fn write_settings(path: &Path, settings: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create settings dir: {}", e))?;
    }

    let content = serde_json::to_string_pretty(settings)
        .map_err(|e| format!("Failed to serialize settings: {}", e))?;

    fs::write(path, content).map_err(|e| format!("Failed to write settings: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_settings_path_exists() {
        let path = claude_settings_path();
        assert!(path.to_str().unwrap().contains(".claude"));
        assert!(path.to_str().unwrap().ends_with("settings.json"));
    }

    fn marked() -> String {
        format!(
            "{}\n{}\n{}",
            CLAUDE_MD_MARKER_START, "RAILGUARD BODY", CLAUDE_MD_MARKER_END
        )
    }

    #[test]
    fn upsert_replace_keeps_blank_line_before_marker() {
        // Regression: reinstall must not fuse the user's last line onto the start marker.
        let existing = format!(
            "# Notes\nlast line\n\n{}\nOLD BODY\n{}\n",
            CLAUDE_MD_MARKER_START, CLAUDE_MD_MARKER_END
        );
        let out = upsert_railguard_section(&existing, &marked());
        assert!(
            out.contains(&format!("last line\n\n{}", CLAUDE_MD_MARKER_START)),
            "expected blank line before marker, got:\n{out}"
        );
        assert!(!out.contains(&format!("last line{}", CLAUDE_MD_MARKER_START)));
        assert!(out.contains("RAILGUARD BODY") && !out.contains("OLD BODY"));
        assert!(out.ends_with('\n') && !out.ends_with("\n\n"));
    }

    #[test]
    fn upsert_replace_is_idempotent() {
        let existing = format!(
            "# Notes\nlast line\n\n{}\nOLD\n{}\n",
            CLAUDE_MD_MARKER_START, CLAUDE_MD_MARKER_END
        );
        let once = upsert_railguard_section(&existing, &marked());
        let twice = upsert_railguard_section(&once, &marked());
        assert_eq!(once, twice);
    }

    #[test]
    fn upsert_appends_with_blank_line_when_no_marker() {
        let out = upsert_railguard_section("# Notes\nblah", &marked());
        assert!(out.contains(&format!("blah\n\n{}", CLAUDE_MD_MARKER_START)));
    }

    #[test]
    fn upsert_on_empty_has_no_leading_blank() {
        let out = upsert_railguard_section("", &marked());
        assert!(out.starts_with(CLAUDE_MD_MARKER_START));
    }

    #[test]
    fn strip_rejoins_surrounding_content_without_fusing() {
        let existing = format!(
            "# Top\nA\n\n{}\nBODY\n{}\n\n# Bottom\nB\n",
            CLAUDE_MD_MARKER_START, CLAUDE_MD_MARKER_END
        );
        let out = strip_railguard_section(&existing).unwrap();
        assert!(!out.contains(CLAUDE_MD_MARKER_START) && !out.contains(CLAUDE_MD_MARKER_END));
        assert!(out.contains("A\n\n# Bottom"), "got:\n{out}");
        assert!(!out.contains("AB") && !out.contains("A# Bottom"));
    }

    #[test]
    fn strip_returns_none_without_marker() {
        assert!(strip_railguard_section("# Just user notes\n").is_none());
    }

    #[test]
    fn upsert_hook_preserves_user_hooks_and_replaces_stale_railguard() {
        let mut hooks = json!({
            "PreToolUse": [
                {"matcher": "", "hooks": [{"type": "command", "command": "my-custom-linter"}]},
                {"matcher": "", "hooks": [{"type": "command", "command": "/old/path/railguard hook --event PreToolUse"}]}
            ]
        });
        let hooks_obj = hooks.as_object_mut().unwrap();
        let entry = json!({"matcher": "", "hooks": [{"type": "command", "command": "/new/railguard hook --event PreToolUse"}]});
        upsert_hook_entry(hooks_obj, "PreToolUse", entry);

        let arr = hooks_obj["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 2, "got: {arr:?}");
        assert!(arr
            .iter()
            .any(|e| e.pointer("/hooks/0/command").unwrap() == "my-custom-linter"));
        assert!(arr
            .iter()
            .any(|e| e.pointer("/hooks/0/command").unwrap()
                == "/new/railguard hook --event PreToolUse"));
        assert!(!arr.iter().any(|e| {
            e.pointer("/hooks/0/command")
                .and_then(|c| c.as_str())
                .is_some_and(|c| c.starts_with("/old/"))
        }));
    }

    #[test]
    fn upsert_hook_creates_event_when_missing() {
        let mut hooks = json!({});
        let hooks_obj = hooks.as_object_mut().unwrap();
        upsert_hook_entry(
            hooks_obj,
            "SessionStart",
            json!({"matcher": "", "hooks": [{"type": "command", "command": "railguard hook --event SessionStart"}]}),
        );
        assert_eq!(hooks_obj["SessionStart"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn codex_hooks_use_explicit_client_and_seconds_timeout() {
        let mut hooks = json!({});
        upsert_client_hooks(
            hooks.as_object_mut().unwrap(),
            "/bin/railguard",
            HookClient::Codex,
        );

        for event in ["PreToolUse", "PostToolUse", "SessionStart"] {
            let hook = &hooks[event][0]["hooks"][0];
            assert_eq!(hook["timeout"], 60);
            assert_eq!(
                hook["command"],
                format!("/bin/railguard hook --client codex --event {}", event)
            );
        }
    }

    #[test]
    fn remove_hooks_keeps_third_party_handler_sharing_a_group() {
        let mut settings = json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [
                        {"type": "command", "command": "railguard hook --client codex --event PreToolUse"},
                        {"type": "command", "command": "/opt/company/dlp-check"}
                    ]
                }]
            }
        });

        remove_railguard_hooks(&mut settings);

        let handlers = settings["hooks"]["PreToolUse"][0]["hooks"]
            .as_array()
            .unwrap();
        assert_eq!(handlers.len(), 1);
        assert_eq!(handlers[0]["command"], "/opt/company/dlp-check");
    }

    #[test]
    fn unrelated_command_containing_railguard_is_not_removed() {
        let mut settings = json!({
            "hooks": {
                "PreToolUse": [{
                    "hooks": [{"type": "command", "command": "/opt/railguardian/scan --all"}]
                }]
            }
        });

        remove_railguard_hooks(&mut settings);

        assert_eq!(settings["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn install_path_with_spaces_is_quoted() {
        let mut hooks = json!({});
        upsert_client_hooks(
            hooks.as_object_mut().unwrap(),
            "/Applications/Rail Guard/railguard",
            HookClient::Codex,
        );

        let command = hooks["PreToolUse"][0]["hooks"][0]["command"]
            .as_str()
            .unwrap();
        assert!(command.starts_with("'/Applications/Rail Guard/railguard'"));
        // The quoted form must still be recognized as ours, or uninstall and
        // reinstall would leave duplicate entries behind.
        assert!(is_railguard_entry(&hooks["PreToolUse"][0]));
    }

    #[test]
    fn remove_hooks_preserves_non_railguard_entries() {
        let mut settings = json!({
            "hooks": {
                "PreToolUse": [
                    {"hooks": [{"type": "command", "command": "custom-check"}]},
                    {"hooks": [{"type": "command", "command": "railguard hook --client codex --event PreToolUse"}]}
                ]
            }
        });

        remove_railguard_hooks(&mut settings);

        assert_eq!(settings["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
        assert_eq!(
            settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            "custom-check"
        );
    }
}
