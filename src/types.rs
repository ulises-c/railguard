use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum HookClient {
    Auto,
    Claude,
    Codex,
}

impl HookClient {
    pub fn resolve(self, input: &HookInput) -> Self {
        if self != Self::Auto {
            return self;
        }
        if input.model.is_some() {
            Self::Codex
        } else {
            Self::Claude
        }
    }

    pub fn supports_interactive_approval(self) -> bool {
        matches!(self, Self::Claude)
    }
}

// ── Hook Input ──

#[derive(Debug, Clone, Deserialize)]
pub struct HookInput {
    pub session_id: String,
    pub cwd: String,
    pub hook_event_name: String,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub tool_input: Option<serde_json::Value>,
    #[serde(default)]
    pub tool_use_id: Option<String>,
    #[serde(default)]
    pub tool_response: Option<serde_json::Value>,
    #[serde(default)]
    pub timestamp: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
}

// ── Hook Output (what we write to stdout) ──

/// Prefix every approval prompt opens with. Shared so the Codex denial path can
/// strip it back off without the two copies drifting apart.
pub const ASK_BANNER: &str = "🛡️ RAILGUARD is asking (not Claude Code's permission system).\n\n";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HookOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook_specific_output: Option<HookSpecificOutput>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HookSpecificOutput {
    pub hook_event_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_decision_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

impl HookOutput {
    /// Allow a PreToolUse tool call using the response shape each client accepts.
    pub fn allow_for(client: HookClient) -> Self {
        if client == HookClient::Codex {
            return Self::noop();
        }

        HookOutput {
            hook_specific_output: Some(HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: Some("allow".to_string()),
                permission_decision_reason: None,
                additional_context: None,
            }),
        }
    }

    /// No-op output for events that don't need a permission decision
    /// (e.g. SessionStart, PostToolUse).
    pub fn noop() -> Self {
        HookOutput {
            hook_specific_output: None,
        }
    }

    pub fn deny(reason: &str) -> Self {
        // Codex rejects a `deny` carrying an empty reason and then runs the tool
        // anyway, so an empty reason must never reach the wire.
        let reason = match reason.trim() {
            "" => "Blocked by Railguard policy.",
            trimmed => trimmed,
        };
        HookOutput {
            hook_specific_output: Some(HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: Some("deny".to_string()),
                permission_decision_reason: Some(reason.to_string()),
                additional_context: None,
            }),
        }
    }

    pub fn ask(context: &str) -> Self {
        HookOutput {
            hook_specific_output: Some(HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: Some("ask".to_string()),
                permission_decision_reason: Some(context.to_string()),
                additional_context: Some(context.to_string()),
            }),
        }
    }

    pub fn approval_required(client: HookClient, context: &str) -> Self {
        if client.supports_interactive_approval() {
            return Self::ask(context);
        }

        let details = context.strip_prefix(ASK_BANNER).unwrap_or(context);
        Self::deny(&format!(
            "Railguard requires human approval, but Codex PreToolUse hooks cannot open an approval prompt. This tool call was blocked. Ask the human to update the Railguard policy or allowlist outside Codex, then retry.\n\n{}",
            details
        ))
    }

    pub fn session_message(message: &str) -> Self {
        HookOutput {
            hook_specific_output: Some(HookSpecificOutput {
                hook_event_name: "SessionStart".to_string(),
                permission_decision: None,
                permission_decision_reason: None,
                additional_context: Some(message.to_string()),
            }),
        }
    }
}

// ── Policy Types ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Policy {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub blocklist: Vec<Rule>,
    #[serde(default)]
    pub approve: Vec<Rule>,
    #[serde(default)]
    pub allowlist: Vec<Rule>,
    #[serde(default)]
    pub fence: FenceConfig,
    #[serde(default)]
    pub trace: TraceConfig,
    #[serde(default)]
    pub snapshot: SnapshotConfig,
    #[serde(default)]
    pub memory: MemoryConfig,
}

fn default_version() -> u32 {
    1
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    pub name: String,
    #[serde(default = "default_tool")]
    pub tool: String,
    pub pattern: String,
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default)]
    pub message: Option<String>,
}

fn default_tool() -> String {
    "Bash".to_string()
}

fn default_action() -> String {
    "block".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FenceConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub allowed_paths: Vec<String>,
    /// Additive: entries here are unioned with the built-in denies rather than
    /// replacing them. Listing one custom path must never silently drop
    /// `~/.ssh` — or `~/.claude` / `~/.codex`, which are Railguard's own
    /// self-protection. Use `denied_paths_remove` to drop a built-in on purpose.
    #[serde(default)]
    pub denied_paths: Vec<String>,
    /// Built-in denies to opt out of, by exact string. Deliberately explicit and
    /// noisy: `railguard status` reports every entry, because giving the agent
    /// write access to one of these is a decision that should stay visible.
    #[serde(default)]
    pub denied_paths_remove: Vec<String>,
    /// When true, a project-local `.railguard.local.yaml` may *add* to
    /// `allowed_paths` (never remove denies). Off by default: the override file
    /// is controlled by the repository being guarded, so honoring it by default
    /// would let a cloned or hostile repo widen the fence across the user's home
    /// directory with no human confirmation. Denied paths still win, but the
    /// gap between "not denied" and "safe to write" is large. Opt in per machine
    /// from the human's own global policy.
    #[serde(default)]
    pub allow_local_overrides: bool,
}

impl Default for FenceConfig {
    fn default() -> Self {
        FenceConfig {
            enabled: true,
            allowed_paths: vec![],
            denied_paths: vec![
                "~/.ssh".to_string(),
                "~/.aws".to_string(),
                "~/.gnupg".to_string(),
                "~/.config/gcloud".to_string(),
                "~/.claude".to_string(),
                "~/.codex".to_string(),
                "/etc".to_string(),
                // Shell and login init files: writing any of these is arbitrary
                // code execution on the human's next shell, so they belong with
                // the credential stores rather than behind a mere approval prompt.
                "~/.bashrc".to_string(),
                "~/.bash_profile".to_string(),
                "~/.profile".to_string(),
                "~/.zshrc".to_string(),
                "~/.zshenv".to_string(),
                "~/.zprofile".to_string(),
                "~/.config/fish".to_string(),
                // Same reachability, one indirection out: hook/alias surfaces that
                // run on ordinary developer commands or at login.
                "~/.gitconfig".to_string(),
                "~/.config/git".to_string(),
                "~/.local/bin".to_string(),
                "~/.config/systemd/user".to_string(),
                "~/.config/autostart".to_string(),
            ],
            denied_paths_remove: vec![],
            allow_local_overrides: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TraceConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_trace_dir")]
    pub directory: String,
}

impl Default for TraceConfig {
    fn default() -> Self {
        TraceConfig {
            enabled: true,
            directory: default_trace_dir(),
        }
    }
}

fn default_trace_dir() -> String {
    ".railguard/traces".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SnapshotConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_snapshot_tools")]
    pub tools: Vec<String>,
    #[serde(default = "default_snapshot_dir")]
    pub directory: String,
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        SnapshotConfig {
            enabled: true,
            tools: default_snapshot_tools(),
            directory: default_snapshot_dir(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_snapshot_tools() -> Vec<String> {
    vec!["Write".to_string(), "Edit".to_string()]
}

fn default_snapshot_dir() -> String {
    ".railguard/snapshots".to_string()
}

// ── Memory Safety Types ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MemoryConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub require_approval_for_behavioral: bool,
    #[serde(default = "default_true")]
    pub block_secrets: bool,
    #[serde(default = "default_true")]
    pub append_only: bool,
    #[serde(default = "default_true")]
    pub verify_on_read: bool,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        MemoryConfig {
            enabled: true,
            require_approval_for_behavioral: true,
            block_secrets: true,
            append_only: true,
            verify_on_read: true,
        }
    }
}

/// Provenance record for a memory file write.
/// Stored in .railguard/memory/provenance.jsonl
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    pub id: String,
    pub timestamp: String,
    pub session_id: String,
    pub file_path: String,
    pub content_hash: String,
    pub classification: String,
    pub human_approved: bool,
    pub provenance: String,
}

/// Result of memory content classification.
#[derive(Debug, Clone, PartialEq)]
pub enum MemoryClassification {
    /// Factual project context — auto-allow
    Factual,
    /// Behavioral directive — requires human approval
    Behavioral,
    /// Contains secrets/credentials — block
    Secret,
}

/// Decision from the memory guard.
#[derive(Debug, Clone)]
pub enum MemoryDecision {
    /// Allow the write
    Allow,
    /// Block the write with a reason
    Block(String),
    /// Ask for human approval with a reason
    Approve(String),
}

// ── Trace Entry ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEntry {
    pub timestamp: String,
    pub session_id: String,
    pub event: String,
    pub tool: String,
    pub input_summary: String,
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    pub duration_ms: u64,
}

// ── Snapshot Manifest Entry ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEntry {
    pub id: String,
    pub timestamp: String,
    pub session_id: String,
    pub tool_use_id: String,
    pub file_path: String,
    pub hash: String,
    pub existed: bool,
}

// ── Decision (internal) ──

#[derive(Debug, Clone)]
pub enum Decision {
    Allow,
    Block { rule: String, message: String },
    Approve { rule: String, message: String },
}

#[cfg(test)]
mod hook_output_tests {
    use super::*;

    #[test]
    fn codex_approval_required_is_a_valid_denial() {
        let output = HookOutput::approval_required(HookClient::Codex, "Needs approval");
        let json = serde_json::to_value(output).unwrap();

        assert_eq!(
            json.pointer("/hookSpecificOutput/permissionDecision"),
            Some(&serde_json::Value::String("deny".to_string()))
        );
        assert!(!json.to_string().contains("\"ask\""));
    }

    #[test]
    fn codex_allow_omits_the_unsupported_decision() {
        let output = HookOutput::allow_for(HookClient::Codex);
        let json = serde_json::to_value(output).unwrap();

        assert_eq!(json, serde_json::json!({}));
    }

    #[test]
    fn claude_allow_keeps_the_explicit_decision() {
        let output = HookOutput::allow_for(HookClient::Claude);
        let json = serde_json::to_value(output).unwrap();

        assert_eq!(
            json.pointer("/hookSpecificOutput/permissionDecision"),
            Some(&serde_json::Value::String("allow".to_string()))
        );
    }

    #[test]
    fn claude_approval_required_keeps_ask() {
        let output = HookOutput::approval_required(HookClient::Claude, "Needs approval");
        let json = serde_json::to_value(output).unwrap();

        assert_eq!(
            json.pointer("/hookSpecificOutput/permissionDecision"),
            Some(&serde_json::Value::String("ask".to_string()))
        );
    }

    #[test]
    fn auto_client_detects_codex_model_field() {
        let codex: HookInput = serde_json::from_value(serde_json::json!({
            "session_id": "session",
            "cwd": "/project",
            "hook_event_name": "SessionStart",
            "model": "gpt-codex"
        }))
        .unwrap();
        let claude: HookInput = serde_json::from_value(serde_json::json!({
            "session_id": "session",
            "cwd": "/project",
            "hook_event_name": "SessionStart"
        }))
        .unwrap();

        assert_eq!(HookClient::Auto.resolve(&codex), HookClient::Codex);
        assert_eq!(HookClient::Auto.resolve(&claude), HookClient::Claude);
    }
}
