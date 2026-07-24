//! Evasion detection and command normalization.
//!
//! AI agents have been documented bypassing text-based safety rules by:
//! - Base64 encoding commands
//! - Using variable substitution ($CMD)
//! - Hex encoding
//! - String concatenation tricks
//! - Using eval/xargs/sh -c indirection
//! - Backtick/subshell command substitution
//!
//! This module normalizes commands before pattern matching to catch these.

use base64::Engine;
use std::sync::LazyLock;

static ASSIGN_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r#"(\w+)=["']?([^"';\s&|]+)["']?"#).unwrap());

/// Any path-shaped substring, preceded by start/whitespace/quote/`=`. Used only
/// inside recursed executable payloads (interpreter code, `eval`, command
/// substitutions, shell heredocs), where a path can be glued to code
/// punctuation (`open("/etc/x")`, `['cat','/etc/x']`) and no top-level shell
/// word-splitting applies. Not used at the shell command line — that's where
/// the issue #17 data-vs-operand false positives live.
static PATH_SUBSTR_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r#"(?:^|[\s"'=(\[,])((?:/|~/|\.\./)[\w./_-]+)"#).unwrap());

/// Normalize a command string for pattern matching.
/// Returns a vec of strings to match against (original + decoded variants).
pub fn normalize_command(cmd: &str) -> Vec<String> {
    let mut variants = vec![cmd.to_string()];

    // Collapse whitespace
    let collapsed = collapse_whitespace(cmd);
    if collapsed != cmd {
        variants.push(collapsed);
    }

    // Detect and decode base64 pipes: echo "dGVycm..." | base64 -d | sh
    if let Some(decoded) = detect_base64_pipe(cmd) {
        variants.push(decoded.clone());
        variants.extend(normalize_command(&decoded));
    }

    // Detect eval with string concat: eval "ter""raform destroy"
    if let Some(evaled) = detect_eval_concat(cmd) {
        variants.push(evaled.clone());
        variants.extend(normalize_command(&evaled));
    }

    // Detect variable expansion patterns: CMD="terraform destroy"; $CMD
    if let Some(expanded) = detect_variable_expansion(cmd) {
        variants.push(expanded.clone());
        variants.extend(normalize_command(&expanded));
    }

    // Detect multi-variable concat: a="terra"; b="form"; "$a$b" → "terraform"
    if let Some(expanded) = detect_multi_variable_concat(cmd) {
        variants.push(expanded.clone());
        variants.extend(normalize_command(&expanded));
    }

    // Detect sh -c / bash -c wrapping
    if let Some(inner) = detect_shell_wrapper(cmd) {
        variants.push(inner.clone());
        variants.extend(normalize_command(&inner));
    }

    // Detect xargs indirection: echo "terraform destroy" | xargs -I{} sh -c "{}"
    if let Some(inner) = detect_xargs(cmd) {
        variants.push(inner.clone());
    }

    // Detect hex escape sequences: $'\x74\x65\x72\x72\x61\x66\x6f\x72\x6d'
    if let Some(decoded) = detect_hex_escapes(cmd) {
        variants.push(decoded.clone());
    }

    // Detect backtick substitution
    if let Some(inner) = detect_backtick_subshell(cmd) {
        variants.push(inner.clone());
    }

    // P0 Fix: Recursive base64 decoding (catches double/triple encoding)
    if let Some(decoded) = detect_recursive_base64(cmd) {
        variants.push(decoded.clone());
        variants.extend(normalize_command(&decoded));
    }

    variants.sort();
    variants.dedup();
    variants
}

fn collapse_whitespace(cmd: &str) -> String {
    cmd.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Detect: echo "BASE64" | base64 --decode | sh
fn detect_base64_pipe(cmd: &str) -> Option<String> {
    let patterns = [
        r#"echo\s+["']?([A-Za-z0-9+/=]+)["']?\s*\|\s*base64\s+(-d|--decode)"#,
        r#"printf\s+["']?([A-Za-z0-9+/=]+)["']?\s*\|\s*base64\s+(-d|--decode)"#,
    ];

    for pattern in &patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if let Some(caps) = re.captures(cmd) {
                if let Some(b64) = caps.get(1) {
                    if let Ok(bytes) =
                        base64::engine::general_purpose::STANDARD.decode(b64.as_str())
                    {
                        if let Ok(decoded) = String::from_utf8(bytes) {
                            return Some(decoded);
                        }
                    }
                }
            }
        }
    }
    None
}

/// Detect: eval "ter""raform"" destroy" or eval $'terraform\x20destroy'
fn detect_eval_concat(cmd: &str) -> Option<String> {
    let trimmed = cmd.trim();
    if !trimmed.starts_with("eval ") {
        return None;
    }

    let rest = &trimmed[5..].trim();

    // Remove quotes and concatenate: "ter""raform" → terraform
    let unquoted = rest
        .replace("\"\"", "")
        .replace("''", "")
        .replace(['"', '\''], "");

    if unquoted != *rest {
        Some(unquoted)
    } else {
        Some(rest.to_string())
    }
}

static VAR_EXPANSION_ASSIGN_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r#"(\w+)=(?:"([^"]*)"|'([^']*)'|([^\s;&|"']+))"#).unwrap());

/// Detect: CMD="terraform destroy"; $CMD  or  X=terraform && $X destroy
///
/// The regex crate has no backreferences, so instead of matching
/// assignment and reference in one pattern, parse each assignment and
/// search the remainder for a bare `$name` reference. This also survives
/// decoy pairs (`A=v; $AB=x; $AB`) that a single left-to-right
/// non-overlapping scan would consume.
fn detect_variable_expansion(cmd: &str) -> Option<String> {
    for caps in VAR_EXPANSION_ASSIGN_RE.captures_iter(cmd) {
        let name = caps.get(1)?.as_str();
        let value = caps
            .get(2)
            .or_else(|| caps.get(3))
            .or_else(|| caps.get(4))?
            .as_str();
        let after = &cmd[caps.get(0)?.end()..];
        if let Some(pos) = find_bare_var_ref(after, name) {
            let rest = &after[pos + name.len() + 1..];
            return Some(format!("{}{}", value, rest));
        }
    }
    None
}

/// Find `$name` in `s` where it is not a prefix of a longer variable name.
fn find_bare_var_ref(s: &str, name: &str) -> Option<usize> {
    let pat = format!("${}", name);
    let mut start = 0;
    while let Some(i) = s[start..].find(&pat) {
        let abs = start + i;
        let end = abs + pat.len();
        let at_boundary = s[end..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_alphanumeric() && c != '_');
        if at_boundary {
            return Some(abs);
        }
        start = end;
    }
    None
}

/// Detect: sh -c "dangerous command" or bash -c "..."
fn detect_shell_wrapper(cmd: &str) -> Option<String> {
    let re = regex::Regex::new(r#"(?:sh|bash|zsh)\s+-c\s+["'](.+?)["']"#).ok()?;
    re.captures(cmd)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()))
}

/// Detect: echo "cmd" | xargs ...
fn detect_xargs(cmd: &str) -> Option<String> {
    let re = regex::Regex::new(r#"echo\s+["'](.+?)["']\s*\|\s*xargs"#).ok()?;
    re.captures(cmd)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()))
}

/// Detect: $'\x74\x65\x72\x72...' hex escape sequences
fn detect_hex_escapes(cmd: &str) -> Option<String> {
    if !cmd.contains("\\x") {
        return None;
    }

    let re = regex::Regex::new(r"\\x([0-9a-fA-F]{2})").ok()?;
    let decoded = re.replace_all(cmd, |caps: &regex::Captures| {
        let hex_str = caps.get(1).unwrap().as_str();
        if let Ok(byte) = u8::from_str_radix(hex_str, 16) {
            String::from(byte as char)
        } else {
            caps[0].to_string()
        }
    });

    if decoded != cmd {
        Some(decoded.replace("$'", "").replace('\'', ""))
    } else {
        None
    }
}

/// Detect backtick command substitution: `echo terraform` destroy
fn detect_backtick_subshell(cmd: &str) -> Option<String> {
    if !cmd.contains('`') {
        return None;
    }

    let re = regex::Regex::new(r"`echo\s+([^`]+)`").ok()?;
    let expanded = re.replace_all(cmd, |caps: &regex::Captures| {
        caps.get(1).unwrap().as_str().to_string()
    });

    if expanded != cmd {
        Some(expanded.to_string())
    } else {
        None
    }
}

/// P0 R3 Fix: Multi-variable concat — catches a="terra"; b="form"; "$a$b" destroy
/// Resolves all variable assignments and expands $var references in the command.
fn detect_multi_variable_concat(cmd: &str) -> Option<String> {
    // Parse all VAR="value" or VAR='value' assignments
    let assign_re = regex::Regex::new(r#"(\w+)=["']([^"']+)["']"#).ok()?;
    let mut vars = std::collections::HashMap::new();
    for caps in assign_re.captures_iter(cmd) {
        if let (Some(name), Some(value)) = (caps.get(1), caps.get(2)) {
            vars.insert(name.as_str().to_string(), value.as_str().to_string());
        }
    }

    if vars.is_empty() {
        return None;
    }

    // Find the execution portion (after the last ; or &&)
    let exec_part = cmd.rsplit([';', '&']).next().unwrap_or("").trim();

    if exec_part.is_empty() {
        return None;
    }

    // Expand $var and ${var} references
    let mut expanded = exec_part.to_string();
    for (name, value) in &vars {
        expanded = expanded.replace(&format!("${{{}}}", name), value);
        expanded = expanded.replace(&format!("${}", name), value);
    }

    // Remove surrounding quotes from the expanded result
    let expanded = expanded.replace(['"', '\''], "");
    let expanded = expanded.trim().to_string();

    if expanded != exec_part.replace(['"', '\''], "").trim() {
        Some(expanded)
    } else {
        None
    }
}

/// P0 Fix: Recursive base64 decoding — catches double/triple encoding.
/// e.g., echo 'ZEdWeWNtRm1iM0p0SUdSbGMzUnliM2s9' | base64 -d | base64 -d | sh
fn detect_recursive_base64(cmd: &str) -> Option<String> {
    // Count how many `base64 -d` / `base64 --decode` stages there are
    let decode_count = cmd.matches("base64 -d").count() + cmd.matches("base64 --decode").count();

    if decode_count < 2 {
        return None;
    }

    // Extract the initial base64 payload
    let re = regex::Regex::new(r#"echo\s+["']?([A-Za-z0-9+/=]+)["']?"#).ok()?;
    let caps = re.captures(cmd)?;
    let mut payload = caps.get(1)?.as_str().to_string();

    // Decode up to `decode_count` layers
    for _ in 0..decode_count {
        match base64::engine::general_purpose::STANDARD.decode(&payload) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(decoded) => payload = decoded,
                Err(_) => return None,
            },
            Err(_) => return None,
        }
    }

    Some(payload)
}

/// P0 Fix: Detect text-transform-to-shell patterns.
/// Catches: rev | sh, tr ... | sh, sed ... | sh, awk ... | sh
/// These transforms can construct any command at runtime.
pub fn is_transform_pipe_to_shell(cmd: &str) -> bool {
    let re = regex::Regex::new(r"(?:rev|tr\s+|sed\s+|awk\s+).*\|\s*(?:sh|bash|zsh|eval|source)\b");
    match re {
        Ok(re) => re.is_match(cmd),
        Err(_) => false,
    }
}

/// P0 Fix: Detect interpreter + obfuscation combos.
/// Catches: python3 -c "...base64.b64decode..." or "...chr(..." etc.
/// The combination of an interpreter with string manipulation is suspicious.
/// Strong obfuscation — encoding/decoding and dynamic execution of constructed
/// code. These have no place in readable code, so they flag in *any* interpreter
/// payload, inline one-liner or multi-line heredoc script.
static STRONG_OBFUSCATION_SIGNALS: LazyLock<Vec<regex::Regex>> = LazyLock::new(|| {
    compile_signals(&[
        r"b64decode",
        r"b64encode",
        r"base64\s*\.\s*\w*decode",
        r"codecs\s*\.\s*decode",
        r"fromhex",
        r"unhexlify",
        r"atob\s*\(",
        // Bare calls only: attribute calls (re.compile, model.eval,
        // ast.literal_eval, child_process.exec) are everyday code, so require a
        // non-word, non-dot char (or start) before the name. The regex crate
        // has no lookbehind; the alternation group stands in for one.
        r"(?:^|[^\w.])eval\s*\(",
        r"(?:^|[^\w.])exec\s*\(",
        r"(?:^|[^\w.])compile\s*\(",
    ])
});

/// Weak obfuscation — character assembly, hex escapes, path assembly. Readable
/// scripts use these legitimately (ANSI stripping, byte handling, path joins),
/// so they only flag in a terse inline one-liner, where they are far more
/// suspicious than in a multi-line heredoc script (issue #18).
static INLINE_OBFUSCATION_SIGNALS: LazyLock<Vec<regex::Regex>> = LazyLock::new(|| {
    compile_signals(&[
        r"chr\s*\(",
        r"fromCharCode",
        r"\\x[0-9a-fA-F]{2}",
        // Path assembly via join — '/'.join or "/".join
        r#"['"]/'*\s*\.\s*join\s*\("#,
    ])
});

/// Command-execution primitives. Only treated as obfuscation in an inline
/// one-liner (`-c`/`-e`/`<<<`/`eval`) — the classic bypass shape. Multi-line
/// heredoc scripts use subprocess legitimately all the time.
static EXECUTION_SIGNALS: LazyLock<Vec<regex::Regex>> = LazyLock::new(|| {
    compile_signals(&[
        r"os\.system",
        r"os\.popen",
        r"system\s*\(",
        r"Popen\s*\(",
        r"subprocess",
        r"child_process",
    ])
});

fn compile_signals(patterns: &[&str]) -> Vec<regex::Regex> {
    patterns
        .iter()
        .map(|p| regex::Regex::new(p).unwrap())
        .collect()
}

#[derive(Clone, Copy, PartialEq)]
enum PayloadKind {
    /// Inline one-liner: `-c`/`-e` arg, `<<<` here-string, `eval` arg.
    Inline,
    /// Multi-line script fed on stdin via a heredoc.
    Script,
}

/// True when an interpreter in `cmd` is fed a code payload carrying genuine
/// obfuscation signals. Signals are matched only inside the executable payload
/// (the interpreter's `-c`/`-e` string, here-string, `eval` arg, or heredoc
/// body) — never against surrounding data such as comments, commit messages, or
/// prose that merely mentions an interpreter (issue #18).
pub fn is_interpreter_obfuscation(cmd: &str) -> bool {
    for (kind, payload) in interpreter_code_payloads(cmd) {
        if STRONG_OBFUSCATION_SIGNALS
            .iter()
            .any(|re| re.is_match(&payload))
        {
            return true;
        }
        if kind == PayloadKind::Inline
            && (INLINE_OBFUSCATION_SIGNALS
                .iter()
                .any(|re| re.is_match(&payload))
                || EXECUTION_SIGNALS.iter().any(|re| re.is_match(&payload)))
        {
            return true;
        }
    }
    false
}

/// The executable code payloads an interpreter/shell is invoked with in `cmd`.
/// Reuses the same command-resolution predicates as path extraction so the two
/// stay consistent (issue #27): only segments whose effective command is a
/// shell/interpreter contribute a payload.
fn interpreter_code_payloads(cmd: &str) -> Vec<(PayloadKind, String)> {
    let mut payloads = Vec::new();
    collect_interpreter_payloads(cmd, 0, &mut payloads);
    payloads
}

fn collect_interpreter_payloads(
    cmd: &str,
    depth: usize,
    payloads: &mut Vec<(PayloadKind, String)>,
) {
    if depth > MAX_EXTRACT_DEPTH {
        return;
    }
    let parsed = tokenize_shell(cmd);

    for_each_segment(&parsed.tokens, |segment| {
        collect_payloads_from_segment(segment, depth, payloads);
    });

    // Obfuscation hidden in a command substitution feeding another command is
    // still executable code; recurse it as the path extractor does.
    for sub in &parsed.substitutions {
        collect_interpreter_payloads(sub, depth + 1, payloads);
    }
    for heredoc in &parsed.heredocs {
        if heredoc.body_is_code {
            payloads.push((PayloadKind::Script, heredoc.body.clone()));
        }
    }
}

fn collect_payloads_from_segment(
    tokens: &[&ShellToken],
    depth: usize,
    payloads: &mut Vec<(PayloadKind, String)>,
) {
    let words: Vec<&str> = tokens
        .iter()
        .filter_map(|t| match t {
            ShellToken::Word(w) => Some(w.as_str()),
            _ => None,
        })
        .collect();
    if words.is_empty() {
        return;
    }
    let (eff_idx, split_commands) = resolve_effective_command(&words);
    for command in split_commands {
        collect_interpreter_payloads(&format!("env {command}"), depth + 1, payloads);
    }
    let eff = words
        .get(eff_idx)
        .map(|w| command_basename(w))
        .unwrap_or("");
    let stdin_is_code = heredoc_body_is_code(&words);
    if !is_shell_or_interpreter(eff) && !stdin_is_code {
        return;
    }

    let mut pending_inline_code = false;
    let mut pending_option_value = false;
    let mut here_string = false;
    let mut word_no = 0usize;
    for tok in tokens {
        match tok {
            ShellToken::Op("<<<") => here_string = true,
            ShellToken::Op(_) => here_string = false,
            ShellToken::Redirection(w) => {
                if std::mem::take(&mut here_string) && stdin_is_code {
                    payloads.push((PayloadKind::Inline, w.to_string()));
                }
            }
            ShellToken::Word(w) => {
                if std::mem::take(&mut pending_inline_code) {
                    payloads.push((PayloadKind::Inline, w.to_string()));
                } else if word_no > eff_idx && !std::mem::take(&mut pending_option_value) {
                    if eff == "eval" {
                        payloads.push((PayloadKind::Inline, w.to_string()));
                    } else if is_inline_code_flag(eff, w) {
                        pending_inline_code = true;
                    } else if interpreter_option_takes_value(eff, w) {
                        pending_option_value = true;
                    }
                }
                word_no += 1;
            }
        }
    }
}

/// Split a token stream into pipeline/list segments on shell operators, calling
/// `f` with each segment. Shared by path and payload extraction so the two
/// never disagree on where a command begins.
fn for_each_segment<F: FnMut(&[&ShellToken])>(tokens: &[ShellToken], mut f: F) {
    let mut segment: Vec<&ShellToken> = Vec::new();
    for tok in tokens {
        if let ShellToken::Op(op) = tok {
            if matches!(*op, "&&" | "||" | ";" | "|" | "&" | "(" | ")" | "`") {
                f(&segment);
                segment.clear();
                continue;
            }
        }
        segment.push(tok);
    }
    f(&segment);
}

/// Extract all file paths from a command, resolving variable assignments.
/// This catches variable indirection like: d="$HOME/.ssh"; cat "$d/id_ed25519"
///
/// Extraction is shell-word-level (issue #17): a token is a path candidate only
/// when a word *starts* with a path marker (`/`, `~/`, `../`) — or the value of
/// `--opt=value` / an attached short flag like `-I/usr/include` does. Path
/// mentions buried inside multi-word quoted text (commit messages, sed
/// programs, prose) are data, not operands. Executable payloads are still
/// scanned: interpreter `-c`/`-e` strings, `eval` args, `$(...)`/backtick
/// substitutions, and heredoc bodies consumed by a shell/interpreter are
/// recursed as sub-commands.
pub fn extract_paths_from_command(cmd: &str) -> Vec<String> {
    let mut paths = Vec::new();
    extract_paths_inner(cmd, 0, &mut paths);
    paths
}

const MAX_EXTRACT_DEPTH: usize = 4;

fn extract_paths_inner(cmd: &str, depth: usize, paths: &mut Vec<String>) {
    if depth > MAX_EXTRACT_DEPTH {
        return;
    }

    let mut vars = std::collections::HashMap::new();
    for caps in ASSIGN_RE.captures_iter(cmd) {
        if let (Some(name), Some(value)) = (caps.get(1), caps.get(2)) {
            vars.insert(name.as_str().to_string(), value.as_str().to_string());
        }
    }
    if let Some(home) = dirs::home_dir() {
        vars.insert("HOME".to_string(), home.display().to_string());
    }

    let mut expanded_cmd = cmd.to_string();
    // Two passes so a value that itself contains a variable ($HOME inside an
    // assignment) resolves regardless of map iteration order.
    for _ in 0..2 {
        for (name, value) in &vars {
            expanded_cmd = expanded_cmd.replace(&format!("${{{}}}", name), value);
            expanded_cmd = expanded_cmd.replace(&format!("${}", name), value);
        }
    }

    collect_paths_from_text(&expanded_cmd, depth, paths);
    if expanded_cmd != cmd {
        collect_paths_from_text(cmd, depth, paths);
    }

    // Recursed payloads are executable code, not a shell command line: a path
    // may be glued to code punctuation that word-splitting can't isolate, so
    // fall back to substring scanning to restore the flat-regex coverage.
    if depth > 0 {
        scan_path_substrings(&expanded_cmd, paths);
        if expanded_cmd != cmd {
            scan_path_substrings(cmd, paths);
        }
    }
}

fn scan_path_substrings(text: &str, paths: &mut Vec<String>) {
    for caps in PATH_SUBSTR_RE.captures_iter(text) {
        if let Some(m) = caps.get(1) {
            let p = m.as_str().to_string();
            if has_path_component(&p) && !is_benign_path(&p) && !paths.contains(&p) {
                paths.push(p);
            }
        }
    }
}

/// Tokenize one command text and collect path candidates, splitting into
/// pipeline/list segments and processing each independently.
fn collect_paths_from_text(text: &str, depth: usize, paths: &mut Vec<String>) {
    let parsed = tokenize_shell(text);

    for_each_segment(&parsed.tokens, |segment| {
        collect_paths_from_segment(segment, depth, paths);
    });

    for sub in &parsed.substitutions {
        extract_paths_inner(sub, depth + 1, paths);
    }
    for heredoc in &parsed.heredocs {
        if heredoc.body_is_code {
            extract_paths_inner(&heredoc.body, depth + 1, paths);
        }
    }
}

#[derive(PartialEq)]
enum NextWord {
    Operand,
    Skip,
    Recurse,
}

/// Process one command segment: resolve the effective command (skipping env
/// assignments and wrapper prefixes like `env`, `timeout`, `xargs` so
/// `env bash -c '...'` is still recognized as an interpreter invocation), then
/// treat the remaining words as path operands — except interpreter code
/// payloads (recursed) and git/gh message text (skipped).
fn collect_paths_from_segment(tokens: &[&ShellToken], depth: usize, paths: &mut Vec<String>) {
    let words: Vec<&str> = tokens
        .iter()
        .filter_map(|t| match t {
            ShellToken::Word(w) => Some(w.as_str()),
            _ => None,
        })
        .collect();
    if words.is_empty() {
        return;
    }
    let (eff_idx, split_commands) = resolve_effective_command(&words);
    for command in split_commands {
        extract_paths_inner(&format!("env {command}"), depth + 1, paths);
    }
    let eff = words
        .get(eff_idx)
        .map(|w| command_basename(w))
        .unwrap_or("");
    let is_vcs = matches!(eff, "git" | "gh");
    let is_interp = is_shell_or_interpreter(eff);
    let stdin_is_code = heredoc_body_is_code(&words);

    let mut pending = NextWord::Operand;
    let mut here_string = false;
    let mut word_no = 0usize;
    for tok in tokens {
        match tok {
            ShellToken::Op("<<<") => here_string = true,
            ShellToken::Op(_) => here_string = false,
            ShellToken::Redirection(w) => {
                if std::mem::take(&mut here_string) && stdin_is_code {
                    extract_paths_inner(w, depth + 1, paths);
                } else {
                    push_candidate(w, paths);
                }
            }
            ShellToken::Word(w) => {
                match std::mem::replace(&mut pending, NextWord::Operand) {
                    NextWord::Recurse => extract_paths_inner(w, depth + 1, paths),
                    NextWord::Skip => {}
                    NextWord::Operand => {
                        if word_no <= eff_idx {
                            push_candidate(w, paths);
                        } else if is_vcs && is_message_flag(w) {
                            // `-m msg` skips the following value; attached
                            // `--message=msg` skips only itself.
                            if matches!(w.as_str(), "-m" | "--message" | "--title" | "--body") {
                                pending = NextWord::Skip;
                            }
                        } else if is_interp && is_code_flag(w) {
                            pending = NextWord::Recurse;
                        } else if eff == "eval" {
                            extract_paths_inner(w, depth + 1, paths);
                        } else {
                            push_candidate(w, paths);
                        }
                    }
                }
                word_no += 1;
            }
        }
    }
}

fn resolve_effective_command<'a>(words: &[&'a str]) -> (usize, Vec<&'a str>) {
    let mut idx = 0;
    let mut wrapper = None;
    let mut split_commands = Vec::new();
    while idx < words.len() {
        let w = words[idx];
        let command = command_basename(w);
        if is_env_assignment(w) {
            idx += 1;
        } else if is_wrapper(command) {
            wrapper = Some(command);
            idx += 1;
        } else if let Some(split_command) =
            env_split_string_value(w).filter(|_| wrapper == Some("env"))
        {
            split_commands.push(split_command);
            idx += 1;
        } else if wrapper.is_some_and(|wrapper| wrapper_option_takes_value(wrapper, w)) {
            if wrapper == Some("env")
                && matches!(w, "-S" | "--split-string")
                && idx + 1 < words.len()
            {
                split_commands.push(words[idx + 1]);
            }
            idx += 2;
        } else if wrapper.is_some()
            && !w.is_empty()
            && (w.starts_with('-') || w.chars().all(|c| c.is_ascii_digit()))
        {
            idx += 1;
        } else {
            break;
        }
    }
    (idx.min(words.len().saturating_sub(1)), split_commands)
}

fn heredoc_body_is_code(words: &[&str]) -> bool {
    let (eff_idx, split_commands) = resolve_effective_command(words);
    // `xargs` reads stdin itself and hands the wrapped command *arguments*, so a
    // heredoc it consumes is argument data — never the wrapped command's script.
    if words
        .iter()
        .take(eff_idx + 1)
        .any(|word| command_basename(word) == "xargs")
    {
        return false;
    }
    let split_command_reads_stdin = split_commands
        .iter()
        .any(|command| command_reads_stdin_as_code(&format!("env {command}")));
    if split_command_reads_stdin {
        return true;
    }
    if words
        .get(eff_idx)
        .is_some_and(|word| split_commands.contains(word))
    {
        return false;
    }

    let eff = words
        .get(eff_idx)
        .map(|word| command_basename(word))
        .unwrap_or("");
    if !is_shell_or_interpreter(eff) || eff == "eval" {
        return false;
    }
    if eff == "busybox" {
        return words
            .iter()
            .skip(eff_idx + 1)
            .position(|word| !word.starts_with('-'))
            .is_some_and(|offset| heredoc_body_is_code(&words[eff_idx + 1 + offset..]));
    }

    let mut pending_inline_code = false;
    let mut pending_option_value = false;
    for word in words.iter().skip(eff_idx + 1) {
        if pending_inline_code {
            return false;
        }
        if std::mem::take(&mut pending_option_value) {
            continue;
        }
        if is_inline_code_flag(eff, word) {
            pending_inline_code = true;
        } else if interpreter_option_takes_value(eff, word) {
            pending_option_value = true;
        } else if *word == "-"
            || (is_shell(eff)
                && word.starts_with('-')
                && !word.starts_with("--")
                && word[1..].contains('s'))
        {
            return true;
        } else if !word.starts_with('-') {
            return false;
        }
    }
    !pending_inline_code && !pending_option_value
}

fn command_reads_stdin_as_code(command: &str) -> bool {
    let parsed = tokenize_shell(command);
    let mut reads_stdin_as_code = false;
    for_each_segment(&parsed.tokens, |segment| {
        let words: Vec<&str> = segment
            .iter()
            .filter_map(|token| match token {
                ShellToken::Word(word) => Some(word.as_str()),
                _ => None,
            })
            .collect();
        if !words.is_empty() && heredoc_body_is_code(&words) {
            reads_stdin_as_code = true;
        }
    });
    reads_stdin_as_code
}

const WRAPPER_VALUE_OPTIONS: &[(&str, &[&str])] = &[
    (
        "env",
        &[
            "-u",
            "--unset",
            "-C",
            "--chdir",
            "-S",
            "--split-string",
            "--argv0",
        ],
    ),
    ("exec", &["-a"]),
    ("nice", &["-n", "--adjustment"]),
    (
        "ionice",
        &[
            "-c",
            "--class",
            "-n",
            "--classdata",
            "-p",
            "--pid",
            "-P",
            "--pgid",
            "-u",
            "--uid",
        ],
    ),
    ("timeout", &["-k", "--kill-after", "-s", "--signal"]),
    (
        "stdbuf",
        &["-i", "--input", "-o", "--output", "-e", "--error"],
    ),
    (
        "xargs",
        &[
            "-a",
            "--arg-file",
            "-E",
            "--eof",
            "-I",
            "--replace",
            "-L",
            "--max-lines",
            "-n",
            "--max-args",
            "-P",
            "--max-procs",
            "-s",
            "--max-chars",
            "--process-slot-var",
        ],
    ),
    (
        "chrt",
        &[
            "-T",
            "--sched-runtime",
            "-P",
            "--sched-period",
            "-D",
            "--sched-deadline",
        ],
    ),
    ("time", &["-f", "--format", "-o", "--output"]),
    ("proxychains", &["-f"]),
    ("proxychains4", &["-f"]),
    (
        "sudo",
        &[
            "-a",
            "--auth-type",
            "-C",
            "--close-from",
            "-c",
            "--login-class",
            "-D",
            "--chdir",
            "-g",
            "--group",
            "-h",
            "--host",
            "-p",
            "--prompt",
            "-R",
            "--chroot",
            "-r",
            "--role",
            "-T",
            "--command-timeout",
            "-t",
            "--type",
            "-U",
            "--other-user",
            "-u",
            "--user",
        ],
    ),
    (
        "doas",
        &["-a", "--auth-style", "-C", "--config", "-u", "--user"],
    ),
];

fn wrapper_option_takes_value(wrapper: &str, option: &str) -> bool {
    WRAPPER_VALUE_OPTIONS
        .iter()
        .any(|(command, options)| *command == wrapper && options.contains(&option))
}

fn env_split_string_value(option: &str) -> Option<&str> {
    option
        .strip_prefix("--split-string=")
        .or_else(|| option.strip_prefix("-S").filter(|value| !value.is_empty()))
}

fn is_env_assignment(w: &str) -> bool {
    match w.find('=') {
        Some(eq) if eq > 0 => w[..eq].chars().all(|c| c.is_alphanumeric() || c == '_'),
        _ => false,
    }
}

/// Commands that delegate to a following command rather than being the
/// operation themselves — the real command is resolved past them.
fn is_wrapper(cmd: &str) -> bool {
    matches!(
        cmd,
        "env"
            | "command"
            | "exec"
            | "nohup"
            | "nice"
            | "ionice"
            | "timeout"
            | "stdbuf"
            | "setsid"
            | "unbuffer"
            | "xargs"
            | "chrt"
            | "time"
            | "proxychains"
            | "proxychains4"
            | "sudo"
            | "doas"
    )
}

/// A flag that introduces inline code for a shell/interpreter: `--eval`, or a
/// single-dash cluster containing a code letter - `c` (sh/python), `e`/`E`
/// (perl/ruby/node), `n`/`p` (perl/node autoloop) - so `-c`, `-E`, `-cx`, `-ne`
/// all match. Only consulted when the effective command is an interpreter.
fn is_code_flag(w: &str) -> bool {
    w == "--eval"
        || (w.len() >= 2
            && w.starts_with('-')
            && !w.starts_with("--")
            && w[1..]
                .chars()
                .any(|c| matches!(c, 'c' | 'e' | 'E' | 'n' | 'p')))
}

fn is_inline_code_flag(eff: &str, w: &str) -> bool {
    let is_short_option = w.len() >= 2 && w.starts_with('-') && !w.starts_with("--");
    if is_shell(eff) {
        return is_short_option && w[1..].contains('c');
    }
    if eff.starts_with("python") {
        return w == "-c";
    }
    if eff.starts_with("perl") {
        return w == "--eval" || (is_short_option && matches!(w.chars().last(), Some('e' | 'E')));
    }
    if eff.starts_with("ruby") {
        return w == "--eval" || (is_short_option && w.ends_with('e'));
    }
    if matches!(eff, "node" | "nodejs") {
        return matches!(w, "--eval" | "--print")
            || (is_short_option && matches!(w.chars().last(), Some('e' | 'p')));
    }
    if eff == "pwsh" {
        return matches!(w.to_ascii_lowercase().as_str(), "-c" | "-command");
    }
    matches!(
        (eff, w),
        ("php", "-r" | "--run") | ("lua", "-e") | ("expect", "-c")
    )
}

fn interpreter_option_takes_value(eff: &str, option: &str) -> bool {
    if eff.starts_with("python") {
        return matches!(option, "-W" | "-X" | "--check-hash-based-pycs");
    }
    if is_shell(eff) {
        return matches!(
            option,
            "-O" | "+O" | "-o" | "+o" | "--init-file" | "--rcfile"
        );
    }
    if eff == "php" {
        return matches!(option, "-c" | "--php-ini" | "-d" | "--define");
    }
    if matches!(eff, "node" | "nodejs") {
        return matches!(
            option,
            "-r" | "--require" | "--import" | "--loader" | "--input-type" | "--conditions"
        );
    }
    if eff.starts_with("ruby") {
        return matches!(option, "-I" | "-r" | "-C" | "-E" | "-F");
    }
    if eff == "lua" {
        return option == "-l";
    }
    if eff == "tclsh" {
        return option == "-encoding";
    }
    if eff == "pwsh" {
        return matches!(
            option.to_ascii_lowercase().as_str(),
            "-executionpolicy" | "-workingdirectory" | "-configurationname"
        );
    }
    false
}

fn is_shell(command: &str) -> bool {
    matches!(
        command,
        "sh" | "bash" | "zsh" | "dash" | "ksh" | "mksh" | "ash"
    )
}

fn push_candidate(word: &str, paths: &mut Vec<String>) {
    if let Some(p) = path_candidate(word) {
        if has_path_component(&p) && !is_benign_path(&p) && !paths.contains(&p) {
            paths.push(p);
        }
    }
}

/// The path candidate named by a shell word, if the word is a path operand.
/// A word qualifies only when it *starts* with a path marker (`/`, `~/`,
/// `../`) — so a path-shaped run buried inside multi-word data is ignored — and
/// the candidate is the leading path run, stopping at the first character a
/// path can't contain. This mirrors the old regex for operands (`~/.ssh/*`
/// yields `~/.ssh/`, `/etc/secret:/data` yields `/etc/secret`) without scanning
/// across word boundaries.
fn path_candidate(word: &str) -> Option<String> {
    if let Some(rest) = word.strip_prefix("file://") {
        let rest = rest.strip_prefix("localhost").unwrap_or(rest);
        return leading_path(rest);
    }
    if word.contains("://") {
        return None;
    }
    if let Some(p) = leading_path(word) {
        return Some(p);
    }
    if let Some((_, value)) = word.split_once('=') {
        if let Some(p) = leading_path(value) {
            return Some(p);
        }
    }
    if word.len() > 2 && word.starts_with('-') && word.as_bytes()[1].is_ascii_alphanumeric() {
        if let Some(p) = leading_path(&word[2..]) {
            return Some(p);
        }
    }
    None
}

/// The leading filesystem path of `s`, if `s` begins with `/`, `~/`, or `../`.
/// The run ends at the first character outside the plain path set, so a
/// trailing glob (`*`), separator (`:`), or space doesn't discard the path.
fn leading_path(s: &str) -> Option<String> {
    let prefix_len = if s.starts_with("~/") {
        2
    } else if s.starts_with("../") {
        3
    } else if s.starts_with('/') {
        1
    } else {
        return None;
    };
    let rest = &s[prefix_len..];
    let run = rest
        .find(|c: char| !(c.is_alphanumeric() || matches!(c, '.' | '/' | '_' | '-')))
        .unwrap_or(rest.len());
    Some(s[..prefix_len + run].to_string())
}

fn command_basename(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

/// git/gh flags whose value is message text (commit messages, PR titles/bodies)
/// and can never name a file. `--body-file` and friends intentionally don't match.
fn is_message_flag(w: &str) -> bool {
    matches!(w, "-m" | "--message" | "--title" | "--body")
        || (w.starts_with("-m") && !w.starts_with("--"))
        || w.starts_with("--message=")
        || w.starts_with("--title=")
        || w.starts_with("--body=")
}

/// Commands whose string arguments / heredoc bodies are executed, not data.
/// Prefix-matched for versioned binaries (`python3.12`, `perl5`).
fn is_shell_or_interpreter(cmd: &str) -> bool {
    if cmd.starts_with("python") || cmd.starts_with("ruby") || cmd.starts_with("perl") {
        return true;
    }
    matches!(
        cmd,
        "sh" | "bash"
            | "zsh"
            | "dash"
            | "ksh"
            | "mksh"
            | "ash"
            | "busybox"
            | "eval"
            | "node"
            | "nodejs"
            | "php"
            | "pwsh"
            | "lua"
            | "tclsh"
            | "expect"
    )
}

enum ShellToken {
    Word(String),
    Redirection(String),
    Op(&'static str),
}

struct Heredoc {
    body_is_code: bool,
    body: String,
}

struct TokenizedCommand {
    tokens: Vec<ShellToken>,
    heredocs: Vec<Heredoc>,
    /// `$(...)`/backtick bodies found inside double quotes — they execute, so
    /// they are scanned as sub-commands even though the enclosing word is data.
    substitutions: Vec<String>,
}

#[derive(Default)]
struct LexState {
    tokens: Vec<ShellToken>,
    heredocs: Vec<Heredoc>,
    substitutions: Vec<String>,
    word: String,
    has_word: bool,
    word_has_quoted_part: bool,
    segment_words: Vec<String>,
    /// Some(strip_tabs) right after a <</<<- operator: the next word is a heredoc delimiter.
    expecting_delim: Option<bool>,
    expecting_redirection: bool,
    /// Heredocs opened on the current line: (delimiter, strip_tabs, body_is_code).
    pending: Vec<(String, bool, Option<bool>)>,
}

impl LexState {
    fn push_char(&mut self, c: char) {
        self.word.push(c);
        self.has_word = true;
    }

    fn flush(&mut self) {
        if !self.has_word {
            return;
        }
        let w = std::mem::take(&mut self.word);
        self.has_word = false;
        self.word_has_quoted_part = false;
        if let Some(strip_tabs) = self.expecting_delim.take() {
            self.pending.push((w, strip_tabs, None));
        } else if std::mem::take(&mut self.expecting_redirection) {
            self.tokens.push(ShellToken::Redirection(w));
        } else {
            self.segment_words.push(w.clone());
            self.tokens.push(ShellToken::Word(w));
        }
    }

    fn current_heredoc_body_is_code(&self) -> bool {
        let refs: Vec<&str> = self.segment_words.iter().map(String::as_str).collect();
        heredoc_body_is_code(&refs)
    }

    fn finalize_pending_heredocs(&mut self) {
        let body_is_code = self.current_heredoc_body_is_code();
        for (_, _, classification) in &mut self.pending {
            if classification.is_none() {
                *classification = Some(body_is_code);
            }
        }
    }

    fn push_op(&mut self, op: &'static str, resets_segment: bool) {
        self.flush();
        if resets_segment {
            self.finalize_pending_heredocs();
            self.segment_words.clear();
        }
        self.tokens.push(ShellToken::Op(op));
    }

    fn push_redirection(&mut self, op: &'static str, strip_tabs: Option<bool>) {
        if self.has_word
            && !self.word_has_quoted_part
            && self.word.chars().all(|c| c.is_ascii_digit())
        {
            self.word.clear();
            self.has_word = false;
        } else {
            self.flush();
        }
        self.tokens.push(ShellToken::Op(op));
        if let Some(strip_tabs) = strip_tabs {
            self.expecting_delim = Some(strip_tabs);
        } else {
            self.expecting_redirection = true;
        }
    }

    /// Heredoc bodies start after the line that opened them. Returns the index
    /// past the consumed bodies.
    fn consume_heredoc_bodies(&mut self, chars: &[char], mut i: usize) -> usize {
        while let Some((delim, strip_tabs, body_is_code)) = self.pending.first().cloned() {
            let body_is_code =
                body_is_code.expect("heredoc classification is finalized at the opener newline");
            let mut body = String::new();
            let mut found = false;
            while i < chars.len() {
                let start = i;
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                let line: String = chars[start..i].iter().collect();
                if i < chars.len() {
                    i += 1;
                }
                let terminator = if strip_tabs {
                    line.trim_start_matches('\t')
                } else {
                    line.as_str()
                };
                if terminator == delim {
                    found = true;
                    break;
                }
                body.push_str(&line);
                body.push('\n');
            }
            self.heredocs.push(Heredoc { body_is_code, body });
            self.pending.remove(0);
            if !found {
                break;
            }
        }
        i
    }
}

/// Split command text into shell words and operators. Quotes are removed but
/// their content stays one word; operators split words even without spaces
/// (`>/etc/x`). Lenient on malformed input: an unbalanced quote consumes to
/// end-of-string as a single word.
fn tokenize_shell(text: &str) -> TokenizedCommand {
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    let mut lex = LexState::default();

    let mut i = 0;
    while i < len {
        match chars[i] {
            '\'' => {
                lex.has_word = true;
                lex.word_has_quoted_part = true;
                i += 1;
                while i < len && chars[i] != '\'' {
                    lex.word.push(chars[i]);
                    i += 1;
                }
                i += 1;
            }
            '"' => {
                lex.has_word = true;
                lex.word_has_quoted_part = true;
                i += 1;
                while i < len && chars[i] != '"' {
                    if chars[i] == '\\' && i + 1 < len {
                        lex.word.push(chars[i + 1]);
                        i += 2;
                    } else if chars[i] == '$' && i + 1 < len && chars[i + 1] == '(' {
                        let (sub, next) = read_substitution(&chars, i + 2);
                        lex.substitutions.push(sub);
                        i = next;
                    } else if chars[i] == '`' {
                        let start = i + 1;
                        let mut j = start;
                        while j < len && chars[j] != '`' {
                            j += 1;
                        }
                        lex.substitutions.push(chars[start..j].iter().collect());
                        i = if j < len { j + 1 } else { j };
                    } else {
                        lex.word.push(chars[i]);
                        i += 1;
                    }
                }
                i += 1;
            }
            '\\' => {
                if i + 1 < len {
                    lex.word_has_quoted_part = true;
                    lex.push_char(chars[i + 1]);
                }
                i += 2;
            }
            '\n' => {
                lex.push_op(";", true);
                i += 1;
                i = lex.consume_heredoc_bodies(&chars, i);
            }
            c if c.is_whitespace() => {
                lex.flush();
                i += 1;
            }
            '<' => {
                if i + 2 < len && chars[i + 1] == '<' && chars[i + 2] == '<' {
                    lex.push_redirection("<<<", None);
                    i += 3;
                } else if i + 1 < len && chars[i + 1] == '<' {
                    let strip_tabs = i + 2 < len && chars[i + 2] == '-';
                    lex.push_redirection("<<", Some(strip_tabs));
                    i += if strip_tabs { 3 } else { 2 };
                } else if i + 1 < len && chars[i + 1] == '&' {
                    lex.push_redirection("<&", None);
                    i += 2;
                } else if i + 1 < len && chars[i + 1] == '>' {
                    lex.push_redirection("<>", None);
                    i += 2;
                } else {
                    lex.push_redirection("<", None);
                    i += 1;
                }
            }
            '>' => {
                if i + 1 < len && chars[i + 1] == '>' {
                    lex.push_redirection(">>", None);
                    i += 2;
                } else if i + 1 < len && chars[i + 1] == '&' {
                    lex.push_redirection(">&", None);
                    i += 2;
                } else if i + 1 < len && chars[i + 1] == '|' {
                    lex.push_redirection(">|", None);
                    i += 2;
                } else {
                    lex.push_redirection(">", None);
                    i += 1;
                }
            }
            '|' => {
                if i + 1 < len && chars[i + 1] == '|' {
                    lex.push_op("||", true);
                    i += 2;
                } else {
                    lex.push_op("|", true);
                    i += 1;
                }
            }
            '&' => {
                if i + 2 < len && chars[i + 1] == '>' && chars[i + 2] == '>' {
                    lex.push_redirection("&>>", None);
                    i += 3;
                } else if i + 1 < len && chars[i + 1] == '>' {
                    lex.push_redirection("&>", None);
                    i += 2;
                } else if i + 1 < len && chars[i + 1] == '&' {
                    lex.push_op("&&", true);
                    i += 2;
                } else {
                    lex.push_op("&", true);
                    i += 1;
                }
            }
            ';' => {
                lex.push_op(";", true);
                i += 1;
            }
            '(' => {
                lex.push_op("(", true);
                i += 1;
            }
            ')' => {
                lex.push_op(")", true);
                i += 1;
            }
            '`' => {
                lex.push_op("`", true);
                i += 1;
            }
            // `#` starts a comment only at a word boundary (a bare `#`), not
            // mid-word (`a#b` is literal); skip the rest of the line so paths
            // mentioned in a trailing comment aren't read as operands.
            '#' if !lex.has_word => {
                while i < len && chars[i] != '\n' {
                    i += 1;
                }
            }
            c => {
                lex.push_char(c);
                i += 1;
            }
        }
    }
    lex.flush();
    lex.finalize_pending_heredocs();

    TokenizedCommand {
        tokens: lex.tokens,
        heredocs: lex.heredocs,
        substitutions: lex.substitutions,
    }
}

/// Read a `$(...)` body starting just past the opening paren.
/// Returns the body and the index past the closing paren.
///
/// Quote- and escape-aware: a parenthesis inside a quoted string is literal, so
/// counting it would truncate the substitution and hide the code after it
/// (`"$(printf ')'; python3 -c '...')"`).
fn read_substitution(chars: &[char], start: usize) -> (String, usize) {
    let mut depth = 1usize;
    let mut in_single = false;
    let mut in_double = false;
    let mut j = start;
    while j < chars.len() {
        match chars[j] {
            '\\' if !in_single => j += 1,
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '(' if !in_single && !in_double => depth += 1,
            ')' if !in_single && !in_double => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
        j += 1;
    }
    let end = if j < chars.len() { j + 1 } else { j };
    (chars[start..j].iter().collect(), end)
}

/// Whether a captured token actually names a file, rather than being a run of
/// path punctuation. The path regex can capture slash sequences with no real
/// component — e.g. `//` from jq's alternative operator (`a // b`) — which then
/// trip the fence as a bogus "outside project" path. Real targets (`/etc`,
/// `~/.ssh`, `../foo`) always carry at least one alphanumeric character.
fn has_path_component(path: &str) -> bool {
    path.chars().any(|c| c.is_alphanumeric())
}

/// Paths that should never trigger fence violations.
/// These are system/binary paths that appear in commands but aren't data targets.
fn is_benign_path(path: &str) -> bool {
    // /dev/* — virtual device paths
    path == "/dev/null"
        || path == "/dev/stdin"
        || path == "/dev/stdout"
        || path == "/dev/stderr"
        || path == "/dev/tty"
        || path.starts_with("/dev/fd/")
        // System binary/library paths (read-only, not sensitive data)
        || path.starts_with("/usr/bin/")
        || path.starts_with("/usr/local/bin/")
        || path.starts_with("/usr/lib/")
        || path.starts_with("/usr/sbin/")
        || path.starts_with("/bin/")
        || path.starts_with("/sbin/")
        || path.starts_with("/opt/homebrew/bin/")
        // Cargo binary path (railguard itself lives here)
        || path.contains(".cargo/bin/")
        // Temporary files
        || path.starts_with("/tmp/")
        || path.starts_with("/var/tmp/")
        || path.starts_with("/private/tmp/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_decode() {
        // "terraform destroy" in base64
        let cmd = "echo dGVycmFmb3JtIGRlc3Ryb3k= | base64 --decode | sh";
        let variants = normalize_command(cmd);
        assert!(variants.iter().any(|v| v.contains("terraform destroy")));
    }

    #[test]
    fn test_eval_concat() {
        let cmd = r#"eval "ter""raform destroy""#;
        let variants = normalize_command(cmd);
        assert!(variants.iter().any(|v| v.contains("terraform destroy")));
    }

    #[test]
    fn test_variable_expansion() {
        let cmd = r#"CMD="terraform destroy"; $CMD"#;
        let variants = normalize_command(cmd);
        assert!(variants.iter().any(|v| v.contains("terraform destroy")));
    }

    #[test]
    fn test_variable_expansion_unquoted_single_var() {
        // Regression for the dead-backreference bug: the unquoted form is not
        // covered by detect_multi_variable_concat (its assignment regex
        // requires quotes), so only detect_variable_expansion catches it.
        let cmd = "CMD=terraform; $CMD destroy";
        let expanded = detect_variable_expansion(cmd);
        assert_eq!(expanded.as_deref(), Some("terraform destroy"));
        let variants = normalize_command(cmd);
        assert!(
            variants.iter().any(|v| v.contains("terraform destroy")),
            "unquoted single-var expansion should normalize: {:?}",
            variants
        );
    }

    #[test]
    fn test_variable_expansion_skips_mismatched_reference() {
        assert_eq!(detect_variable_expansion("A=foo; $B run"), None);
        // A later matching pair is still found after a mismatched one.
        let expanded = detect_variable_expansion("A=foo; $B; C=terraform; $C destroy");
        assert_eq!(expanded.as_deref(), Some("terraform destroy"));
    }

    #[test]
    fn test_variable_expansion_decoy_pair_does_not_mask_real_one() {
        // A decoy assignment/reference whose names share a prefix must not
        // consume the genuine pair (found by adversarial review).
        let expanded = detect_variable_expansion("A=v; $AB=terraform; $AB destroy");
        assert_eq!(expanded.as_deref(), Some("terraform destroy"));
    }

    #[test]
    fn test_variable_expansion_and_separator_stays_clean() {
        // `&&`-chained assignments must not leak a stray `&` into the
        // expanded variant (would break downstream contiguous matching).
        let expanded = detect_variable_expansion("X=danger && $X -rf /");
        assert_eq!(expanded.as_deref(), Some("danger -rf /"));

        let expanded = detect_variable_expansion(r#"V="two words" && $V"#);
        assert_eq!(expanded.as_deref(), Some("two words"));
    }

    #[test]
    fn test_shell_wrapper() {
        let cmd = r#"sh -c "terraform destroy""#;
        let variants = normalize_command(cmd);
        assert!(variants.iter().any(|v| v == "terraform destroy"));
    }

    #[test]
    fn test_xargs() {
        let cmd = r#"echo "rm -rf /" | xargs sh -c"#;
        let variants = normalize_command(cmd);
        assert!(variants.iter().any(|v| v.contains("rm -rf /")));
    }

    #[test]
    fn test_hex_escapes() {
        // "rm" in hex
        let cmd = r"$'\x72\x6d' -rf /";
        let variants = normalize_command(cmd);
        assert!(variants.iter().any(|v| v.contains("rm -rf /")));
    }

    #[test]
    fn test_backtick_subshell() {
        let cmd = "`echo terraform` destroy";
        let variants = normalize_command(cmd);
        assert!(variants.iter().any(|v| v.contains("terraform destroy")));
    }

    #[test]
    fn test_passthrough_normal_command() {
        let cmd = "npm test";
        let variants = normalize_command(cmd);
        assert!(variants.contains(&"npm test".to_string()));
    }

    #[test]
    fn test_whitespace_collapse() {
        let cmd = "terraform    destroy   --auto-approve";
        let variants = normalize_command(cmd);
        assert!(variants
            .iter()
            .any(|v| v == "terraform destroy --auto-approve"));
    }

    #[test]
    fn test_double_base64() {
        // "terraform destroy" → base64 → base64 (double encoded)
        let cmd = "echo ZEdWeWNtRm1iM0p0SUdSbGMzUnliM2s9 | base64 -d | base64 -d | sh";
        let variants = normalize_command(cmd);
        assert!(variants.iter().any(|v| v.contains("terraform destroy")));
    }

    #[test]
    fn test_transform_pipe_to_shell() {
        assert!(is_transform_pipe_to_shell(
            "rev <<< 'yortsed mrofarret' | sh"
        ));
        assert!(is_transform_pipe_to_shell(
            "tr 'a-z' 'n-za-m' <<< 'greensbez' | bash"
        ));
        assert!(is_transform_pipe_to_shell("sed 's/x/y/g' file.txt | sh"));
        assert!(!is_transform_pipe_to_shell("rev file.txt")); // no pipe to sh
        assert!(!is_transform_pipe_to_shell("echo hello | sh")); // not a transform
    }

    #[test]
    fn test_interpreter_obfuscation() {
        assert!(is_interpreter_obfuscation(
            r#"python3 -c "import os,base64; os.system(base64.b64decode('dGVy').decode())""#
        ));
        assert!(is_interpreter_obfuscation(
            r#"python3 -c "import os; os.system(chr(116)+chr(101))""#
        ));
        assert!(is_interpreter_obfuscation(
            r#"ruby -e 'system("foo".decode)'"#
        ));
        assert!(is_interpreter_obfuscation(
            r#"node -e 'require("child_process").exec("foo")'"#
        ));
        // Safe: interpreter without obfuscation
        assert!(!is_interpreter_obfuscation(
            r#"python3 -c "print('hello world')""#
        ));
        // Safe: not an interpreter
        assert!(!is_interpreter_obfuscation("echo base64 | sh"));
    }

    #[test]
    fn test_interpreter_obfuscation_r3_python_join() {
        // R3 finding: Python '/'.join() to construct paths
        assert!(is_interpreter_obfuscation(
            r#"python3 -c "p = '/'.join(['','Users','arichoudhury','.claude','settings.json']); import json; d = json.load(open(p))""#
        ));
        // Python open() with join
        assert!(is_interpreter_obfuscation(
            r#"python3 -c "print(open('/'.join(['','etc','passwd'])).read())""#
        ));
    }

    #[test]
    fn test_interpreter_obfuscation_subprocess() {
        // subprocess.run
        assert!(is_interpreter_obfuscation(
            r#"python3 -c "import subprocess; subprocess.run(['terraform', 'destroy'])""#
        ));
        // subprocess.Popen
        assert!(is_interpreter_obfuscation(
            r#"python3 -c "import subprocess; subprocess.Popen('rm -rf /', shell=True)""#
        ));
        // os.popen
        assert!(is_interpreter_obfuscation(
            r#"python3 -c "import os; os.popen('cat /etc/passwd').read()""#
        ));
        // os.system
        assert!(is_interpreter_obfuscation(
            r#"python3 -c "import os; os.system('terraform destroy')""#
        ));
    }

    #[test]
    fn test_heredoc_interpreter_clean_code_not_flagged() {
        // Issue #18: a readable heredoc script must not be flagged just because
        // it reads/writes files or its comments mention an interpreter.
        let cmd = "python3 - <<'PY'\n\
                   import re\n\
                   text = open('railguard.yaml').read()\n\
                   blocks = re.split(r'(?m)^(?=\\S)', text)\n\
                   # reorder top-level keys, cf. python3 -c usage in docs\n\
                   open('railguard.yaml', 'w').write('\\n'.join(sorted(blocks)))\n\
                   PY";
        assert!(!is_interpreter_obfuscation(cmd));
    }

    #[test]
    fn test_heredoc_interpreter_obfuscated_payload_flagged() {
        // Same shape, but the body genuinely obfuscates — must still be caught.
        let cmd = "python3 - <<'PY'\n\
                   import base64, os\n\
                   os.system(base64.b64decode('dGVycmFmb3JtIGRlc3Ryb3k=').decode())\n\
                   PY";
        assert!(is_interpreter_obfuscation(cmd));
    }

    #[test]
    fn test_interpreter_option_values_do_not_hide_heredoc_payloads() {
        for command in [
            "python3 -W ignore <<'PY'\n\
             import base64, os\n\
             os.system(base64.b64decode('eA==').decode())\n\
             PY",
            "bash -O extglob <<'SH'\n\
             python3 -c \"import base64,os; os.system(base64.b64decode('eA==').decode())\"\n\
             SH",
            "php -c php.ini <<'PHP'\n\
             eval(base64_decode('ZWNobyAxOw=='));\n\
             PHP",
        ] {
            assert!(is_interpreter_obfuscation(command), "{command}");
        }
    }

    #[test]
    fn test_heredoc_before_program_definition_is_data() {
        for command in [
            "python3 <<'EOF' -c \"print('safe')\"\n\
             note: use the b64decode helper\n\
             EOF",
            "python3 <<'EOF' helper.py\n\
             note: use the b64decode helper\n\
             EOF",
            "python3 <<'EOF' 2>&1 helper.py\n\
             note: use the b64decode helper\n\
             EOF",
            "python3 <<'EOF' &>output.txt helper.py\n\
             note: use the b64decode helper\n\
             EOF",
            "python3 '2'>output.txt <<'EOF'\n\
             note: use the b64decode helper\n\
             EOF",
        ] {
            assert!(!is_interpreter_obfuscation(command), "{command}");
        }
    }

    #[test]
    fn test_redirections_are_not_interpreter_arguments() {
        let command = "python3 >output.txt 2>/dev/null <<'PY'\n\
             import base64, os\n\
             os.system(base64.b64decode('eA==').decode())\n\
             PY";
        assert!(is_interpreter_obfuscation(command));
    }

    #[test]
    fn test_signal_word_outside_payload_not_flagged() {
        // Signal words in data (commit messages, echoed docs) are not payloads.
        assert!(!is_interpreter_obfuscation(
            r#"git commit -m "document python3 -e usage and b64decode helper""#
        ));
        assert!(!is_interpreter_obfuscation(
            r#"python3 script.py && echo "see base64.b64decode docs""#
        ));
    }

    #[test]
    fn test_inline_readable_write_join_not_flagged() {
        // Readable open().write('\n'.join(...)) is not obfuscation — the '\n'
        // join has no path-assembly quote-slash signal.
        assert!(!is_interpreter_obfuscation(
            r#"python3 -c "open('out.txt','w').write('\n'.join(['a','b']))""#
        ));
    }

    #[test]
    fn test_autoloop_flag_does_not_capture_filename() {
        // `-n`/`-p` take no inline code, so the following script filename must
        // not be scanned as a payload — even if its name contains a signal word.
        assert!(!is_interpreter_obfuscation("sh -n deploy_subprocess.sh"));
        assert!(!is_interpreter_obfuscation("perl -n audit_system.pl"));
    }

    #[test]
    fn test_python_ignore_env_flag_before_code_flag() {
        // `python3 -E -c "<obf>"`: -E (ignore-env, no code) must not swallow -c;
        // the real -c payload still gets scanned.
        assert!(is_interpreter_obfuscation(
            r#"python3 -E -c "import base64,os; os.system(base64.b64decode('x').decode())""#
        ));
    }

    #[test]
    fn test_heredoc_benign_hex_escape_not_flagged() {
        // A heredoc script stripping ANSI escapes uses \x1b legitimately; hex
        // escapes are weak signals that must not flag a multi-line script.
        let cmd = "python3 - <<'PY'\n\
                   text = open('log.txt').read()\n\
                   clean = text.replace('\\x1b[0m', '')\n\
                   open('log.txt', 'w').write(clean)\n\
                   PY";
        assert!(!is_interpreter_obfuscation(cmd));
    }

    #[test]
    fn test_obfuscation_in_command_substitution_flagged() {
        // Obfuscation hidden in a $(...) feeding another command is still code.
        assert!(is_interpreter_obfuscation(
            r#"echo "$(python3 -c 'import base64,os; os.system(base64.b64decode("eA==").decode())')""#
        ));
    }

    #[test]
    fn test_quoted_paren_does_not_truncate_substitution() {
        // A `)` inside a quoted string is literal: counting it as the closing
        // paren would drop the interpreter call that follows.
        for cmd in [
            r#"echo "$(printf ')'; python3 -c 'import os; os.system(chr(108))')""#,
            r#"echo "$(printf ")"; python3 -c 'import os; os.system(chr(108))')""#,
            r#"echo "$(printf \); python3 -c 'import os; os.system(chr(108))')""#,
            r#"echo "$(echo "$(date)"; python3 -c 'import os; os.system(chr(108))')""#,
        ] {
            assert!(is_interpreter_obfuscation(cmd), "not flagged: {cmd}");
        }
    }

    #[test]
    fn test_read_substitution_respects_quotes_and_nesting() {
        let read = |text: &str| {
            let chars: Vec<char> = text.chars().collect();
            read_substitution(&chars, 0)
        };
        assert_eq!(read("printf ')' ; ls)").0, "printf ')' ; ls");
        assert_eq!(read(r#"printf ")" ; ls)"#).0, r#"printf ")" ; ls"#);
        assert_eq!(read(r"printf \) ; ls)").0, r"printf \) ; ls");
        assert_eq!(read("echo $(date) ; ls)").0, "echo $(date) ; ls");
        // Unbalanced input must terminate at end of text, not spin.
        assert_eq!(read("echo '(").0, "echo '(");
    }

    #[test]
    fn test_heredoc_attribute_calls_not_flagged() {
        // re.compile( / model.eval( / ast.literal_eval( are everyday Python;
        // only BARE eval(/exec(/compile( are dynamic-code-execution signals.
        let cmd = "python3 - <<'PY'\n\
                   import re, ast\n\
                   pat = re.compile(r'^foo')\n\
                   cfg = ast.literal_eval(open('cfg.txt').read())\n\
                   model.eval()\n\
                   PY";
        assert!(!is_interpreter_obfuscation(cmd));
    }

    #[test]
    fn test_heredoc_bare_dynamic_exec_flagged() {
        let cmd = "python3 - <<'PY'\n\
                   code = open('payload.txt').read()\n\
                   exec(compile(code, '<x>', 'exec'))\n\
                   PY";
        assert!(is_interpreter_obfuscation(cmd));
    }

    #[test]
    fn test_inline_re_compile_not_flagged() {
        assert!(!is_interpreter_obfuscation(
            r#"python3 -c "import re; print(re.compile('^a').match('a') is not None)""#
        ));
    }

    #[test]
    fn test_shell_errexit_flag_does_not_capture_filename() {
        // `sh -e` is errexit and `bash -E` is trap-inherit — neither takes
        // inline code, so the script filename must not be scanned as a payload.
        assert!(!is_interpreter_obfuscation("sh -e run_subprocess.sh"));
        assert!(!is_interpreter_obfuscation("bash -E trap_subprocess.sh"));
    }

    #[test]
    fn test_wrapper_option_values_do_not_hide_interpreter() {
        for command in [
            r#"sudo -u root python3 -c "base64.b64decode('eA==')""#,
            r#"env -u FOO python3 -c "base64.b64decode('eA==')""#,
            r#"env -S "python3 -c \"base64.b64decode('eA==')\"""#,
        ] {
            assert!(is_interpreter_obfuscation(command), "{command}");
        }
        assert!(!is_interpreter_obfuscation(r#"env -S "python3 script.py""#));
    }

    #[test]
    fn test_shell_code_flag_can_precede_other_flags() {
        assert!(is_interpreter_obfuscation(
            r#"bash -cx "python3 -c \"base64.b64decode('eA==')\"""#
        ));
    }

    #[test]
    fn test_herestring_data_to_script_file_not_flagged() {
        // When the interpreter runs a script FILE, a here-string is stdin data
        // the script reads, not code - a signal word in it must not flag.
        for command in [
            "python3 app.py <<< 'note: see the b64decode helper'",
            "python3 <<< 'note: see the b64decode helper' -c \"print('safe')\"",
        ] {
            assert!(!is_interpreter_obfuscation(command), "{command}");
        }
    }

    #[test]
    fn test_interpreter_option_values_do_not_hide_herestring_payloads() {
        for command in [
            "python3 -W ignore <<< \"import base64,os; \
             os.system(base64.b64decode('eA==').decode())\"",
            "env --split-string=\"bash -s\" <<< \
             \"python3 -c \\\"import base64,os; os.system(base64.b64decode('eA==').decode())\\\"\"",
        ] {
            assert!(is_interpreter_obfuscation(command), "{command}");
        }
    }

    #[test]
    fn test_heredoc_data_to_script_file_not_flagged() {
        for command in [
            "python3 app.py <<'EOF'\n\
             note: see the b64decode helper\n\
             EOF",
            "env -S \"python3 app.py\" <<'EOF'\n\
             note: see the b64decode helper\n\
             EOF",
        ] {
            assert!(!is_interpreter_obfuscation(command), "{command}");
        }
    }

    #[test]
    fn test_env_split_string_shell_heredoc_scanned() {
        for command in [
            "env -S \"bash -s\" <<'SH'\n\
             python3 -c \"import base64,os; os.system(base64.b64decode('eA==').decode())\"\n\
             SH",
            "env --split-string=\"bash -s\" <<'SH'\n\
             python3 -c \"import base64,os; os.system(base64.b64decode('eA==').decode())\"\n\
             SH",
            "env --split-string=\"-u FOO bash -s\" <<'SH'\n\
             python3 -c \"import base64,os; os.system(base64.b64decode('eA==').decode())\"\n\
             SH",
            "env -S \"-u FOO\" bash -s <<'SH'\n\
             python3 -c \"import base64,os; os.system(base64.b64decode('eA==').decode())\"\n\
             SH",
        ] {
            assert!(is_interpreter_obfuscation(command), "{command}");
        }
    }

    #[test]
    fn test_env_split_string_node_heredoc_scanned() {
        let command = "env -S \"node --input-type=commonjs\" <<'JS'\n\
             eval(atob('Y29uc29sZS5sb2coMSk='))\n\
             JS";
        assert!(is_interpreter_obfuscation(command));
    }

    #[test]
    fn test_interpreter_no_false_positives() {
        // Safe: simple print with path — should NOT trigger
        assert!(!is_interpreter_obfuscation(
            r#"python3 -c "print('hello world')""#
        ));
        // Safe: reading a file with literal path — no obfuscation
        assert!(!is_interpreter_obfuscation(
            r#"python3 -c "print(open('/tmp/output.txt').read())""#
        ));
        // Safe: math with + — should NOT trigger
        assert!(!is_interpreter_obfuscation(r#"python3 -c "print(1 + 2)""#));
        // Safe: not an interpreter
        assert!(!is_interpreter_obfuscation("echo base64 | sh"));
    }

    #[test]
    fn test_multi_variable_concat() {
        // R3 finding: a="terra"; b="form"; "$a$b" destroy
        let cmd = r#"a="terra"; b="form"; c="destroy"; "$a$b" "$c""#;
        let variants = normalize_command(cmd);
        assert!(
            variants.iter().any(|v| v.contains("terraform")),
            "multi-variable concat should expand to 'terraform': {:?}",
            variants
        );
    }

    #[test]
    fn test_multi_variable_simple() {
        // t="terraform"; $t destroy
        let cmd = r#"t="terraform"; $t destroy"#;
        let variants = normalize_command(cmd);
        assert!(
            variants.iter().any(|v| v.contains("terraform destroy")),
            "single variable should expand: {:?}",
            variants
        );
    }

    #[test]
    fn test_jq_alternative_operator_not_a_path() {
        // jq's `a // b` operator must not be captured as the path `//`.
        let cmd = r#"jq '{m: (.permissions.defaultMode // null)}' settings.json"#;
        let paths = extract_paths_from_command(cmd);
        assert!(
            !paths.iter().any(|p| p == "//"),
            "jq // operator should not be extracted as a path: {:?}",
            paths
        );
    }

    #[test]
    fn test_bare_double_slash_not_a_path() {
        let paths = extract_paths_from_command(r#"echo "//" "#);
        assert!(
            !paths.contains(&"//".to_string()),
            "bare // should not be extracted as a path: {:?}",
            paths
        );
    }

    #[test]
    fn test_real_paths_still_extracted() {
        // The has_path_component filter must not drop genuine targets.
        assert!(extract_paths_from_command("cat /etc/passwd").contains(&"/etc/passwd".to_string()));
        assert!(extract_paths_from_command("vim ~/.ssh/id_ed25519")
            .contains(&"~/.ssh/id_ed25519".to_string()));
    }

    // ── issue #17: path-shaped text in data positions must not be extracted ──

    #[test]
    fn test_sed_program_not_a_path() {
        let paths = extract_paths_from_command(r#"sed -n '/<<<<<<< /,/>>>>>>> /p' src/main.rs"#);
        assert!(paths.is_empty(), "sed program text extracted: {:?}", paths);
    }

    #[test]
    fn test_file_url_with_variable_not_extracted() {
        for cmd in [
            "curl file://$PWD/fixtures/data.json",
            "curl -s file:///$PWD/_t-abc/x",
        ] {
            let paths = extract_paths_from_command(cmd);
            assert!(paths.is_empty(), "`{cmd}` extracted: {:?}", paths);
        }
    }

    #[test]
    fn test_https_url_not_extracted() {
        let paths = extract_paths_from_command("curl -s https://example.com/api/v1/status");
        assert!(paths.is_empty(), "{:?}", paths);
    }

    #[test]
    fn test_commit_message_mentioning_path_not_extracted() {
        let paths = extract_paths_from_command(
            r#"git commit -m "docs: update ~/.claude/docs/RAILGUARD.md notes""#,
        );
        assert!(paths.is_empty(), "{:?}", paths);
    }

    #[test]
    fn test_commit_message_slash_token_not_extracted() {
        let paths = extract_paths_from_command(r#"git commit -m "ran /verify and it passed""#);
        assert!(paths.is_empty(), "{:?}", paths);
    }

    #[test]
    fn test_message_flag_bare_path_not_extracted() {
        let paths = extract_paths_from_command(r#"git commit -m "~/.claude/docs/RAILGUARD.md""#);
        assert!(paths.is_empty(), "{:?}", paths);
        let paths = extract_paths_from_command(
            r#"gh pr create --title "/verify" --body "~/.claude/notes""#,
        );
        assert!(paths.is_empty(), "{:?}", paths);
    }

    #[test]
    fn test_prose_path_in_quotes_not_extracted() {
        let paths = extract_paths_from_command(r#"echo "the file /etc/passwd is famous""#);
        assert!(paths.is_empty(), "{:?}", paths);
    }

    #[test]
    fn test_data_heredoc_not_scanned() {
        let cmd = "cat <<EOF\nSee /verify and ~/.claude/docs for details\nEOF";
        let paths = extract_paths_from_command(cmd);
        assert!(paths.is_empty(), "{:?}", paths);
    }

    #[test]
    fn test_script_file_heredoc_data_not_scanned() {
        let cmd = "python3 app.py <<EOF\nRead /etc/passwd as an example\nEOF";
        let paths = extract_paths_from_command(cmd);
        assert!(paths.is_empty(), "{:?}", paths);
    }

    // ── issue #17: genuine operands and executable payloads must survive ──

    #[test]
    fn test_file_url_literal_path_extracted() {
        let paths = extract_paths_from_command("curl file:///etc/passwd");
        assert!(paths.contains(&"/etc/passwd".to_string()), "{:?}", paths);
    }

    #[test]
    fn test_quoted_single_word_path_extracted() {
        assert!(extract_paths_from_command(r#"cat "~/.ssh/id_rsa""#)
            .contains(&"~/.ssh/id_rsa".to_string()));
    }

    #[test]
    fn test_redirect_targets_extracted() {
        assert!(
            extract_paths_from_command("echo x > /etc/passwd").contains(&"/etc/passwd".to_string())
        );
        assert!(
            extract_paths_from_command("echo x >/etc/passwd").contains(&"/etc/passwd".to_string())
        );
    }

    #[test]
    fn test_flag_value_paths_extracted() {
        assert!(extract_paths_from_command("crontab --file=/etc/cron.d/x")
            .contains(&"/etc/cron.d/x".to_string()));
        assert!(extract_paths_from_command("gcc -I/usr/include/x main.c")
            .contains(&"/usr/include/x".to_string()));
    }

    #[test]
    fn test_interpreter_payload_scanned() {
        let paths = extract_paths_from_command(r#"bash -c "cat ~/.ssh/id_rsa""#);
        assert!(paths.contains(&"~/.ssh/id_rsa".to_string()), "{:?}", paths);
        let paths = extract_paths_from_command(r#"python3 -c "open('/home/u/.aws/credentials')""#);
        assert!(
            paths.contains(&"/home/u/.aws/credentials".to_string()),
            "{:?}",
            paths
        );
    }

    #[test]
    fn test_shell_heredoc_scanned() {
        let cmd = "sh <<EOF\ncat /etc/shadow\nEOF";
        let paths = extract_paths_from_command(cmd);
        assert!(paths.contains(&"/etc/shadow".to_string()), "{:?}", paths);
    }

    #[test]
    fn test_shell_herestring_scanned() {
        let paths = extract_paths_from_command(r#"bash <<< "cat /etc/shadow""#);
        assert!(paths.contains(&"/etc/shadow".to_string()), "{:?}", paths);
    }

    #[test]
    fn test_heredoc_redirect_target_still_extracted() {
        let cmd = "cat > ~/outside/x <<EOF\njust some text\nEOF";
        let paths = extract_paths_from_command(cmd);
        assert!(paths.contains(&"~/outside/x".to_string()), "{:?}", paths);
    }

    #[test]
    fn test_command_substitution_in_quotes_scanned() {
        let paths = extract_paths_from_command(r#"echo "key: $(cat ~/.ssh/id_rsa)""#);
        assert!(paths.contains(&"~/.ssh/id_rsa".to_string()), "{:?}", paths);
    }

    #[test]
    fn test_variable_indirection_extracted() {
        let paths = extract_paths_from_command(r#"d="$HOME/.ssh"; cat "$d/id_ed25519""#);
        assert!(
            paths.iter().any(|p| p.ends_with(".ssh/id_ed25519")),
            "{:?}",
            paths
        );
    }

    #[test]
    fn test_home_variable_expanded() {
        let paths = extract_paths_from_command("cat $HOME/.aws/credentials");
        assert!(
            paths.iter().any(|p| p.ends_with(".aws/credentials")),
            "{:?}",
            paths
        );
    }

    #[test]
    fn test_copy_outside_extracted() {
        assert!(
            extract_paths_from_command("cp secrets.txt ~/Dropbox/exfil.txt")
                .contains(&"~/Dropbox/exfil.txt".to_string())
        );
    }

    // ── wrapper / combined-flag / unknown-interpreter payloads must not escape ──

    #[test]
    fn test_wrapper_prefixed_interpreter_payload_scanned() {
        for cmd in [
            r#"env bash -c "cat ~/.ssh/id_rsa""#,
            r#"command bash -c "cat ~/.ssh/id_rsa""#,
            r#"timeout 5 bash -c "cat ~/.ssh/id_rsa""#,
            r#"nice -n 10 bash -c "cat ~/.ssh/id_rsa""#,
            r#"env FOO=bar bash -c "cat ~/.ssh/id_rsa""#,
            r#"sudo -u root bash -c "cat ~/.ssh/id_rsa""#,
            r#"env -S "bash -c \"cat ~/.ssh/id_rsa\"""#,
        ] {
            assert!(
                extract_paths_from_command(cmd).contains(&"~/.ssh/id_rsa".to_string()),
                "wrapper hid interpreter payload: `{cmd}`"
            );
        }
    }

    #[test]
    fn test_combined_short_flag_payload_scanned() {
        assert!(
            extract_paths_from_command(r#"bash -cx "cat ~/.ssh/id_rsa""#)
                .contains(&"~/.ssh/id_rsa".to_string())
        );
    }

    #[test]
    fn test_versioned_and_busybox_interpreters_scanned() {
        assert!(
            extract_paths_from_command(r#"python3.12 -c "open('/etc/shadow')""#)
                .contains(&"/etc/shadow".to_string())
        );
        let cmd = "busybox sh <<EOF\ncat /etc/shadow\nEOF";
        assert!(extract_paths_from_command(cmd).contains(&"/etc/shadow".to_string()));
    }

    #[test]
    fn test_deeply_nested_interpreter_payload_scanned() {
        let cmd = r#"bash -c "bash -c 'bash -c \"cat /etc/shadow\"'""#;
        assert!(
            extract_paths_from_command(cmd).contains(&"/etc/shadow".to_string()),
            "nested payload lost"
        );
    }

    #[test]
    fn test_glob_and_metachar_operands_extract_prefix() {
        // A word starting with a path but ending in a metachar must still yield
        // the leading path — the fence checks the directory it points into.
        assert!(extract_paths_from_command("rm -rf ~/.ssh/*").contains(&"~/.ssh/".to_string()));
        assert!(extract_paths_from_command("cat /etc/*").contains(&"/etc/".to_string()));
        assert!(extract_paths_from_command("cat ~/.ssh/id_*").contains(&"~/.ssh/id_".to_string()));
        assert!(
            extract_paths_from_command("docker run -v /etc/secret:/data img")
                .contains(&"/etc/secret".to_string())
        );
    }

    #[test]
    fn test_prefix_extraction_does_not_reach_across_words() {
        // Leading-prefix extraction must not resurrect the mid-prose FP.
        assert!(extract_paths_from_command(r#"echo "the file /etc/passwd is famous""#).is_empty());
    }

    #[test]
    fn test_interpreter_payload_glued_path_scanned() {
        // A path glued to code punctuation isn't a standalone shell word, so the
        // recursed-payload substring scan must catch it.
        assert!(
            extract_paths_from_command(r#"perl -e 'open(F,"/etc/shadow")'"#)
                .contains(&"/etc/shadow".to_string())
        );
        assert!(extract_paths_from_command(
            r#"python3 -c "subprocess.run(['cat','/etc/shadow'])""#
        )
        .contains(&"/etc/shadow".to_string()));
    }

    #[test]
    fn test_uppercase_and_autoloop_code_flags_scanned() {
        assert!(
            extract_paths_from_command(r#"perl -E 'open("/etc/passwd")'"#)
                .contains(&"/etc/passwd".to_string())
        );
        assert!(
            extract_paths_from_command(r#"perl -ne 'print if -e "/etc/hosts"'"#)
                .contains(&"/etc/hosts".to_string())
        );
    }

    #[test]
    fn test_trailing_comment_path_not_extracted() {
        assert!(extract_paths_from_command("make build # writes to /etc/hosts").is_empty());
        // A mid-word '#' is literal, not a comment.
        assert!(extract_paths_from_command("cat /etc/pass#wd").contains(&"/etc/pass".to_string()));
    }
}
