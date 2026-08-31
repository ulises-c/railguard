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
pub fn is_interpreter_obfuscation(cmd: &str) -> bool {
    // Check if command invokes an interpreter with inline code
    let interpreter_re = regex::Regex::new(r"(?:python3?|ruby|perl|node)\s+(?:-[ec]\s+|-e\s+)");
    let has_interpreter = match &interpreter_re {
        Ok(re) => re.is_match(cmd),
        Err(_) => false,
    };

    if !has_interpreter {
        return false;
    }

    // Check for obfuscation patterns in the inline code
    let obfuscation_patterns = [
        // Encoding / decoding
        r"b64decode",
        r"b64encode",
        r"base64\..*decode",
        // Character construction
        r"chr\s*\(",
        r"\\x[0-9a-fA-F]{2}",
        r"fromCharCode",
        r"String\.fromCharCode",
        // Code execution
        r"eval\s*\(",
        r"exec\s*\(",
        r"system\s*\(",
        r"os\.system\s*\(",
        r"os\.popen\s*\(",
        r"subprocess",
        r"Popen\s*\(",
        // P0 R3: Path construction via join — '/'.join or "/".join
        r#"['"]/'*\s*\.\s*join\s*\("#,
        // P0 R3: open() with constructed path (join/chr)
        r"open\s*\(.*\.join\s*\(",
        r"open\s*\(.*chr\s*\(",
    ];

    for pattern in &obfuscation_patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if re.is_match(cmd) {
                return true;
            }
        }
    }

    false
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

    let mut segment: Vec<&ShellToken> = Vec::new();
    for tok in &parsed.tokens {
        if let ShellToken::Op(op) = tok {
            if matches!(*op, "&&" | "||" | ";" | "|" | "&" | "(" | ")" | "`") {
                collect_paths_from_segment(&segment, depth, paths);
                segment.clear();
                continue;
            }
        }
        segment.push(tok);
    }
    collect_paths_from_segment(&segment, depth, paths);

    for sub in &parsed.substitutions {
        extract_paths_inner(sub, depth + 1, paths);
    }
    for heredoc in &parsed.heredocs {
        if is_shell_or_interpreter(&heredoc.consumer) {
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
    let eff_idx = effective_command_index(&words);
    let eff = words
        .get(eff_idx)
        .map(|w| command_basename(w))
        .unwrap_or("");
    let is_vcs = matches!(eff, "git" | "gh");
    let is_interp = is_shell_or_interpreter(eff);
    let program_idx = program_operand_index(&words, eff_idx, eff);

    let mut pending = NextWord::Operand;
    let mut word_no = 0usize;
    for tok in tokens {
        match tok {
            // Here-string payloads execute only when fed to a shell/interpreter.
            ShellToken::Op("<<<") if is_interp => pending = NextWord::Recurse,
            ShellToken::Op(_) => {}
            ShellToken::Word(w) => {
                match std::mem::replace(&mut pending, NextWord::Operand) {
                    NextWord::Recurse => extract_paths_inner(w, depth + 1, paths),
                    NextWord::Skip => {}
                    NextWord::Operand => {
                        if word_no <= eff_idx {
                            push_candidate(w, paths);
                        } else if Some(word_no) == program_idx {
                            // The tool's program/pattern: data it matches
                            // against, never a file it opens.
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

/// Tools whose first non-option operand is a program or pattern rather than a
/// path. `sed -n '/1000/p' f`, `awk '/total/{print}' f` and `grep -o '/1000' f`
/// all name a regex there, and once the shell strips the quotes a
/// slash-delimited regex is indistinguishable from a path (issue #32). Their
/// *later* operands are real files and stay extracted.
fn takes_program_operand(cmd: &str) -> bool {
    matches!(
        cmd,
        "sed"
            | "gsed"
            | "awk"
            | "gawk"
            | "mawk"
            | "nawk"
            | "grep"
            | "egrep"
            | "fgrep"
            | "rg"
            | "ag"
            | "ack"
    )
}

/// A flag that supplies the program itself (`grep -f patterns.txt data.txt`,
/// `sed -e 's/a/b/' f`), so no operand holds it and every operand is a path —
/// including the flag's own value, which is a real file.
fn supplies_program(word: &str) -> bool {
    matches!(
        word,
        "-e" | "-f" | "--expression" | "--file" | "--regexp" | "--source"
    ) || word.starts_with("--expression=")
        || word.starts_with("--regexp=")
        || word.starts_with("--file=")
        || word.starts_with("--source=")
        // attached short forms: -e's/a/b/', -fpatterns.txt
        || (word.len() > 2
            && !word.starts_with("--")
            && (word.starts_with("-e") || word.starts_with("-f")))
}

/// Flags of these tools that consume the following word, so a flag value is
/// never mistaken for the program operand. Deliberately short: an unlisted
/// value-taking flag costs at most a surviving false positive, while wrongly
/// listing one would skip a real path.
fn consumes_next_value(tool: &str, word: &str) -> bool {
    match tool {
        "awk" | "gawk" | "mawk" | "nawk" => matches!(word, "-F" | "-v"),
        _ => matches!(word, "-m" | "-A" | "-B" | "-C" | "-l"),
    }
}

/// Index in `words` of the program/pattern operand, if this segment has one.
fn program_operand_index(words: &[&str], eff_idx: usize, tool: &str) -> Option<usize> {
    if !takes_program_operand(tool) {
        return None;
    }
    let mut idx = eff_idx + 1;
    while idx < words.len() {
        let word = words[idx];
        if word == "--" {
            // Everything after `--` is an operand, so the program is next.
            return (idx + 1 < words.len()).then_some(idx + 1);
        }
        if word.len() > 1 && word.starts_with('-') {
            if supplies_program(word) {
                return None;
            }
            idx += if consumes_next_value(tool, word) {
                2
            } else {
                1
            };
            continue;
        }
        return Some(idx);
    }
    None
}

/// Index of the real command in a segment, skipping a leading run of env
/// assignments (`FOO=bar`), wrapper commands (`env`, `timeout`, `xargs`, ...),
/// and — once a wrapper has been seen — that wrapper's flag/numeric arguments.
fn effective_command_index(words: &[&str]) -> usize {
    let mut idx = 0;
    let mut saw_prefix = false;
    while idx < words.len() {
        let w = words[idx];
        if command_basename(w) == "rtk" {
            // RTK dispatches the remaining words as the real command. Its
            // explicit `proxy` subcommand is routing syntax, not the command.
            saw_prefix = true;
            idx += 1;
            if words.get(idx).is_some_and(|word| *word == "proxy") {
                idx += 1;
            }
        } else if is_env_assignment(w) || is_wrapper(command_basename(w)) {
            saw_prefix = true;
            idx += 1;
        } else if saw_prefix
            && !w.is_empty()
            && (w.starts_with('-') || w.chars().all(|c| c.is_ascii_digit()))
        {
            idx += 1;
        } else {
            break;
        }
    }
    idx.min(words.len().saturating_sub(1))
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
/// single-dash cluster containing a code letter — `c` (sh/python), `e`/`E`
/// (perl/ruby/node), `n`/`p` (perl/node autoloop) — so `-c`, `-E`, `-cx`, `-ne`
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
    Op(&'static str),
}

struct Heredoc {
    /// First word of the segment the heredoc feeds (its consuming command).
    consumer: String,
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
    /// Words of the current segment so far — used to resolve the effective
    /// command that consumes a heredoc (past any wrapper/env prefix).
    segment_words: Vec<String>,
    /// Some(strip_tabs) right after a <</<<- operator: the next word is a heredoc delimiter.
    expecting_delim: Option<bool>,
    /// Heredocs opened on the current line: (delimiter, strip_tabs, consumer).
    pending: Vec<(String, bool, String)>,
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
        if let Some(strip_tabs) = self.expecting_delim.take() {
            let consumer = self.effective_consumer();
            self.pending.push((w, strip_tabs, consumer));
        } else {
            self.segment_words.push(w.clone());
            self.tokens.push(ShellToken::Word(w));
        }
    }

    fn effective_consumer(&self) -> String {
        let refs: Vec<&str> = self.segment_words.iter().map(String::as_str).collect();
        let idx = effective_command_index(&refs);
        refs.get(idx)
            .map(|w| command_basename(w).to_string())
            .unwrap_or_default()
    }

    fn push_op(&mut self, op: &'static str, resets_segment: bool) {
        self.flush();
        if resets_segment {
            self.segment_words.clear();
        }
        self.tokens.push(ShellToken::Op(op));
    }

    /// Heredoc bodies start after the line that opened them. Returns the index
    /// past the consumed bodies.
    fn consume_heredoc_bodies(&mut self, chars: &[char], mut i: usize) -> usize {
        while let Some((delim, strip_tabs, consumer)) = self.pending.first().cloned() {
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
            self.heredocs.push(Heredoc { consumer, body });
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
                i += 1;
                while i < len && chars[i] != '\'' {
                    lex.word.push(chars[i]);
                    i += 1;
                }
                i += 1;
            }
            '"' => {
                lex.has_word = true;
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
                    lex.push_op("<<<", false);
                    i += 3;
                } else if i + 1 < len && chars[i + 1] == '<' {
                    let strip_tabs = i + 2 < len && chars[i + 2] == '-';
                    lex.push_op("<<", false);
                    lex.expecting_delim = Some(strip_tabs);
                    i += if strip_tabs { 3 } else { 2 };
                } else {
                    lex.push_op("<", false);
                    i += 1;
                }
            }
            '>' => {
                if i + 1 < len && chars[i + 1] == '>' {
                    lex.push_op(">>", false);
                    i += 2;
                } else {
                    lex.push_op(">", false);
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
                if i + 1 < len && chars[i + 1] == '&' {
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

    TokenizedCommand {
        tokens: lex.tokens,
        heredocs: lex.heredocs,
        substitutions: lex.substitutions,
    }
}

/// Read a `$(...)` body starting just past the opening paren.
/// Returns the body and the index past the closing paren.
fn read_substitution(chars: &[char], start: usize) -> (String, usize) {
    let mut depth = 1usize;
    let mut j = start;
    while j < chars.len() {
        match chars[j] {
            '(' => depth += 1,
            ')' => {
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
    fn test_regex_operand_is_not_a_path() {
        // Issue #32: a slash-delimited regex is the tool's program, not a file.
        for cmd in [
            r#"cargo test 2>&1 | awk '/test result/ {print $4}'"#,
            r#"cargo test | sed -n '/1000/p'"#,
            r#"cargo test | sed -n '/1000/,$p'"#,
            r#"cargo test | grep -o '/1000'"#,
            r#"cargo build | rg '/etc/passwd'"#,
            r#"cargo test | grep -- '/1000/'"#,
            r#"rtk sed -n '/Operating/,/Wholesale/p' local.txt"#,
            r#"rtk proxy sed -n '/Flagged/,/^$/p' local.txt"#,
        ] {
            assert!(
                extract_paths_from_command(cmd).is_empty(),
                "{cmd} -> {:?}",
                extract_paths_from_command(cmd)
            );
        }
    }

    #[test]
    fn test_path_operands_of_regex_tools_still_extracted() {
        // The skip covers only the program slot; real files must stay fenced.
        for (cmd, expected) in [
            (r#"awk '{print}' /etc/passwd"#, "/etc/passwd"),
            (r#"sed -n '/x/p' /etc/shadow"#, "/etc/shadow"),
            (r#"sed -i 's/a/b/' /etc/hosts"#, "/etc/hosts"),
            (r#"grep -A 3 pattern /etc/shadow"#, "/etc/shadow"),
            (r#"awk -F, '{print $1}' /etc/passwd"#, "/etc/passwd"),
            // -f supplies the program, so its value is a real file and the
            // operand after it is a data file — neither may be skipped.
            (r#"grep -f /etc/patterns /var/log/syslog"#, "/etc/patterns"),
            (
                r#"grep -f /etc/patterns /var/log/syslog"#,
                "/var/log/syslog",
            ),
            (r#"grep -- pattern /etc/shadow"#, "/etc/shadow"),
            (r#"cat /etc/shadow | grep '/1000/'"#, "/etc/shadow"),
            (r#"rtk sed -n '/x/p' /etc/shadow"#, "/etc/shadow"),
            (r#"rtk proxy grep pattern /etc/shadow"#, "/etc/shadow"),
        ] {
            let paths = extract_paths_from_command(cmd);
            assert!(
                paths.contains(&expected.to_string()),
                "{cmd} -> {paths:?} (missing {expected})"
            );
        }
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
