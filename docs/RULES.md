# Default Rules & Configuration

Railguard blocks catastrophic, remote, and data-destructive operations. Local pruning that is useful but difficult to undo requires your approval. Evasion attempts are hard-blocked. Everything else flows through instantly.

## Default rules

### Local pruning (approve - you decide)

| Rule | What it catches | Why |
|------|----------------|-----|
| `rm-rf-home-descendant` | `rm -rf /home/user/repo`, `rm -rf ~/build` | Broad local deletion |
| `git-clean-force` | `git clean -f` | Removes untracked files |
| `git-worktree-remove-force` | `git worktree remove --force` | Discards a dirty worktree |
| `docker-system-prune` | `docker system prune -a` | Removes all images |
| `docker-volume-prune` | `docker volume prune` | Removes local volumes and data |
| `docker-builder-prune-all` | `docker builder/buildx prune --all` | Removes the broad build cache |
| `npm-publish` | `npm publish` | Accidental publishes |

`git clean` dry runs, `git worktree prune`, non-force worktree removal, and ordinary relative cleanup such as `rm -rf target` remain allowed.

### Hard blocks

| Rule | What it catches |
|------|----------------|
| `terraform-destroy` | `terraform destroy`, `apply -auto-approve` |
| `rm-rf-critical` | Exact filesystem roots: `/`, `/home`, `~`, `$HOME`, `/home/user` |
| `sql-drop` | `DROP TABLE`, `DATABASE`, `SCHEMA`, `TRUNCATE TABLE` |
| `git-force-push` | `git push --force` |
| `git-reset-hard` | `git reset --hard` |
| `drizzle-force` | `drizzle-kit push --force` |
| `k8s-delete-namespace` | `kubectl delete namespace` |
| `aws-s3-rm-recursive` | `aws s3 rm --recursive` |
| `chmod-777-recursive` | `chmod -R 777 /` |
| `disk-format` | `mkfs`, `dd of=/dev/` |
| `network-curl-pipe-sh` | `curl \| sh` / `curl \| bash` |
| `network-nc` | `nc` / `netcat` / `ncat` |
| `base64-to-shell` | `base64 -d \| sh` |
| `printf-hex-exec` | `$(printf '\x...')` in command position |
| `transform-pipe-to-shell` | `rev \| sh`, `tr \| sh`, `sed \| sh` |
| `interpreter-obfuscation` | Python/Ruby with chr(), b64decode, system() |
| `git-config-global-write` | `git config --global` writes |

### Self-protection (hard block)

| Rule | What it catches |
|------|----------------|
| `railguard-uninstall` | `railguard uninstall` |
| `railguard-tamper-settings` | Edits to `.claude/settings.json` (provably read-only commands, e.g. a plain `grep`/`cat`, are exempt) |
| `railguard-remove-binary` | `rm` targeting railguard binary |
| `railguard-config-edit` | Edits to `railguard.yaml` (approve) |

### Network & credentials (approve)

| Rule | What it catches |
|------|----------------|
| `network-curl-post` | `curl -X POST` / `curl --data` |
| `network-wget` | `wget` |
| `network-ssh-scp` | `ssh` / `scp` / `rsync` |
| `env-dump` | `env` / `printenv` |
| `eval-dynamic` | `eval` with variable expansion |
| `symlink-to-outside` | Symlinks to absolute paths |

## Evasion detection

Agents have been [documented trying to bypass safety rules](https://github.com/anthropics/claude-code/issues/29691). Railguard normalizes commands before matching:

```
Direct:     terraform destroy                           → ⛔ blocked
Base64:     echo dGVycmFmb3Jt... | base64 -d | sh      → ⛔ blocked
Double b64: echo ZEdW... | base64 -d | base64 -d | sh  → ⛔ blocked + SESSION KILLED
Variable:   CMD="terraform destroy"; $CMD               → expanded   → ⛔ blocked
Shell wrap: sh -c "terraform destroy"                   → unwrapped  → ⛔ blocked
Eval:       eval "ter""raform destroy"                  → joined     → ⛔ blocked
Hex:        $'\x74\x65\x72\x72...'                      → decoded    → ⛔ blocked
Rev pipe:   rev <<< 'yortsed mrofarret' | sh            → shape      → ⛔ SESSION KILLED
ROT13:      tr 'a-z' 'n-za-m' <<< '...' | sh           → shape      → ⛔ SESSION KILLED
Python:     python3 -c "...b64decode..." / "...chr(..." → detected   → ⛔ SESSION KILLED
```

## Threat escalation

| Tier | Trigger | Action |
|------|---------|--------|
| **1** | `rev\|sh`, `base64\|base64`, `python -c chr()`, `printf \x` | Immediate session kill |
| **2** | Variable-then-exec, `eval $var`, multi-variable concat | Warning, then kill on repeat |
| **3** | Retried blocked command with different syntax | Behavioral detection, then kill |

## Path fencing

When enabled (default), restricts file access:

```
Your project directory     ✅ read/write
~/.ssh/                    ⛔ denied
~/.aws/                    ⛔ denied
~/.gnupg/                  ⛔ denied
~/.config/gcloud/          ⛔ denied
/etc/                      ⛔ denied
```

## Customizing

Edit `railguard.yaml` or run `railguard configure`:

```yaml
# Block a command entirely
blocklist:
  - name: no-deploy
    tool: Bash
    pattern: "deploy-to-prod"
    action: block

# Require approval
approve:
  - name: terraform-apply
    tool: Bash
    pattern: "terraform\\s+apply"
    action: approve

# Skip a default rule
allowlist:
  - name: allow-git-force
    tool: Bash
    pattern: "git push --force"
    action: allow
```

Changes take effect immediately. No restart needed.
