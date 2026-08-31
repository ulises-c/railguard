# Railguard - Active Guardrails

Railguard monitors every tool call in this session: allow, ask, or block. If a command is blocked, do NOT re-issue it with cosmetic changes (new flags, encoding, wrappers) - take a genuinely different approach. On ask, wait for the human. File writes and approved memory deletions are snapshotted and can be rolled back.

Full agent guide (rollback commands, policy customization, path-fence quirks, self-protection): run `railguard guide`.
