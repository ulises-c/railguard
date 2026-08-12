# TRAIL

## Done - Tiered destructive policy + memory snapshot-then-ask (2026-08-12)

**What:** Recalibrated defaults into three tiers (catastrophic/remote -> block, broad local pruning -> ask, routine cleanup -> allow); memory deletes now snapshot affected files then ask, container roots (~/.claude, ~/.claude/projects) stay blocked; hard policy blocks now evaluated before the path fence; read-only detection rejects write-mode flags (sed -i, find -delete, etc.).

**State:** Committed as 3949c99 on `feat/tiered-destructive-policy` (off ulises/main), pushed to fork, PR open: https://github.com/ulises-c/railguard/pull/48. 306 tests, fmt, clippy all clean. Previous branch `fix/cap-session-start-memory-warning` merged upstream as PR #45 - safe to delete locally.

**Next:** Wait for maintainer review on PR #48; address feedback on this branch.
