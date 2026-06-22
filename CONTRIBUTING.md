# Contributing to Railguard

Thanks for your interest in contributing! Railguard is early-stage and we welcome all contributions.

## Getting started

```bash
git clone https://github.com/railyard-dev/railguard.git
cd railguard
cargo test
```

## How to contribute

1. **Fork the repo** and create a branch from `main`
2. **Make your changes** — add tests for new functionality
3. **Run the test suite** — `cargo test` must pass
4. **Submit a pull request** — describe what you changed and why

## What to work on

Check [open issues](https://github.com/railyard-dev/railguard/issues) or pick from these areas:

- **New blocklist rules** — add rules for common destructive commands we're missing
- **Evasion detection** — new encoding schemes, shell tricks, interpreter bypasses
- **Platform support** — test and fix issues on Windows and Linux
- **Agent support** — extend beyond Claude Code to Cursor, Windsurf, Codex, etc.
- **Documentation** — improve docs, add examples, fix typos

## Code style

- Run `cargo fmt` before committing
- Run `cargo clippy` and fix warnings
- Keep functions small and focused
- Add tests for new rules and detection logic

## Tests

The test suite has four categories:

- **Unit tests** (`cargo test --lib`) — individual function tests
- **Attack simulations** (`cargo test --test attack_simulation`) — real incident reproductions and evasion attempts
- **Rollback scenarios** (`cargo test --test rollback_scenarios`) — snapshot and recovery tests
- **Threat detection** (`cargo test --test threat_detection`) — escalation and session termination tests

All tests must pass before merging.

## Community

Join the [Discord](https://discord.gg/MyaUZSus) to discuss ideas, ask questions, or coordinate on larger features.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
