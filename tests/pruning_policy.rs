use railguard::policy::{engine::evaluate, loader::default_policy};
use railguard::types::Decision;

fn decision(command: &str) -> Decision {
    evaluate(
        &default_policy(),
        "Bash",
        &serde_json::json!({ "command": command }),
    )
}

#[test]
fn catastrophic_filesystem_roots_remain_blocked() {
    for command in [
        "rm -rf /",
        "rm -rf /*",
        "rm -rf /home",
        "rm -rf /home/example",
        "rm -Rf /home/example",
        "rm -r -f /home/example",
        "rm --recursive --force /home/example",
        "rm -rf /home/example /tmp/also-remove",
        "rm -rf ~",
        "rm -rf $HOME",
    ] {
        assert!(
            matches!(decision(command), Decision::Block { .. }),
            "`{command}` should remain blocked"
        );
    }
}

#[test]
fn broad_local_pruning_requires_approval() {
    for command in [
        "rm -rf /home/example/repo",
        "git clean -fdX",
        "git clean -d -f",
        "git worktree remove --force /tmp/old-worktree",
        "docker system prune -a",
        "docker volume prune",
        "docker builder prune --all",
        "docker buildx prune --all",
    ] {
        assert!(
            matches!(decision(command), Decision::Approve { .. }),
            "`{command}` should require approval, got {:?}",
            decision(command)
        );
    }
}

#[test]
fn low_risk_local_cleanup_stays_allowed() {
    for command in [
        "rm -rf target",
        "git clean -ndX",
        "git worktree prune",
        "git worktree remove /tmp/old-worktree",
    ] {
        assert!(
            matches!(decision(command), Decision::Allow),
            "`{command}` should stay allowed, got {:?}",
            decision(command)
        );
    }
}

#[test]
fn remote_and_data_destructive_operations_remain_blocked() {
    for command in [
        "terraform destroy",
        "aws s3 rm s3://bucket --recursive",
        "psql -c 'DROP DATABASE app'",
        "git push origin main --force",
    ] {
        assert!(
            matches!(decision(command), Decision::Block { .. }),
            "`{command}` should remain blocked"
        );
    }
}
