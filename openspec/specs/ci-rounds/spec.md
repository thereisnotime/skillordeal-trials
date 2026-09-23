# ci-rounds Specification

## Purpose
TBD - created by archiving change bootstrap-trials. Update Purpose after archive.
## Requirements
### Requirement: CI validates trials and scans for secrets
CI SHALL validate every `trials/*/trial.yaml` with the pinned engine, run actionlint, and run gitleaks over the full history, with third-party actions pinned to commit SHAs.

#### Scenario: Broken trial
- **WHEN** a pull request adds a trial that references an unknown contender
- **THEN** the validate job fails

### Requirement: Rounds run from a dispatch workflow
`round.yml` SHALL take a trial id, round, shard count, per-shard cost ceiling and auth mode, and call the engine's reusable round workflow with only the secret that matches the auth mode.

#### Scenario: Auth mismatch
- **WHEN** the dispatch `auth_mode` differs from `runtime.auth.mode` in the trial
- **THEN** the check job fails before any shard starts

#### Scenario: Unlocked round
- **WHEN** `trials/<id>/rounds/<round>/lock.yaml` is not committed
- **THEN** the check job fails and says to lock the round first

### Requirement: Secrets never enter the repo
The repo SHALL ignore `.env*` except `.env.example`, key and credential files, `work/` and caches, and `just secrets-scan` SHALL run gitleaks over history and staged changes.

#### Scenario: Staged token
- **WHEN** a token is staged for commit
- **THEN** `just secrets-scan` exits non-zero

