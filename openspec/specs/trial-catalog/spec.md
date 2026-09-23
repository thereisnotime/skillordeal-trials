# trial-catalog Specification

## Purpose
TBD - created by archiving change bootstrap-trials. Update Purpose after archive.
## Requirements
### Requirement: Trial layout
Each trial SHALL live in `trials/<id>/` with `trial.yaml`, `README.md`, `tasks/`, `labels/` and `rounds/`, and the trial id SHALL equal the directory name.

#### Scenario: Scaffold a trial
- **WHEN** a user runs `just new-trial name=2026-10-example`
- **THEN** `trials/2026-10-example/` is created from `templates/trial/` with the id filled in, and the command refuses if the directory exists or the name is not a lowercase slug

### Requirement: Trial README sections
A trial README SHALL contain, in order: Question, Hypothesis, TL;DR result, Setup, Contenders, Arenas, Leaderboard, How to reproduce, How to dig in.

#### Scenario: Unrun trial
- **WHEN** a trial has no scored round
- **THEN** the TL;DR and Leaderboard sections say it has not run yet and point at where `just report` will write `rounds/<round>/RESULTS.md`

### Requirement: Pinned contenders
Every contender with a remote source SHALL set `ref` to a full 40-character commit sha, and its subpath SHALL resolve at that sha.

#### Scenario: Dry-run lock
- **WHEN** `skillordeal lock <trial.yaml> -r dryrun --skip-image` runs
- **THEN** every contender materializes and the lock records its sha and tree hash

### Requirement: Excluded candidates are documented
Survey candidates that are not used SHALL be listed in the contenders file with the reason they were excluded.

#### Scenario: Tool-driven skill
- **WHEN** a candidate needs a binary or network access the sandbox lacks
- **THEN** it appears only in the commented "not included" section with that reason

