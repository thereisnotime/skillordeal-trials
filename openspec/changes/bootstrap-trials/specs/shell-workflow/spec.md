## ADDED Requirements

### Requirement: Every step runs from the justfile
The repo SHALL provide `just` recipes for setup, listing trials, validate, lock, plan, run, status, score, judge, review, report, show, transcript, new-trial, secrets-scan and verify, each a thin wrapper over one engine or tool command.

#### Scenario: Menu
- **WHEN** a user runs `just` with no arguments
- **THEN** a colored menu grouped by category lists the recipes and their arguments

### Requirement: Trial and bout arguments resolve
Recipes SHALL accept `trial=<id>` and resolve it to `trials/<id>/trial.yaml`, and SHALL accept `bout=<id>` and resolve it to the single matching bout directory.

#### Scenario: Unknown trial
- **WHEN** `just validate trial=nope` runs and `trials/nope/trial.yaml` does not exist
- **THEN** the recipe exits non-zero with a message naming the path it looked for, without calling the engine

#### Scenario: Pass-through flags
- **WHEN** `just run trial=<id> round=r01 j=2 --max-cost-usd 5` runs
- **THEN** the engine receives `run trials/<id>/trial.yaml -r r01 -j 2 --max-cost-usd 5`

### Requirement: Engine source is overridable
`just setup` SHALL install the engine from the local checkout by default and from any git URL given as `engine=`.

#### Scenario: Pinned release
- **WHEN** `just setup engine=git+https://github.com/thereisnotime/skillordeal@v0.1.0` runs
- **THEN** that tagged engine is installed as a uv tool with the analysis extras
