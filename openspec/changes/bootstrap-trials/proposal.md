# Bootstrap the trials repo

## Why

The skillordeal engine runs bouts, but the studies themselves (questions, pinned inputs, ground truth, human labels and results) need a home that newcomers can navigate and that anyone can reproduce from a shell. Keeping them out of the engine repo lets trials pin a released engine version and lets results accumulate without touching engine code.

## What Changes

- New repo layout: `arenas/`, `contenders/`, `trials/<id>/` (trial.yaml, tasks, labels, rounds), `templates/trial/`.
- First trial `2026-09-secure-coding-audit`: 11 secure-code-review contenders plus baseline, on `dvpwa` and `warpgate-operator`, Opus 5.5 at high effort, 3 reps.
- `arenas/dvpwa/groundtruth.yaml`: 19 issues verified against the source at a1d8f89, `complete: false`.
- A colored `justfile` that wraps every engine command with `trial=` / `round=` / `bout=` arguments.
- CI (`ci.yml`) that validates trials and runs actionlint and gitleaks, and a `round.yml` dispatch workflow that calls the engine's reusable round workflow.
- README written as the entry point: glossary, trial index, reproduce, trace a number, labeling, auth.

## Impact

- No engine changes. Depends on engine commands `score`, `judge`, `review`, `report` that are being added in parallel; the recipes are wired but fail until the engine ships them.
- `round.yml` and `ci.yml` pin the engine at `v0.1.0`, which has to be tagged and its runner image published before they work.
