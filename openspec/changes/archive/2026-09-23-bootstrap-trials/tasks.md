# Tasks

## 1. Repo scaffolding

- [x] 1.1 `.tool-versions` (uv, nodejs, gitleaks, actionlint), `.gitignore`, `.env.example`, `.gitattributes` (lfs for `*.jsonl.zst`, `*.parquet`)
- [x] 1.2 Colored `justfile` with key=value argument parsing and trial/bout resolution
- [x] 1.3 `templates/trial/` scaffold and `just new-trial`

## 2. Arenas

- [x] 2.1 `arenas/dvpwa/arena.yaml` pinned to a1d8f89
- [x] 2.2 `arenas/dvpwa/groundtruth.yaml` from a manual pass over the source, every location verified
- [x] 2.3 `arenas/warpgate-operator/arena.yaml` pinned to the latest release tag, strip and scope set, no ground truth

## 3. Contenders

- [x] 3.1 Convert the verified survey to the engine Contender schema
- [x] 3.2 Check every subpath at its sha with `gh api`; fix the moved Every persona path
- [x] 3.3 Document excluded candidates and reasons

## 4. First trial

- [x] 4.1 `trials/2026-09-secure-coding-audit/trial.yaml`
- [x] 4.2 `tasks/security-audit.md`
- [x] 4.3 Trial README with the fixed section order
- [x] 4.4 `skillordeal validate` passes
- [x] 4.5 `skillordeal lock -r dryrun --skip-image` materializes every contender; dry-run round deleted

## 5. CI

- [x] 5.1 `ci.yml`: validate trials, actionlint, gitleaks
- [x] 5.2 `round.yml`: dispatch inputs, auth check, reusable round call with explicit secrets
- [x] 5.3 `actionlint` clean locally

## 6. Docs and checks

- [x] 6.1 Top-level README (glossary, trial index, reproduce, trace a number, labeling, layout, auth, contributing)
- [x] 6.2 `gitleaks git --staged` clean before the first commit
