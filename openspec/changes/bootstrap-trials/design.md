# Design

## Trials repo, not engine repo

Engine code and study data change at different speeds. A trial pins an engine release in its lock, so results stay reproducible after the engine moves on. The trials repo installs the engine as a uv tool (`uv tool install "skillordeal[analysis] @ <git url>"`), local checkout by default, release tag for real rounds.

## Layout

- `arenas/<id>/` is shared across trials so ground truth accumulates in one place.
- `contenders/<survey>.yaml` is one file per survey; a trial picks ids out of it. Excluded candidates stay in the file as comments with the reason, so the survey is auditable.
- `trials/<id>/rounds/<round>/` holds everything a round produces. Rounds are append-only: reproductions add rounds instead of editing old ones.

## justfile arguments

`just` only accepts `NAME=VALUE` overrides before the recipe name. Recipes here take `*args` with positional arguments enabled and parse `trial=`, `round=`, `j=`, `bout=`, `name=`, `engine=`, `runner=` themselves; anything else passes through to the engine (e.g. `--max-cost-usd 5`). `trial=` accepts an id or a path; `bout=` accepts a directory or a bare bout id, found under `trials/*/rounds/*/bouts/`.

## Contenders

- Every `ref` is a full sha and every `subpath` was checked with `gh api .../contents/<subpath>?ref=<sha>`, then proven by a `lock --skip-image` dry run that materializes all of them.
- No contender gets `extra_tools`. Prompts that ask for Task, Write or git diff run without them, same as the baseline, which keeps the comparison fair.
- Single-file agent/command prompts use `kind: prompt`; the engine wraps them as a skill named after the contender id (avoids clashing with the CLI's built-in `/security-review`).
- The Every persona moved upstream; the survey path no longer exists at the pinned sha, so the subpath points at its current location.

## Ground truth

- Built by reading dvpwa at a1d8f89 by hand. README-documented vulns are `source: documented`, the rest `manual`.
- Issues are split by root cause and exploit path (e.g. three XSS issues by sink family, three missing-authz issues by endpoint) rather than one per vuln class, so recall reflects distinct fixes.
- `complete: false`: unmatched findings are `unknown`, not `fp`. Several issues share nearby lines (app.py, the login handler, fixtures), which the ±5 window can confuse; human labels override.

## Workflows

- `round.yml` takes a trial id, derives the path, checks the round is locked and that `auth_mode` matches the trial, then passes only the matching secret to the reusable workflow.
- Action SHAs are copied from the engine's workflows so both repos move together.

## Trade-offs

- Including diff-scoped and Go-only contenders in r01 costs money on bouts that are expected to do poorly, but the point is to measure that, and they double as controls.
- The judge and review recipes are wired before the engine commands exist. The alternative (adding them later) would mean a README that describes commands the repo can't run.
