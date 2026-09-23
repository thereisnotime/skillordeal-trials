# __TRIAL_ID__

**Design:** TODO contenders × TODO arenas × TODO tasks × TODO models × 3 reps = TODO bouts. Model under test TODO, judge TODO.

**Status:** designed, not locked yet.

## Question

TODO

## Hypothesis

TODO what you expect and why, written before r01 starts.

## TL;DR result

Not run yet.

## Setup

| | |
|---|---|
| Model under test | TODO full model ID, effort, `max_budget_usd` per bout |
| Judge | TODO |
| Claude Code CLI | 2.1.280 (inside the image) |
| Engine | skillordeal v0.1.1 |
| Runner image | `ghcr.io/thereisnotime/skillordeal-runner:v0.1.1`, digest pinned in `rounds/<round>/lock.yaml` |
| Auth | TODO `runtime.auth.mode` |
| Invocation | TODO `forced` or `auto` |
| Reps | 3 per contender × arena × task × model |
| Per-bout limits | TODO timeout, tokens, turns, CPUs, memory |
| Task | TODO link to `tasks/<task>.md` |
| Network | egress only to `api.anthropic.com:443` through a per-bout proxy |

## Contenders

| id | source (pinned sha) | license | role | why included |
|---|---|---|---|---|
| baseline | plain Claude Code, no skill | | finder | the reference every number is compared to |

## Arenas

| id | repo @ ref | language | ground truth |
|---|---|---|---|

## Leaderboard

Not run yet. `just report trial=__TRIAL_ID__ round=r01` writes `rounds/r01/RESULTS.md` and `rounds/r01/report.html`; link them here once they exist.

## How to reproduce

```bash
just setup engine=git+https://github.com/thereisnotime/skillordeal@v0.1.1
just lock  trial=__TRIAL_ID__ round=r01-repro-$USER
just run   trial=__TRIAL_ID__ round=r01-repro-$USER --max-cost-usd 5
```

Then score and compare with r01:

```bash
just score  trial=__TRIAL_ID__ round=r01-repro-$USER
just judge  trial=__TRIAL_ID__ round=r01-repro-$USER
just report trial=__TRIAL_ID__ round=r01-repro-$USER
```

Diff your `lock.yaml` against `rounds/r01/lock.yaml` to see what changed.

## How to dig in

```bash
just status trial=__TRIAL_ID__ round=r01
just show bout=<bout-id>
just transcript bout=<bout-id> | jq -c 'select(.type=="assistant")' | less
jq '.findings[] | {title, file, line_start, cwe}' rounds/r01/bouts/<bout-id>/findings.json
```

Per-finding verdicts are in `rounds/r01/scores/verdicts.jsonl` (ground truth, judge and human side by side). Human labels win, then ground truth, then the judge.
