# __TRIAL_ID__

## Question

TODO

## Hypothesis

TODO what you expect and why, written before round r01 runs.

## TL;DR result

Not run yet.

## Setup

| | |
|---|---|
| Models | TODO |
| Judge | TODO |
| Claude Code CLI | 2.1.280 |
| Engine | skillordeal v0.1.1 |
| Runner image | `ghcr.io/thereisnotime/skillordeal-runner:v0.1.1` (digest in `rounds/<round>/lock.yaml`) |
| Reps | 3 per contender × arena × task × model |

## Contenders

| id | source | license | role | why included |
|---|---|---|---|---|
| baseline | plain Claude Code, no skill | | finder | reference point |

## Arenas

| id | repo @ ref | language | ground truth |
|---|---|---|---|

## Leaderboard

Generated into [`rounds/r01/RESULTS.md`](rounds/r01/RESULTS.md) by `just report trial=__TRIAL_ID__ round=r01`.

## How to reproduce

```bash
just setup engine=git+https://github.com/thereisnotime/skillordeal@v0.1.1
just lock trial=__TRIAL_ID__ round=r01-repro
just run  trial=__TRIAL_ID__ round=r01-repro --max-cost-usd 5
```

## How to dig in

```bash
just status trial=__TRIAL_ID__ round=r01
just show bout=<bout-id>
just transcript bout=<bout-id> | jq -c 'select(.type=="assistant")' | head
```
