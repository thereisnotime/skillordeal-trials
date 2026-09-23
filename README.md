# skillordeal-trials

**Start here.** This repo holds the studies run with [skillordeal](https://github.com/thereisnotime/skillordeal), a harness that benchmarks LLM agent skills (`SKILL.md` packs, Claude Code plugins, plain prompts) against a no-skill baseline. Each trial asks one question, pins every input (skill commits, target repos, model ids, CLI version, container image), runs the agent in an isolated rootless podman container with nothing else in context, and keeps the raw output of every run. Ground truth, human labels, scores and reports live next to that raw data, so every number in a results table can be traced back to the transcript it came from and re-run from a shell.

- [Words used everywhere](#words-used-everywhere)
- [Trials](#trials)
- [Reproduce a round in 3 commands](#reproduce-a-round-in-3-commands)
- [Trace a number](#trace-a-number)
- [How to label findings](#how-to-label-findings)
- [Repo layout](#repo-layout)
- [Auth and secrets](#auth-and-secrets)
- [Contributing](#contributing)

## Words used everywhere

| Term | Meaning |
|---|---|
| **Trial** | One study: a question plus a fixed design (`trial.yaml`). Example: `2026-09-secure-coding-audit`. |
| **Round** | One locked execution of a trial (`rounds/r01/lock.yaml`). Reproductions add new rounds. |
| **Contender** | A skill under test, or `baseline` (no skill). Kinds: `skill`, `plugin`, `prompt`, `baseline`. |
| **Arena** | A target repo pinned to a commit, optionally with ground truth. |
| **Task** | A prompt template, e.g. `security-audit`. |
| **Bout** | One run: contender × arena × task × model × rep. Its ID is a hash of its locked inputs. |
| **Verdict** | What a finding turned out to be. Ground truth gives `tp` / `dup` / `fp` / `unknown`, the judge gives `valid` / `invalid` / `duplicate` / `unverifiable`, humans give `tp` / `fp` / `dup` / `unsure`. Human beats ground truth beats judge. |

## Trials

| Trial | Question | Status | Latest round | Results | Lock |
|---|---|---|---|---|---|
| [2026-09-secure-coding-audit](trials/2026-09-secure-coding-audit/) | Which openly available secure-code-review skills find more real vulnerabilities per dollar than a plain Claude Code baseline? | designed, not run | none (r01 next) | [RESULTS.md](trials/2026-09-secure-coding-audit/rounds/r01/RESULTS.md) (after r01) | [lock.yaml](trials/2026-09-secure-coding-audit/rounds/r01/lock.yaml) (after r01) |

`just trials` prints the same list from the files on disk.

## Reproduce a round in 3 commands

You need `asdf`, `just` and rootless `podman` (cgroup v2), plus a Claude credential (see [Auth](#auth-and-secrets)).

```bash
just setup engine=git+https://github.com/thereisnotime/skillordeal@v0.1.0   # toolchain, engine, runner image
just lock  trial=2026-09-secure-coding-audit round=r01-repro-$USER         # pin everything into a new round
just run   trial=2026-09-secure-coding-audit round=r01-repro-$USER --max-cost-usd 50
```

- Use the engine version recorded in the original round's `lock.yaml` (`engine.version`).
- `run` is resumable. Finished bouts are skipped, so re-running after a crash or a spend limit picks up where it stopped.
- `j=4` runs four bouts at once. Limit the round with `--contender baseline`, `--arena dvpwa` or `--rep 1` to spend less.
- Afterwards: `just score …`, `just judge …`, `just report …` with the same `trial=` and `round=`. Then `diff` your `lock.yaml` against the original to see what moved.

Without just, every recipe is one engine command, e.g. `skillordeal run trials/<trial>/trial.yaml -r <round> -j 1`.

## Trace a number

Say `rounds/r01/RESULTS.md` says `sentry-security-review` found 7 true positives on `dvpwa` at $0.62 per TP. To check it:

1. **Find the bouts behind the row.** Each leaderboard row links to its bouts. The same data is in `rounds/r01/scores/bouts.csv` (one row per bout):

   ```bash
   cd trials/2026-09-secure-coding-audit
   grep sentry-security-review rounds/r01/scores/bouts.csv | grep dvpwa
   ```

2. **Open one bout.** `record.json` has status, versions, hashes, cost, tokens, turns, tool calls, whether the skill fired and RAM/CPU peaks:

   ```bash
   just show bout=b-0123abcd4567ef89
   jq '{status, skill_fired, cost: .usage.total_cost_usd, tokens: .usage.tokens.total_tokens, turns: .usage.num_turns, tool_calls}' \
     rounds/r01/bouts/b-0123abcd4567ef89/record.json
   ```

3. **See what it reported.** `findings.json` is the model's structured output:

   ```bash
   jq -r '.findings[] | "\(.severity)\t\(.cwe // "-")\t\(.file):\(.line_start)\t\(.title)"' \
     rounds/r01/bouts/b-0123abcd4567ef89/findings.json
   ```

4. **See how each finding was scored.** Finding ids are `<bout_id>:<n>` (1-based position in `findings.json`):

   ```bash
   grep b-0123abcd4567ef89 rounds/r01/scores/gt_matches.jsonl | jq -c '{finding_id, verdict, issue_id}'
   grep b-0123abcd4567ef89 rounds/r01/scores/findings.jsonl  | jq -r .finding_hash \
     | xargs -I{} grep {} labels/labels.jsonl rounds/r01/scores/judge.jsonl
   ```

   A `tp` with an `issue_id` points at an entry in `arenas/<arena>/groundtruth.yaml`; that file has the exact file and line range the finding was matched against.

5. **Read the transcript.** The full scrubbed stream-json of the run:

   ```bash
   just transcript bout=b-0123abcd4567ef89 | jq -c 'select(.type=="assistant") | .message.content[]? | select(.type=="tool_use") | {name, input}' | less
   just transcript bout=b-0123abcd4567ef89 | jq 'select(.type=="result")'
   ```

   `prompt.md` in the bout directory is the exact prompt that was sent, and `resources.jsonl` has the 1 s resource samples.

The file formats are defined in the engine's [docs/data-contracts.md](https://github.com/thereisnotime/skillordeal/blob/main/docs/data-contracts.md).

## How to label findings

Ground truth can't settle everything: warpgate-operator has none yet, and dvpwa's is not exhaustive. Humans fill the gap.

```bash
just score  trial=2026-09-secure-coding-audit round=r01   # ground-truth matches first
just review trial=2026-09-secure-coding-audit round=r01   # opens the review UI in your browser
```

The UI shows each finding with its code excerpt, the ground-truth match and the judge's opinion. Pick `tp`, `fp`, `dup` or `unsure`, optionally link a ground-truth issue and add a note. Every click appends one line to `trials/<trial>/labels/labels.jsonl`:

```json
{"finding_hash": "…", "finding_id": "b-…:3", "arena": "dvpwa", "verdict": "tp",
 "issue_id": "dvpwa-sqli-student-create", "labeler": "human:<you>", "ts": "…", "note": ""}
```

- Later lines override earlier ones for the same `finding_hash` and `labeler`, so fixing a label is just labeling again.
- Labels are keyed by `finding_hash`, so they carry over to any round where the same finding shows up.
- A `tp` with no `issue_id` is a candidate for new ground truth (`skillordeal gt-promote`).
- Commit `labels.jsonl` and re-run `just report …` to update the results.

## Repo layout

```
.
├── README.md                  you are here
├── justfile                   every workflow step; `just` prints the menu
├── arenas/
│   ├── dvpwa/
│   │   ├── arena.yaml         repo, pinned commit, language, strip/scope
│   │   └── groundtruth.yaml   known issues with file + line ranges + CWE
│   └── warpgate-operator/
│       └── arena.yaml         no ground truth yet
├── contenders/
│   └── secure-coding-2026-09.yaml   skills under test, each pinned to a sha
├── templates/trial/           scaffold for `just new-trial`
├── trials/
│   └── 2026-09-secure-coding-audit/
│       ├── README.md          question, hypothesis, setup, contenders, how to reproduce
│       ├── trial.yaml         the design
│       ├── tasks/             prompt templates
│       ├── labels/labels.jsonl   human verdicts (written by `just review`)
│       └── rounds/<round>/
│           ├── lock.yaml      every input resolved to an immutable value
│           ├── bouts/<bout-id>/   record.json, findings.json, prompt.md,
│           │                      transcript.jsonl.zst, resources.jsonl, stderr.log
│           ├── scores/        findings.jsonl, gt_matches.jsonl, judge.jsonl, bouts.csv, summary.parquet
│           └── RESULTS.md     generated leaderboard
├── openspec/                  specs and change history for this repo
└── .github/workflows/         ci.yml (validate, actionlint, gitleaks), round.yml (run a round on Actions)
```

Transcripts (`*.jsonl.zst`) and `*.parquet` are stored with git-lfs (see `.gitattributes`). Run `git lfs install` once before committing round output.

## Auth and secrets

Trials only name the environment variable that holds a credential, never the value. The engine hands it to podman with `-e NAME`, so it doesn't show up in argv, logs or artifacts, and every artifact goes through a scrubber before it is written.

| `runtime.auth.mode` | Credential | Notes |
|---|---|---|
| `api_key` | `ANTHROPIC_API_KEY` | Pay-per-token. Bouts run with `--bare`. `cost_usd` is exact. |
| `oauth` | `CLAUDE_CODE_OAUTH_TOKEN` | Long-lived token from `claude setup-token` (subscription). Cost is an estimate from token counts. |
| `credentials_file` | `~/.claude/.credentials.json` | Copied into the bout's throwaway config dir, nothing else from `~/.claude`. |

To use a personal token that lives under another name or in another file, override it for one run instead of editing the trial:

```bash
SKILLORDEAL_TOKEN_ENV=TOC_CLAUDE_CODE_OAUTH_TOKEN \
SKILLORDEAL_ENV_FILE=~/Private/Secret/xxRC/.env \
  just run trial=2026-09-secure-coding-audit round=r01
```

Never commit tokens. `.env` and `.env.*` are gitignored (only `.env.example` is tracked), and `just secrets-scan` runs gitleaks over history and staged changes. CI runs gitleaks too. On GitHub Actions, `round.yml` reads `ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN` from repo secrets depending on the `auth_mode` input.

## Contributing

Run `just verify` before you push (validates every trial, runs actionlint and gitleaks).

**A new trial.**

1. `just new-trial name=2026-10-my-question` scaffolds `trials/2026-10-my-question/` from `templates/trial/`.
2. Fill in `trial.yaml` (full model ids only, aliases are rejected) and the README's Question and Hypothesis *before* running anything.
3. `just validate trial=…`, then `just lock trial=… round=r01` and commit the lock before the run, so the design is fixed in history.
4. Run, score, judge, label, report. Commit the round and update the trial index above.

**A new arena.** Add `arenas/<id>/arena.yaml` with `repo`, a full-sha `ref` (or a release tag, which the lock resolves), `language`, `strip` for build output and agent context files, and `scope` if only part of the repo matters. If you write ground truth, follow the contract in the engine's data-contracts doc: every issue needs a stable `id`, exact `file` and inclusive `lines`, `cwe`, `severity` and `source`. Only list issues you verified in the source at that sha, and set `complete: false` unless you can back up the claim that nothing else is there.

**A new contender.** Add an entry to a file under `contenders/` with `ref` set to a full commit sha. Check the subpath exists at that sha:

```bash
gh api "repos/<owner>/<repo>/contents/<subpath>?ref=<sha>" -q '.[].name // .name'
```

Then prove it materializes without spending anything:

```bash
skillordeal lock trials/<trial>/trial.yaml -r dryrun --skip-image && rm -rf trials/<trial>/rounds/dryrun
```

Use `kind: prompt` for a single `.md` file, `skill` for a directory with `SKILL.md`, `plugin` for a Claude Code plugin directory. Use `strip:` for files that need tools the sandbox doesn't have. Don't add `extra_tools` unless the skill can't work without them, and say why in `notes`.
