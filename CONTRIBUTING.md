# Contributing

Run `just verify` before you push (validates every trial, runs actionlint and gitleaks).

## A new trial

1. `just new-trial name=2026-10-my-question` scaffolds `trials/2026-10-my-question/` from [`templates/trial/`](templates/trial/).
2. Fill in `trial.yaml` (full model IDs only, aliases are rejected) and the README's Question and Hypothesis *before* running anything.
3. `just validate trial=…`, then `just lock trial=… round=r01` and commit the lock before the run, so the design is fixed in history.
4. Run, score, judge, label, report. Commit the round and update the [trial index](README.md#trials).

## A new arena

Add `arenas/<id>/arena.yaml` with `repo`, a full-sha `ref` (or a release tag, which the lock resolves), `language`, `strip` for build output and agent context files, and `scope` if only part of the repo matters. If you write ground truth, follow the [ground truth contract](https://github.com/thereisnotime/skillordeal/blob/main/docs/data-contracts.md#ground-truth-arenasarenagroundtruthyaml-trials-repo): every issue needs a stable `id`, exact `file` and inclusive `lines`, `cwe`, `severity` and `source`. Only list issues you verified in the source at that sha, and set `complete: false` unless you can back up the claim that nothing else is there.

## A new contender

Add an entry to a file under `contenders/` with `ref` set to a full commit sha. Check the subpath exists at that sha:

```bash
gh api "repos/<owner>/<repo>/contents/<subpath>?ref=<sha>" -q '.[].name // .name'
```

Then prove it materializes without spending anything:

```bash
skillordeal lock trials/<trial>/trial.yaml -r dryrun --skip-image && rm -rf trials/<trial>/rounds/dryrun
```

Use `kind: prompt` for a single `.md` file, `skill` for a directory with `SKILL.md`, `plugin` for a Claude Code plugin directory, and `pipeline` to chain existing contenders as finder then verifiers (see [Pipelines](https://github.com/thereisnotime/skillordeal#pipelines)). Use `strip:` for files that need tools the sandbox doesn't have. Don't add `extra_tools` unless the skill can't work without them, and say why in `notes`.
