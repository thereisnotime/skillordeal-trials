# skillordeal-trials

[![ci](https://github.com/thereisnotime/skillordeal-trials/actions/workflows/ci.yml/badge.svg)](https://github.com/thereisnotime/skillordeal-trials/actions/workflows/ci.yml)

Do agent skills (`SKILL.md` packs, Claude Code plugins, prompts) actually make an LLM better at reviewing code? This repo holds the studies that test it with [skillordeal](https://github.com/thereisnotime/skillordeal): every skill runs alone in an isolated container against pinned code, next to a no-skill baseline, and every run is kept so any number can be traced back to its transcript.

## Start here

| I want to… | Go to |
|---|---|
| **See the results** | [Latest results](#latest-results) below, then each trial's README and `RESULTS.md` |
| **Understand the method** | [docs/method.md](docs/method.md): isolation, scoring, how to read the statistics |
| **Check where a number came from** | [docs/trace-a-number.md](docs/trace-a-number.md) |
| **Reproduce a round** | [docs/reproduce.md](docs/reproduce.md): 3 commands, auth, CI secrets |
| **Label findings** | [docs/labeling.md](docs/labeling.md): the blind review UI |
| **Add a trial, arena or skill** | [CONTRIBUTING.md](CONTRIBUTING.md) |

## Latest results

**Bottom line so far:** skills don't make Opus 4.8 find more real vulnerabilities. One skill reliably adds a couple of textbook bugs on a toy app, and the most useful difference between skills is how much noise their reports carry.

**[2026-10-filebrowser-cve-audit](trials/2026-10-filebrowser-cve-audit/)** (real Go app with 11 published CVEs, 10 contenders + baseline, 33 runs):

- No contender beats the baseline on CVEs found. The best average 0.7 of 11 per run, the baseline 0.5, and 7 of the 11 were never found by anyone.
- Skills differ on noise: a threat-model-aware judge panel refuted none of the findings from `sentry-security-review`, `sentry-then-fp-check` and `every-ce-security-reviewer`, and most of `agamm-owasp-security`'s (54%) and `samber-golang-security`'s (67%).

**[2026-09-secure-coding-audit](trials/2026-09-secure-coding-audit/)** (23 skills and pipelines + baseline, toy app dvpwa and the real operator warpgate-operator, 150 runs):

- On dvpwa the baseline finds 6 of 19 known vulnerabilities per run. `anthropic-security-auditor` finds 8 in every run, and that held up in a same-day [control round](trials/2026-09-secure-coding-audit/README.md#control-round-r01-control-2026-10-04): +1.7 [1.2, 2.3] at the baseline's cost. On filebrowser it found none of the CVEs.
- On warpgate-operator the judge panel refuted about half of all findings (109 of 210), mostly issues only an already-privileged user could trigger. On dvpwa it kept 96% of the findings that match known vulnerabilities, so it isn't simply rejecting everything.
- One skill (`anthropic-security-review-cmd`) can't run a full-repo audit at all.

Every number with its confidence interval, the caveats and the charts are in each trial's README and `RESULTS.md`.

## Trials

| Trial | Question | Status | Results | Lock |
|---|---|---|---|---|
| [2026-09-secure-coding-audit](trials/2026-09-secure-coding-audit/) | Which openly available secure-code-review skills find more real vulnerabilities per dollar than a plain Claude Code baseline? | r01 done (150 bouts) | [RESULTS.md](trials/2026-09-secure-coding-audit/rounds/r01/RESULTS.md) | [lock.yaml](trials/2026-09-secure-coding-audit/rounds/r01/lock.yaml) |
| [2026-10-filebrowser-cve-audit](trials/2026-10-filebrowser-cve-audit/) | Confirmation on a real Go app with 11 published CVEs: do the leads and verifier pipelines beat the baseline? | r01 done (33 bouts) | [RESULTS.md](trials/2026-10-filebrowser-cve-audit/rounds/r01/RESULTS.md) | [lock.yaml](trials/2026-10-filebrowser-cve-audit/rounds/r01/lock.yaml) |

`just trials` prints the same list from the files on disk; `just` alone shows every command.

## How it works

```mermaid
flowchart LR
  I["skill + codebase<br/>+ task + model"] --> L["lock<br/>pin every input"]
  L --> B["bout<br/>isolated container"]
  B --> O["findings<br/>+ metrics"]
  O --> S["ground truth"]
  O --> J["LLM judge"]
  O --> H["human labels"]
  S --> R["RESULTS.md<br/>+ charts"]
  J --> R
  H --> R
```

| Term | Meaning |
|---|---|
| **Trial** | One study: a question and a fixed design (`trial.yaml`). |
| **Round** | One locked run of a trial (`rounds/r01/`). Reproductions become new rounds. |
| **Contender** | A skill under test, a finder + verifier `pipeline`, or `baseline` (no skill). |
| **Arena** | A codebase pinned to a commit, optionally with known issues (ground truth). |
| **Bout** | One run: contender × arena × task × model × rep. |

Each bout gets a fresh container, a read-only copy of the code, read-only tools and network access to the model API only. Details in [docs/method.md](docs/method.md).

<details>
<summary><b>Repo layout</b></summary>

```text
.
├── README.md                  you are here
├── docs/                      method, reproduce, labeling, trace a number
├── justfile                   every workflow step; `just` prints the menu
├── arenas/<arena>/
│   ├── arena.yaml             repo, pinned commit, language, strip/scope
│   └── groundtruth.yaml       known issues with file + line ranges + CWE
├── contenders/                skills under test (pinned to a commit) and candidate lists
├── templates/trial/           scaffold for `just new-trial`
└── trials/<trial>/
    ├── README.md              question, hypothesis, results summary, contenders
    ├── trial.yaml             the design
    ├── tasks/                 prompt templates
    ├── labels/labels.jsonl    human verdicts
    └── rounds/<round>/
        ├── lock.yaml          every input resolved to an immutable value
        ├── RESULTS.md         generated report, charts in charts/
        ├── report.html        interactive version (open locally)
        ├── bouts/<bout-id>/   record.json, findings.json, prompt.md, transcript.jsonl.zst, ...
        └── scores/            per-finding and per-bout scores
```

Round output is committed as plain files; a round is a few tens of MB.

</details>

## License

Apache-2.0, see [LICENSE](LICENSE). Skills and codebases under test are referenced by repository and commit, not copied, and keep their own licenses (listed in `contenders/*.yaml` and the trial READMEs). Transcripts and findings are model output about that code and may quote short excerpts of it.
