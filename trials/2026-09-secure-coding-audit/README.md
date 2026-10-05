# 2026-09-secure-coding-audit

**Design:** 24 contenders + baseline × 2 arenas × 1 task × 1 model × 3 reps = 150 bouts. Model under test `claude-opus-4-8` at `high` effort, judge `claude-sonnet-5`.

**Status:** r01 done. The first 72 bouts ran on 2026-09-23 (engine 0.1.2), the 78 for the 13 contenders added later ran on 2026-10-03 (engine 0.1.3, same image, CLI and model). Results: [`rounds/r01/RESULTS.md`](rounds/r01/RESULTS.md). Findings are judged by the threat-model-aware panel (re-judged 2026-10-04; the first fact-checking judge's verdicts stay in its cache); human labels optional.

**Jump to:** [TL;DR](#tldr-result) · [Charts](#leaderboard) · [Contenders](#contenders) · [Arenas](#arenas) · [Reproduce](#how-to-reproduce) · [Dig in](#how-to-dig-in)

## Question

Which openly available secure-code-review skills find more real vulnerabilities per dollar than a plain Claude Code baseline?

## Hypothesis

Written before r01 started:

- Most skills will not beat the baseline on recall by much. Opus at high effort already knows the OWASP checklist, so a skill mostly changes how thorough the model is and how it reports.
- The big methodical skills (cf-security-audit, sentry-security-review) will find a few more issues on dvpwa but cost noticeably more tokens, so per dollar they may land near the baseline.
- Diff-scoped prompts (tob-differential-review, anthropic-security-review-cmd, neolab-security-auditor) will do worse than the baseline because the arena has no git history to diff against.
- sentry-code-review (a thin general checklist) and samber-golang-security on dvpwa (wrong language) act as controls and should not beat the baseline.
- On warpgate-operator, precision will matter more than recall: the interesting question is how many findings survive the judge and human review.

## TL;DR result

From r01 (Opus 4.8 at high effort, 3 reps per cell, 95% bootstrap CIs; [full results](rounds/r01/RESULTS.md)):

- **One skill's lead is real, on easy bugs.** On dvpwa the baseline finds 6 of the 19 known issues per run. Three contenders cleared zero in r01: `anthropic-security-auditor` +2.0, `agamm-owasp-security` +1.7 and `samber-golang-security` +1.3. Because the baseline ran ten days earlier, they were re-run next to a fresh baseline ([control round](#control-round-r01-control-2026-10-04)): `anthropic-security-auditor` held (+1.7 [1.2, 2.3] pooled, 8 known bugs in all six runs), `agamm-owasp-security` partly held, `samber-golang-security` was noise. On the harder [filebrowser trial](../2026-10-filebrowser-cve-audit/) the same lead found none of the 11 real CVEs.
- **Everyone finds the same easy bugs and misses the same hard ones.** On dvpwa 5 issues were found by every contender in every run, 7 by nobody (two XSS sinks in templates, default admin credentials, an exposed Postgres, a root container, an error-page leak, an unverified download), and 3 by only one contender once each.
- **Skills mostly change cost, not quality.** Cost per true positive on dvpwa ranges from $0.057 (`every-ce-security-reviewer`) to $0.229 (`sentry-then-fp-check`); the baseline is $0.070.
- **Verifier pipelines cut findings hard, and a stricter judge cuts half of everyone's.** On warpgate-operator `sentry-then-fp-check` reports 1.3 findings per run and `claude-security-researcher` 1.7, against the baseline's 3. The first judge accepted 694 of 695 findings because it only checked that the code does what a finding says. Re-judged by the threat-model-aware panel (three Opus voters trying to refute each finding through reachability, impact and correctness), 109 of the 210 warpgate-operator findings were refuted, mostly because only someone who can already create the operator's resources could exploit them. On dvpwa the panel kept 455 of the 474 findings that match known vulnerabilities (96%), so it isn't simply rejecting everything. With 4 to 11 findings per contender the per-contender survival rates on warpgate-operator (22% to 78%) are too small to rank on; the [filebrowser trial](../2026-10-filebrowser-cve-audit/#tldr-result) has the cleaner comparison.
- **One skill can't do a full-repo audit.** `anthropic-security-review-cmd` runs `git diff` while it loads; that's denied and there is no history, so all 6 bouts stopped before the first model turn.
- **Every skill loaded.** Each contender's first prompt was 3k to 39k tokens larger than the baseline's.

Against the [hypothesis](#hypothesis): skills barely moving recall held, and so did the big skills costing more without finding more (`cf-security-audit`). The diff-scoped prediction held for one of the three diff-oriented prompts. Of the controls, `sentry-code-review` matched the baseline as predicted; `samber-golang-security` beat it on dvpwa, against the prediction.

### Control round (r01-control, 2026-10-04)

The first r01 bouts and the 13 later contenders ran ten days apart, so the r01 leads were re-run on dvpwa next to a fresh baseline, same lock, same day ([`rounds/r01-control/RESULTS.md`](rounds/r01-control/RESULTS.md)). True positives per run:

| contender | r01 runs | same-day runs | Δ vs same-day baseline | pooled (6 runs each) Δ vs baseline |
|---|---|---|---|---|
| baseline | 7, 5, 6 | 7, 7, 6 | | |
| `anthropic-security-auditor` | 8, 8, 8 | 8, 8, 8 | +1.3 [1.0, 2.0] | **+1.7 [1.2, 2.3]** |
| `agamm-owasp-security` | 8, 7, 8 | 7, 8, 7 | +0.7 [0.0, 1.3] | +1.2 [0.5, 1.8] |
| `samber-golang-security` | 8, 7, 7 | 7, 6, 7 | 0.0 [-0.7, 0.7] | +0.7 [0.0, 1.5] |

`anthropic-security-auditor` reproduces: 8 known bugs in all six runs across both days. `agamm-owasp-security` keeps a smaller edge, and `samber-golang-security`'s r01 result was noise. The baseline drifted up by about 0.7 TP between the two dates, which inflated the r01 gaps a little but doesn't explain them. On the harder [filebrowser trial](../2026-10-filebrowser-cve-audit/) the same lead found none of the 11 real CVEs, so the edge is broader coverage of textbook bugs, not deeper analysis.

## Setup

| | |
|---|---|
| Model under test | `claude-opus-4-8`, effort `high`, `max_budget_usd` 5 per bout |
| Judge | `claude-sonnet-5`, `max_budget_usd` 2 |
| Claude Code CLI | 2.1.280 (inside the image) |
| Engine | skillordeal 0.1.2 (first 72 bouts), 0.1.3 (the 78 added later), 0.1.4 (panel judge); each bout's `record.json` has its own |
| Runner image | `ghcr.io/thereisnotime/skillordeal-runner:v0.1.2`, digest pinned in [`rounds/r01/lock.yaml`](rounds/r01/lock.yaml) |
| Auth | `oauth` (`CLAUDE_CODE_OAUTH_TOKEN`) |
| Invocation | `forced`: the prompt starts with `/<skill-name>` |
| Reps | 3 per contender × arena |
| Per-bout limits | 1800 s, 4,000,000 tokens, 250 turns, 2 CPUs, 4 GB |
| Task | [`tasks/security-audit.md`](tasks/security-audit.md), read-only tools |
| Network | egress only to `api.anthropic.com:443` through a per-bout proxy |


## Contenders

Full definitions: [`contenders/secure-coding-2026-09.yaml`](../../contenders/secure-coding-2026-09.yaml). Excluded candidates and the reasons are listed at the bottom of that file.

The first 12 ran on 2026-09-23; the last 13 rows were added on 2026-10-03.

<details>
<summary><b>All 25 contenders</b> (source, license, role, why included)</summary>

| id | source (pinned sha) | license | role | why included |
|---|---|---|---|---|
| baseline | plain Claude Code, no skill | | finder | the reference every number is compared to |
| cf-security-audit | [cloudflare/security-audit-skill@c1c8a8c](https://github.com/cloudflare/security-audit-skill/tree/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8/skills/security-audit) | MIT | finder | largest and most rigorous single skill; `.cjs` validators stripped (no node in the sandbox) |
| sentry-security-review | [getsentry/skills@c2f99a5](https://github.com/getsentry/skills/tree/c2f99a5b04b4cd992ec3022d7c2c3e23e938d241/skills/security-review) | Apache-2.0 | finder | confidence-based, fully read-only, has python guides |
| sentry-code-review | [getsentry/skills@c2f99a5](https://github.com/getsentry/skills/tree/c2f99a5b04b4cd992ec3022d7c2c3e23e938d241/skills/code-review) | Apache-2.0 | general-review | thin general checklist, control for "any review skill" |
| openai-security-best-practices | [openai/skills@49f948f](https://github.com/openai/skills/tree/49f948faa9258a0c61caceaf225e179651397431/skills/.curated/security-best-practices) | Apache-2.0 | finder | curated OpenAI skill with python and Go guides |
| ecc-security-review | [affaan-m/ECC@bf70150](https://github.com/affaan-m/ECC/tree/bf70150eb2df8070024e5bdf08e4aa08959e2735/skills/security-review) | MIT | finder | most-starred collection in the survey, checklist style |
| samber-golang-security | [samber/cc-skills-golang@19a0626](https://github.com/samber/cc-skills-golang/tree/19a0626ae8565d27a7b7bdf59d8d99d94d7e284c/skills/golang-security) | MIT | finder | Go specialist for warpgate-operator; off-topic control on dvpwa |
| tob-sharp-edges | [trailofbits/skills@32e34f8](https://github.com/trailofbits/skills/tree/32e34f8173796e3566a51aee877dc96bc5191f64/plugins/sharp-edges) | CC-BY-SA-4.0 | finder | footgun and dangerous-default hunting, read-only |
| tob-differential-review | [trailofbits/skills@32e34f8](https://github.com/trailofbits/skills/tree/32e34f8173796e3566a51aee877dc96bc5191f64/plugins/differential-review) | CC-BY-SA-4.0 | finder | diff-oriented; measures how a diff skill copes with a full audit |
| anthropic-security-review-cmd | [anthropics/claude-code-security-review@0c6a49f](https://github.com/anthropics/claude-code-security-review/blob/0c6a49f1fa56a1d472575da86a94dbc1edb78eda/.claude/commands/security-review.md) | MIT | finder | the `/security-review` command prompt, wrapped as a skill |
| every-ce-security-reviewer | [EveryInc/compound-engineering-plugin@4fbabcd](https://github.com/EveryInc/compound-engineering-plugin/blob/4fbabcd32b6ca7d8ebb82f15840fe34ef7562a64/skills/ce-code-review/references/personas/security-reviewer.md) | MIT | finder | security persona from a popular review orchestrator |
| neolab-security-auditor | [NeoLabHQ/context-engineering-kit@23e2428](https://github.com/NeoLabHQ/context-engineering-kit/blob/23e2428e809d77717f8acc9659c374a3a1fcb93e/plugins/review/agents/security-auditor.md) | GPL-3.0 | finder | long security-auditor agent prompt |
| github-copilot-security-review | [github/awesome-copilot@1f56440](https://github.com/github/awesome-copilot/tree/1f5644080a525d26a2e24f61a7609fb9b261c21a/skills/security-review) | MIT | finder | GitHub's official security-review skill (data flow, self-verification, severity). |
| github-copilot-se-security-reviewer | [github/awesome-copilot@1f56440](https://github.com/github/awesome-copilot/blob/1f5644080a525d26a2e24f61a7609fb9b261c21a/agents/se-security-reviewer.agent.md) | MIT | finder | GitHub's security reviewer agent (OWASP Top 10 + LLM Top 10), wrapped as a skill. |
| anthropic-security-auditor | [anthropics/claude-plugins-official@6bfd4e0](https://github.com/anthropics/claude-plugins-official/blob/6bfd4e0c6d3da6050984fa5ed8281d915fa7ed69/plugins/code-modernization/agents/security-auditor.md) | Apache-2.0 | finder | Anthropic's adversarial full-codebase security auditor agent (code-modernization plugin). |
| claude-security-researcher | [anthropics/claude-plugins-official@6bfd4e0](https://github.com/anthropics/claude-plugins-official/blob/6bfd4e0c6d3da6050984fa5ed8281d915fa7ed69/plugins/claude-security/agents/scan-researcher.md) | Apache-2.0 | finder | The researcher agent of Anthropic's claude-security plugin, run on its own. The full product is interactive (AskUserQuestion menu, Workflow scripts, Python helpers, hooks) and can't run headless here, so this and claude-security-flat approximate its method. |
| claude-security-flat | `claude-security-researcher` then `claude-security-verifier` | Apache-2.0 | finder | Approximation of claude-security's scan: its researcher, then its verifier over all findings in one pass (the product runs per component/lens with a 3-voter panel). |
| sentry-then-fp-check | `sentry-security-review` then `tob-fp-check` | stages' licenses | finder | Finder + independent verifier, the combination the research recommended. |
| gemini-security-analyze-full | [gemini-cli-extensions/security@2227f3c](https://github.com/gemini-cli-extensions/security/blob/2227f3cf7150972baac695b8233abc2186408538/commands/security/analyze-full.toml) | Apache-2.0 | finder | Gemini CLI's two-pass taint analysis (recon, then source-to-sink investigation). Degraded here: its scratch files in .gemini_security/ can't be written (read-only arena) and its find_line_numbers MCP tool doesn't exist, so it keeps its plan in context and reads line numbers itself. |
| sari3l-security-code-audit | [sari3l/security-code-audit-skill@f1cf08a](https://github.com/sari3l/security-code-audit-skill/tree/f1cf08acfe8f77486c228590b73d6c2a60ba5195/) | MIT | finder | Thorough evidence-based audit from a little-known author (3 stars), as a contrast to vendor skills. |
| agamm-owasp-security | [agamm/claude-code-owasp@bfaf257](https://github.com/agamm/claude-code-owasp/tree/bfaf257b2859986a6a84d2b7491e1fab2218cd53/.claude/skills/owasp-security) | MIT | finder | OWASP Top 10:2025 and ASVS 5.0. |
| unitone-secure-code-review | [UnitOneAI/SecuritySkills@70bc259](https://github.com/UnitOneAI/SecuritySkills/tree/70bc259bb01abb3015ad2ad859ad5253cbf0bcab/skills/appsec/secure-code-review) | MIT | finder | OWASP and NIST grounded review; semgrep is optional and absent here. |
| evandervecht-security-audit | [evandervecht/security-audit-skill@25a0916](https://github.com/evandervecht/security-audit-skill/tree/25a0916bc664bc2ced2b4557d6153ae79fcc05e9/skills/security-audit) | NOASSERTION (README says MIT / CC-BY-SA) | finder | CWE Top 25 plus CVSS v4 scoring; ships its own eval fixtures. |
| ivan-sincek-cwe-secure-code-review | [ivan-sincek/secure-code-review-agent-skills@5f9b4e3](https://github.com/ivan-sincek/secure-code-review-agent-skills/tree/5f9b4e338a6bce0d09781341632ce57047c63d66/markdown/cwe-secure-code-review) | MIT | finder | Systematic walk through CWE-699 categories. |
| addyosmani-security-auditor | [addyosmani/agent-skills@bcab6a1](https://github.com/addyosmani/agent-skills/blob/bcab6a1b8503100e8618c3b4e32cc78de43de769/agents/security-auditor.md) | MIT | finder | Persona-style security auditor from a very popular collection; a control for "short persona prompt". |

</details>

Defined but not in r01: `tob-fp-check` (verifier, needs a finder's output) and `tob-entry-point-analyzer` (context pre-pass, no findings).

## Arenas

| id | repo @ ref | language | ground truth |
|---|---|---|---|
| dvpwa | [anxolerd/dvpwa@a1d8f89](https://github.com/anxolerd/dvpwa/tree/a1d8f89fac2e57093189853c6527c2b01fc1d9c1) | python | [19 issues](../../arenas/dvpwa/groundtruth.yaml), `complete: false` |
| warpgate-operator | [thereisnotime/warpgate-operator@warpgate-operator-v0.4.11](https://github.com/thereisnotime/warpgate-operator/tree/b31dfff6595115435dbf7411504188edfd8de9a8) (b31dfff) | go | none yet; judge + human labels |

## Leaderboard

[`rounds/r01/RESULTS.md`](rounds/r01/RESULTS.md) opens with generated key takeaways and has every table (with CIs and links to each bout) and chart. The ones to start with:

**Which known vulnerabilities each contender found on dvpwa** (rows are issues by severity, columns contenders):

![dvpwa: ground-truth issues found, by contender](rounds/r01/charts/coverage-dvpwa.svg)

**True positives against the baseline on dvpwa:**

![dvpwa: TP against baseline](rounds/r01/charts/delta-vs-baseline-dvpwa.svg)

**Problems each contender reported on warpgate-operator** (no ground truth; clusters of findings across contenders):

![warpgate-operator: distinct problems reported, by contender](rounds/r01/charts/problems-warpgate-operator.svg)

`report.html` next to RESULTS.md is the interactive version with a per-contender drill-down (open it locally).

## How to reproduce

```bash
just setup engine=git+https://github.com/thereisnotime/skillordeal@v0.1.4
just lock  trial=2026-09-secure-coding-audit round=r01-repro-$USER
just run   trial=2026-09-secure-coding-audit round=r01-repro-$USER j=2 --max-cost-usd 400
```

Then score and compare with r01:

```bash
just score  trial=2026-09-secure-coding-audit round=r01-repro-$USER
just judge  trial=2026-09-secure-coding-audit round=r01-repro-$USER
just report trial=2026-09-secure-coding-audit round=r01-repro-$USER
```

`lock` refuses if the image's CLI version differs from the one the trial pins, and `run` refuses on any drift from the lock. Your new lock records its own image digest, contender tree hashes and arena commits, so diff it against [`rounds/r01/lock.yaml`](rounds/r01/lock.yaml) to see exactly what changed.

## How to dig in

Run these from this directory (`just` finds the repo's justfile from here):

```bash
just status trial=2026-09-secure-coding-audit round=r01           # every bout: status, cost, tokens, RAM
just show bout=<bout-id>                                          # one bout: record + findings
just transcript bout=<bout-id> | jq -c 'select(.type=="assistant")' | less
jq '.findings[] | {title, file, line_start, cwe}' rounds/r01/bouts/<bout-id>/findings.json
```

Per-finding verdicts live in `rounds/r01/scores/gt_matches.jsonl` (ground truth), `rounds/r01/scores/judge.jsonl` (judge) and `labels/labels.jsonl` (humans, written by `just review`); `rounds/r01/scores/verdicts.jsonl` shows all three side by side. Human labels win, then ground truth, then the judge. The top-level README walks through [tracing one number](../../docs/trace-a-number.md) end to end.
