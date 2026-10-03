# Method

[Back to README](../README.md)

How a bout runs and how its findings are scored. The engine docs have the full detail: [README](https://github.com/thereisnotime/skillordeal#readme) and [data contracts](https://github.com/thereisnotime/skillordeal/blob/main/docs/data-contracts.md).

## How a bout is isolated

- **Container:** a fresh rootless podman container per bout, read-only root filesystem, tmpfs `HOME`, and an empty Claude config dir. No MCP servers, no host `~/.claude`, no session persistence.
- **Arena:** mounted read-only with `.git` removed, and agent context files (`CLAUDE.md`, `AGENTS.md`, `.claude/`, `.mcp.json`, `.cursor*` and similar) stripped at any depth.
- **Tools:** read-only (`Read`, `Grep`, `Glob`, `Skill` and a few `Bash` commands such as `ls` and `git log`).
- **Network:** the container sits on an internal-only podman network. Its only way out is a per-bout proxy sidecar that tunnels to `api.anthropic.com:443` and nothing else. Every allowed and denied connection attempt is counted in the bout's `record.json` under `egress`, so a skill that tries to phone home is visible, e.g. `{"mode": "allowlist", "allowed": {"api.anthropic.com:443": 3}, "denied": {}}`.
- **Isolation gate:** the harness checks what the CLI reports at startup and marks the bout `invalid` (excluded from scoring) if the loaded skills or plugins aren't what the contender should provide, an MCP server shows up, or the model isn't the locked one.

Full details: [What "zero context" means here](https://github.com/thereisnotime/skillordeal#what-zero-context-means-here) in the engine README.

## How findings are scored

| Source | What it decides | Notes |
|---|---|---|
| Ground truth (`arenas/<arena>/groundtruth.yaml`) | `tp` / `dup` / `fp` / `unknown` per finding | Matched by file, line window and CWE. Unless the list is marked complete, unmatched findings are `unknown` and precision is only a lower bound. |
| LLM judge (blinded, reads the code) | `valid` / `invalid` / `unverifiable` | Confirms the code does what a finding claims. It does not rule on threat model (who can reach the input). |
| Human labels (`trials/<trial>/labels/labels.jsonl`) | `tp` / `fp` / `dup` / `unsure` | Blind review UI, see [labeling](labeling.md). |

Precedence: human, then ground truth, then judge. `unknown`, `unverifiable` and `unsure` fall through to the next source.

Results are means over reps with 95% bootstrap confidence intervals. With 3 reps and many contenders, expect roughly one interval in twenty to exclude zero by chance, so treat single "significant" results as leads, not conclusions.
