# Reproduce a round

[Back to README](../README.md)

You need `asdf`, `just` and rootless `podman` (cgroup v2), plus a Claude credential (see [Auth and secrets](#auth-and-secrets) below).

```bash
just setup engine=git+https://github.com/thereisnotime/skillordeal@v0.1.4   # toolchain, engine, runner image
just lock  trial=2026-09-secure-coding-audit round=r01-repro-$USER         # pin everything into a new round
just run   trial=2026-09-secure-coding-audit round=r01-repro-$USER --max-cost-usd 50
```

- Use the engine version recorded in the original round's `lock.yaml` (`engine.version`).
- `run` is resumable. Finished bouts are skipped, so re-running after a crash or a spend limit picks up where it stopped.
- `j=4` runs four bouts at once. Limit the round with `--contender baseline`, `--arena dvpwa` or `--rep 1` to spend less.
- Afterwards: `just score …`, `just judge …`, `just report …` with the same `trial=` and `round=`. Then `diff` your `lock.yaml` against the original to see what moved.

Without just, every recipe is one engine command, e.g. `skillordeal run trials/<trial>/trial.yaml -r <round> -j 1`.

## Auth and secrets

Trials only name the environment variable that holds a credential, never the value. The engine hands it to podman with `-e NAME`, so it doesn't show up in argv, logs or artifacts, and every artifact goes through a scrubber before it is written.

| `runtime.auth.mode` | Credential | Notes |
|---|---|---|
| `api_key` | `ANTHROPIC_API_KEY` | Pay-per-token. Bouts run with `--bare`. |
| `oauth` | `CLAUDE_CODE_OAUTH_TOKEN` | Long-lived token from `claude setup-token` (subscription). Cost is the CLI's estimate and notional. |
| `credentials_file` | `~/.claude/.credentials.json` | Copied into the bout's throwaway config dir, nothing else from `~/.claude`. |

To use a personal token that lives under another name or in another file, override it for one run instead of editing the trial:

```bash
SKILLORDEAL_TOKEN_ENV=WORK_CLAUDE_CODE_OAUTH_TOKEN \
SKILLORDEAL_ENV_FILE=~/.config/secrets/claude.env \
  just run trial=2026-09-secure-coding-audit round=r01
```

Never commit tokens. `.env` and `.env.*` are gitignored (only `.env.example` is tracked), and `just secrets-scan` runs gitleaks over history and staged changes. CI runs gitleaks too. On GitHub Actions, `round.yml` reads `ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN` from repo secrets depending on the `auth_mode` input.

## CI secrets

Set these on the repo (Settings, Secrets and variables, Actions):

| Secret | Needed for |
|---|---|
| `CLAUDE_CODE_OAUTH_TOKEN` | `auth_mode: oauth` rounds (a long-lived `claude setup-token` token) |
| `ANTHROPIC_API_KEY` | `auth_mode: api_key` rounds |
| `ENGINE_READ_TOKEN` | while the engine repo and runner image are private: a classic PAT with `repo` and `read:packages` |
