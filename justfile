set shell := ["bash", "-uc"]
set dotenv-load := false
set positional-arguments := true

# ANSI color helpers
BOLD := '\033[1m'
DIM := '\033[2m'
RESET := '\033[0m'
RED := '\033[31m'
GREEN := '\033[32m'
YELLOW := '\033[33m'
MAGENTA := '\033[35m'
CYAN := '\033[36m'

# Engine to install. Override with a pinned release for real rounds, e.g.
#   just setup engine=git+https://github.com/thereisnotime/skillordeal@v0.1.0
engine := "git+file://" + env_var("HOME") + "/Private/Projects/P/skillordeal"
runner := "ghcr.io/thereisnotime/skillordeal-runner:v0.1.0"
so := "skillordeal"

# Defaults for key=value arguments. Pass them after the recipe name:
#   just run trial=2026-09-secure-coding-audit round=r01 j=2 --max-cost-usd 5
trial := ""
round := "r01"
j := "1"
bout := ""
name := ""

# Shared bash helpers for the recipes below: key=value parsing and trial/bout lookup.
_lib := '''
die() { printf "\033[31merror:\033[0m %s\n" "$*" >&2; exit 1; }
extra=()
parse() {
  for a in "$@"; do
    case "$a" in
      trial=*|round=*|j=*|bout=*|name=*|engine=*|runner=*) declare -g "${a%%=*}=${a#*=}" ;;
      *) extra+=("$a") ;;
    esac
  done
}
trial_file() {
  local t="${1:-}"
  [[ -n "$t" ]] || die "trial= is required, e.g. trial=2026-09-secure-coding-audit (see: just trials)"
  if [[ -f "$t" ]]; then echo "$t"
  elif [[ -f "trials/$t/trial.yaml" ]]; then echo "trials/$t/trial.yaml"
  else die "no trial '$t' (looked for trials/$t/trial.yaml)"; fi
}
bout_dir() {
  local b="${1:-}"
  [[ -n "$b" ]] || die "bout= is required: a bout directory or a bout id like b-0123abcd4567ef89"
  if [[ -d "$b" ]]; then echo "$b"; return; fi
  local hits=(trials/*/rounds/*/bouts/"$b")
  [[ -d "${hits[0]}" ]] || die "no bout '$b' under trials/*/rounds/*/bouts/"
  (( ${#hits[@]} == 1 )) || die "bout id '$b' is in several rounds, pass the directory: ${hits[*]}"
  echo "${hits[0]}"
}
'''

# Show the colorized, categorized menu (bare `just`)
default:
    #!/usr/bin/env bash
    set -uo pipefail
    row() { printf "  {{GREEN}}%-48s{{RESET}} %s\n" "$1" "$2"; }
    printf "{{BOLD}}{{CYAN}}skillordeal-trials{{RESET}} {{DIM}}studies, ground truth, labels and results for the skillordeal engine{{RESET}}\n\n"
    printf "{{BOLD}}{{MAGENTA}}SETUP{{RESET}}\n"
    row "setup [engine=URL@TAG]"                      "asdf toolchain, install the engine, pull the runner image"
    row "image [runner=REF]"                          "pull the pinned runner image with podman"
    printf "\n{{BOLD}}{{MAGENTA}}TRIALS{{RESET}}\n"
    row "trials"                                      "list trials and their rounds"
    row "new-trial name=ID"                           "scaffold trials/ID from templates/trial"
    row "validate trial=ID"                           "load and check a trial and everything it references"
    row "lock trial=ID round=R [--force]"             "pin every input into rounds/R/lock.yaml"
    row "plan trial=ID round=R"                       "list the bouts of a locked round"
    printf "\n{{BOLD}}{{MAGENTA}}RUN{{RESET}} {{YELLOW}}(spends model budget){{RESET}}\n"
    row "run trial=ID round=R [j=1] [--max-cost-usd X]" "run a round (resumable, j parallel bouts)"
    row "status trial=ID round=R"                     "per-bout status, cost, tokens, RAM"
    row "judge trial=ID round=R"                      "LLM judge over findings not settled by ground truth"
    printf "\n{{BOLD}}{{MAGENTA}}SCORE & REPORT{{RESET}}\n"
    row "score trial=ID round=R"                      "match findings to ground truth, write rounds/R/scores/"
    row "review trial=ID round=R"                     "label findings in the browser (labels/labels.jsonl)"
    row "report trial=ID round=R"                     "write rounds/R/RESULTS.md from scores + labels"
    printf "\n{{BOLD}}{{MAGENTA}}INSPECT{{RESET}}\n"
    row "show bout=DIR|ID"                            "one bout's record summary and findings"
    row "transcript bout=DIR|ID"                      "decompressed stream-json (pipe to jq)"
    printf "\n{{BOLD}}{{MAGENTA}}CHECKS{{RESET}}\n"
    row "secrets-scan"                                "gitleaks over history and staged changes"
    printf "  {{GREEN}}%-48s{{RESET}} {{YELLOW}}%s{{RESET}}\n" "verify" "validate every trial + actionlint + secrets-scan"
    printf "\n{{DIM}}Arguments are key=value after the recipe name. trial= takes an id from {{RESET}}{{BOLD}}just trials{{RESET}}{{DIM}}; round defaults to r01.{{RESET}}\n"

# SETUP: toolchain, engine and runner image
setup *args:
    #!/usr/bin/env bash
    set -euo pipefail
    engine={{quote(engine)}} runner={{quote(runner)}}
    {{_lib}}
    parse "$@"
    asdf install || true
    printf "{{CYAN}}installing engine from{{RESET}} %s\n" "$engine"
    uv tool install --force "skillordeal[analysis] @ ${engine}"
    {{so}} version
    podman pull "$runner" || printf "{{YELLOW}}could not pull %s; lock needs it (or build it in the engine repo: just image){{RESET}}\n" "$runner"

# SETUP: pull the runner image a trial pins
image *args:
    #!/usr/bin/env bash
    set -euo pipefail
    runner={{quote(runner)}}
    {{_lib}}
    parse "$@"
    podman pull "$runner"
    podman run --rm --network=none "$runner" claude --version

# TRIALS: list trials and their rounds
trials:
    #!/usr/bin/env bash
    set -uo pipefail
    printf "{{BOLD}}%-36s %-10s %s{{RESET}}\n" "trial" "rounds" "title"
    for f in trials/*/trial.yaml; do
      d=$(dirname "$f"); id=$(basename "$d")
      title=$(sed -n 's/^title: *//p' "$f" | head -1)
      rounds=$(find "$d/rounds" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | sort | paste -sd, -)
      printf "{{GREEN}}%-36s{{RESET}} %-10s %s\n" "$id" "${rounds:--}" "$title"
    done

# TRIALS: scaffold a new trial from templates/trial
new-trial *args:
    #!/usr/bin/env bash
    set -euo pipefail
    name={{quote(name)}}
    {{_lib}}
    parse "$@"
    [[ -n "$name" ]] || die "name= is required, e.g. name=2026-10-dependency-review"
    [[ "$name" =~ ^[a-z0-9][a-z0-9._-]*$ ]] || die "name must be a lowercase slug"
    dest="trials/$name"
    [[ ! -e "$dest" ]] || die "$dest already exists"
    cp -r templates/trial "$dest"
    find "$dest" -type f -exec sed -i "s/__TRIAL_ID__/$name/g" {} +
    mkdir -p "$dest/rounds" && touch "$dest/rounds/.gitkeep"
    printf "{{GREEN}}created{{RESET}} %s\n" "$dest"
    printf "next: edit %s/trial.yaml and README.md, then: just validate trial=%s\n" "$dest" "$name"

# TRIALS: load and check a trial.yaml
validate *args:
    #!/usr/bin/env bash
    set -euo pipefail
    trial={{quote(trial)}}
    {{_lib}}
    parse "$@"
    t=$(trial_file "$trial")
    {{so}} validate "$t"

# TRIALS: pin every input into rounds/ROUND/lock.yaml (extra flags pass through, e.g. --force)
lock *args:
    #!/usr/bin/env bash
    set -euo pipefail
    trial={{quote(trial)}} round={{quote(round)}}
    {{_lib}}
    parse "$@"
    t=$(trial_file "$trial")
    {{so}} lock "$t" -r "$round" "${extra[@]}"

# TRIALS: list the bouts of a locked round
plan *args:
    #!/usr/bin/env bash
    set -euo pipefail
    trial={{quote(trial)}} round={{quote(round)}}
    {{_lib}}
    parse "$@"
    t=$(trial_file "$trial")
    {{so}} plan "$t" -r "$round" "${extra[@]}"

# RUN: run a round; j=1 runs one bout at a time. Extra flags pass through (--max-cost-usd 5, --contender x)
run *args:
    #!/usr/bin/env bash
    set -euo pipefail
    trial={{quote(trial)}} round={{quote(round)}} j={{quote(j)}}
    {{_lib}}
    parse "$@"
    t=$(trial_file "$trial")
    {{so}} run "$t" -r "$round" -j "$j" "${extra[@]}"

# RUN: per-bout status table
status *args:
    #!/usr/bin/env bash
    set -euo pipefail
    trial={{quote(trial)}} round={{quote(round)}}
    {{_lib}}
    parse "$@"
    t=$(trial_file "$trial")
    {{so}} status "$t" -r "$round" "${extra[@]}"

# SCORE: match findings against ground truth into rounds/ROUND/scores/
score *args:
    #!/usr/bin/env bash
    set -euo pipefail
    trial={{quote(trial)}} round={{quote(round)}}
    {{_lib}}
    parse "$@"
    t=$(trial_file "$trial")
    {{so}} score "$t" -r "$round" "${extra[@]}"

# RUN: LLM judge for findings ground truth can't settle (cached, costs judge budget)
judge *args:
    #!/usr/bin/env bash
    set -euo pipefail
    trial={{quote(trial)}} round={{quote(round)}}
    {{_lib}}
    parse "$@"
    t=$(trial_file "$trial")
    {{so}} judge "$t" -r "$round" "${extra[@]}"

# SCORE: label findings in the review UI; writes trials/ID/labels/labels.jsonl
review *args:
    #!/usr/bin/env bash
    set -euo pipefail
    trial={{quote(trial)}} round={{quote(round)}}
    {{_lib}}
    parse "$@"
    t=$(trial_file "$trial")
    {{so}} review "$t" -r "$round" "${extra[@]}"

# SCORE: generate rounds/ROUND/RESULTS.md
report *args:
    #!/usr/bin/env bash
    set -euo pipefail
    trial={{quote(trial)}} round={{quote(round)}}
    {{_lib}}
    parse "$@"
    t=$(trial_file "$trial")
    {{so}} report "$t" -r "$round" "${extra[@]}"

# INSPECT: summarize one bout (bout= directory or bout id)
show *args:
    #!/usr/bin/env bash
    set -euo pipefail
    bout={{quote(bout)}}
    {{_lib}}
    parse "$@"
    b=$(bout_dir "$bout")
    {{so}} show "$b"

# INSPECT: print a bout's transcript as JSON lines (pipe into jq)
transcript *args:
    #!/usr/bin/env bash
    set -euo pipefail
    bout={{quote(bout)}}
    {{_lib}}
    parse "$@"
    b=$(bout_dir "$bout")
    {{so}} transcript "$b"

# CHECKS: scan history and staged changes for secrets
secrets-scan:
    gitleaks git --no-banner --redact .
    gitleaks git --no-banner --redact --staged .

# CHECKS: run before you push
verify:
    #!/usr/bin/env bash
    set -euo pipefail
    for f in trials/*/trial.yaml; do {{so}} validate "$f"; done
    actionlint
    just secrets-scan
    printf "{{GREEN}}verify passed{{RESET}}\n"
