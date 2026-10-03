# Trace a number back to its transcript

[Back to README](../README.md)

This walkthrough uses real values from the engine's smoke round (`examples/smoke/rounds/smoke/` in an engine checkout after `just smoke`; that output isn't committed). The smoke round is 1 rep on Haiku, so the numbers prove the plumbing, not anything about skill quality. The layout is the same for every round here: replace the paths with `trials/<trial>/rounds/<round>/`.

Its `RESULTS.md` says `sentry-security-review` found 6 true positives on `dvpwa` at $0.022 per TP. To check it:

1. **Find the bouts behind the row.** Each row in `RESULTS.md` links to its bouts. The same data is in `scores/bouts.csv`, one row per bout:

   ```bash
   cd examples/smoke/rounds/smoke
   grep sentry-security-review scores/bouts.csv | cut -d, -f1-9
   # b-538a92af2574a056,sentry-security-review,dvpwa,security-audit,claude-haiku-4-5-20251001,1,ok,6,0.13267
   ```

   Cost per TP is the total cost of the row's ok bouts over their TPs: $0.13267 / 6 = $0.022.

2. **Open one bout.** `record.json` has status, versions, hashes, cost, tokens, turns, tool calls, whether the skill fired, egress and RAM/CPU peaks:

   ```bash
   skillordeal show bouts/b-538a92af2574a056      # in this repo: just show bout=<bout-id>
   jq -c '{status, skill_fired, cost: .usage.total_cost_usd, tokens: .usage.tokens.total_tokens, turns: .usage.num_turns, tool_calls}' \
     bouts/b-538a92af2574a056/record.json
   # {"status":"ok","skill_fired":true,"cost":0.13267009999999999,"tokens":536667,"turns":37,"tool_calls":{"Bash":11,"Read":24,"StructuredOutput":1}}
   ```

3. **See what it reported.** `findings.json` is the model's structured output:

   ```bash
   jq -r '.findings[] | "\(.severity)\t\(.cwe // "-")\t\(.file):\(.line_start)\t\(.title)"' \
     bouts/b-538a92af2574a056/findings.json
   # critical  CWE-89    sqli/dao/student.py:42           SQL Injection in Student.create()
   # high      CWE-79    sqli/templates/courses.jinja2:17  Stored XSS via Course Title and Description
   # high      CWE-79    sqli/templates/course.jinja2:22   Stored XSS via Review Text
   # high      CWE-326   sqli/dao/user.py:40               Weak Password Hashing Algorithm
   # high      CWE-1004  sqli/middlewares.py:20            Session Cookies Missing HttpOnly Flag
   # medium    CWE-352   sqli/app.py:25                    CSRF Protection Disabled
   ```

4. **See how each finding was scored.** Finding ids are `<bout_id>:<n>` (1-based position in `findings.json`). `verdicts.jsonl` shows every source side by side and which one won:

   ```bash
   grep b-538a92af2574a056:4 scores/gt_matches.jsonl | jq -c '{finding_id, verdict, issue_id, match_basis, line_distance}'
   # {"finding_id":"b-538a92af2574a056:4","verdict":"tp","issue_id":"dvpwa-md5-password-hash","match_basis":"cwe","line_distance":0}
   grep b-538a92af2574a056:4 scores/verdicts.jsonl | jq -c '{human, gt, judge, verdict, source}'
   # {"human":null,"gt":"tp","judge":"valid","verdict":"tp","source":"gt"}
   ```

   A `tp` with an `issue_id` points at an entry in the arena's `groundtruth.yaml`. Here `dvpwa-md5-password-hash` lists `sqli/dao/user.py` lines 40 to 41 and CWE-326 among its CWEs, which is why this finding matched on CWE at distance 0. Human labels for a trial are in `trials/<trial>/labels/labels.jsonl`, keyed by `finding_hash`.

5. **Read the transcript.** The full scrubbed stream-json of the run:

   ```bash
   skillordeal transcript bouts/b-538a92af2574a056 \
     | jq -c 'select(.type=="assistant") | .message.content[]? | select(.type=="tool_use") | {name, input}' | less
   skillordeal transcript bouts/b-538a92af2574a056 | jq -c 'select(.type=="result") | {subtype, num_turns, total_cost_usd}'
   # {"subtype":"success","num_turns":37,"total_cost_usd":0.13267009999999999}
   ```

   `prompt.md` in the bout directory is the exact prompt that was sent, and `resources.jsonl` has the 1 s resource samples.
