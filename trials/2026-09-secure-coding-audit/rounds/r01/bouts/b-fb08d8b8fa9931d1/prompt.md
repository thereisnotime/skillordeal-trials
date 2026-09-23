/ordeal:code-review

You are auditing the repository in the current directory (dvpwa, primarily python) for security vulnerabilities. Scope: the whole repository.

Rules:

- Work read-only. Do not create, edit or delete files, and do not try to build, run or install anything.
- Investigate the code yourself. Do not guess from file names, comments or the project's reputation.
- Report only issues you can point to in the code. Every finding needs the exact file path relative to the repository root and the line range (`line_start`, `line_end`, inclusive) where the flaw lives. Point at the root cause (the sink, the missing check, the bad setting), not at a caller several hops away.
- One finding per distinct issue. If the same flaw shows up in several places, report the place that best represents it and list the others in the description.
- Prefer precision over volume. Leave out generic advice, style issues and anything you could not trace to real, reachable code.

For each finding give:

- `title`: one line, specific ("SQL injection in Student.create", not "SQL injection")
- `category`: usually `security`
- `cwe`: the most specific CWE id that applies, e.g. `CWE-89`
- `severity`: critical, high, medium, low or info, based on realistic impact in this codebase
- `confidence`: high, medium or low
- `file`, `line_start`, `line_end`
- `description`: how it can be exploited or why it matters, including who can reach it
- `evidence`: the relevant code or the data flow from source to sink
- `recommendation`: the concrete fix

When you are done, write your report as described below. The `summary` says what you reviewed and the overall risk; `coverage` lists the files or directories you actually read. If you find nothing, return an empty findings list and say what you covered.

---

## How to report

When you are done, write your report as a single JSON document to `/out/findings.json` with the Write tool. That file is the only thing that is collected; anything else you say is ignored. Use Edit or Write again if you need to fix it. It must be valid JSON matching this schema:

```json
{
  "type": "object",
  "additionalProperties": false,
  "required": [
    "summary",
    "findings"
  ],
  "properties": {
    "summary": {
      "type": "string",
      "description": "Two to five sentences: what was reviewed, overall risk, coverage limits."
    },
    "coverage": {
      "type": "array",
      "description": "Files or directories actually reviewed.",
      "items": {
        "type": "string"
      }
    },
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": [
          "title",
          "category",
          "severity",
          "confidence",
          "file",
          "line_start",
          "description"
        ],
        "properties": {
          "title": {
            "type": "string"
          },
          "category": {
            "type": "string",
            "enum": [
              "security",
              "quality",
              "maintainability",
              "performance",
              "other"
            ]
          },
          "cwe": {
            "type": "string",
            "description": "CWE id like CWE-89, if applicable."
          },
          "severity": {
            "type": "string",
            "enum": [
              "critical",
              "high",
              "medium",
              "low",
              "info"
            ]
          },
          "confidence": {
            "type": "string",
            "enum": [
              "high",
              "medium",
              "low"
            ]
          },
          "file": {
            "type": "string",
            "description": "Path relative to the repository root."
          },
          "line_start": {
            "type": "integer",
            "minimum": 1
          },
          "line_end": {
            "type": "integer",
            "minimum": 1
          },
          "description": {
            "type": "string"
          },
          "evidence": {
            "type": "string",
            "description": "Relevant code or data-flow trace."
          },
          "recommendation": {
            "type": "string"
          }
        }
      }
    }
  }
}
```

Put every finding in the `findings` array (an empty array if you found nothing) and keep `summary` to a few sentences. Paths are relative to the repository root. After writing the file, reply with one short line saying it is written.
