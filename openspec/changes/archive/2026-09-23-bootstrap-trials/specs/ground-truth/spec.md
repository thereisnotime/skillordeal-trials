## ADDED Requirements

### Requirement: Ground truth follows the engine contract
`arenas/<arena>/groundtruth.yaml` SHALL follow the ground-truth contract in the engine's `docs/data-contracts.md`: `arena`, `sha`, and `issues` with `id`, `title`, `category`, `cwe`, `severity`, `locations` (file and inclusive `lines`), `source` and `notes`.

#### Scenario: Engine lock hashes the file
- **WHEN** a trial using the arena is locked
- **THEN** the lock records the ground-truth file and its sha256

### Requirement: Verified locations
Every ground-truth location SHALL be checked against the arena source at the recorded `sha`, and only issues confirmed in the code SHALL be listed.

#### Scenario: Line drift
- **WHEN** the arena `ref` changes to a new commit
- **THEN** the ground truth is re-verified and its `sha` updated before the next lock

### Requirement: Completeness is explicit
Ground truth SHALL declare `complete` and `window`. It SHALL NOT claim `complete: true` unless the arena's issues are exhaustively known.

#### Scenario: Unmatched finding on dvpwa
- **WHEN** a finding matches no dvpwa issue
- **THEN** it scores `unknown` and is left to the judge and human labels
