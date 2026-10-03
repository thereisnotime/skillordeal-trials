# Arena: filebrowser

[File Browser](https://github.com/filebrowser/filebrowser) pinned at
[`a1e442ef`](https://github.com/filebrowser/filebrowser/tree/a1e442ef9e4a14719184bf02c50dbc981ecf8665)
(tag `v2.63.5`, 2026-05-21). License: Apache-2.0.

## Why this one

dvpwa is a teaching app, so every model finds the same textbook bugs. File Browser is a real,
widely deployed, actively maintained Go web app with a size that fits a 30-minute read-only
audit (about 10k lines of non-test Go, 13k lines of Vue/TS frontend after `strip`). Between
June and July 2026 it published a run of advisories, and the v2.63.5 release still contained
eleven of them. They are mostly authorization and scope bugs that need the reviewer to
understand the app's model (users, scopes, rules, public shares), plus one pre-auth command
injection and two path traversal variants. All advisories were published after the
vulnerable release, from 2026-06-03 on.

Agent context files: none at this sha (no `CLAUDE.md`, `AGENTS.md`, `.cursor*` or
`.github/copilot-instructions.md`). `www/` (the docs site) is stripped because its
deployment notes describe some of these issues.

## Ground truth

| id | advisory | CWE | location at sha | severity | published | fix |
|---|---|---|---|---|---|---|
| fb-hook-auth-cmd-injection | [CVE-2026-54088 / GHSA-m93h-4hw7-5qcm](https://github.com/filebrowser/filebrowser/security/advisories/GHSA-m93h-4hw7-5qcm) | CWE-78, 77, 88, 306 | auth/hook.go 88-109 | critical | 2026-06-03 | [34ae34e7](https://github.com/filebrowser/filebrowser/commit/34ae34e764d72540c039f1f5ea2ec4c974168c1f) |
| fb-public-share-rule-rebase | [CVE-2026-54091 / GHSA-j9jx-hp4c-ghhh](https://github.com/filebrowser/filebrowser/security/advisories/GHSA-j9jx-hp4c-ghhh) | CWE-863, 285, 284, 639 | http/public.go 56-77, http/data.go 29-48 | high | 2026-06-06 | [e07c59df](https://github.com/filebrowser/filebrowser/commit/e07c59df0b850f5924d5b1683e8609661ddcf534) |
| fb-share-delete-prefix-cross-user | [CVE-2026-54097 / GHSA-5ww9-jg6q-38r7](https://github.com/filebrowser/filebrowser/security/advisories/GHSA-5ww9-jg6q-38r7) | CWE-639, 863, 285, 284, 862 | http/resource.go 103, storage/bolt/share.go 79-90 | high | 2026-06-03 | [0231b7eb](https://github.com/filebrowser/filebrowser/commit/0231b7ebdfbe77a6c54027d30c4856c3fd81ee4d) |
| fb-archive-backslash-zipslip | [CVE-2026-54093 / GHSA-gxjx-7m74-hcq8](https://github.com/filebrowser/filebrowser/security/advisories/GHSA-gxjx-7m74-hcq8) | CWE-22, 23, 29 | http/raw.go 124-135 | medium | 2026-06-06 | [847d08bd](https://github.com/filebrowser/filebrowser/commit/847d08bdd135e5c3659f2e6dea2f0cd36617af9b) |
| fb-symlink-scope-escape | [CVE-2026-54094 / GHSA-239w-m3h6-ch8v](https://github.com/filebrowser/filebrowser/security/advisories/GHSA-239w-m3h6-ch8v) | CWE-59, 61, 22, 23 | files/file.go 131-151, http/resource.go 297-310, users/users.go 93-97 | high | 2026-06-03 | [847d08bd](https://github.com/filebrowser/filebrowser/commit/847d08bdd135e5c3659f2e6dea2f0cd36617af9b), [3471ec2c](https://github.com/filebrowser/filebrowser/commit/3471ec2c4b6473831c72ee889cb3c1a6849a1fb1), [7c2c0a11](https://github.com/filebrowser/filebrowser/commit/7c2c0a11b31b2bb214d741005a0b02b1764208b3) |
| fb-share-nonexistent-path | [CVE-2026-54096 / GHSA-3q2p-72cj-682c](https://github.com/filebrowser/filebrowser/security/advisories/GHSA-3q2p-72cj-682c) | CWE-862, 863, 284, 285 | http/share.go 101-110, 156-167 | high | 2026-06-04 | [166583db](https://github.com/filebrowser/filebrowser/commit/166583db632e088e9f0adce30aec43bb9d9019f4), [ca019ae7](https://github.com/filebrowser/filebrowser/commit/ca019ae7d966a7c28de2b2341271cd13e3458ae6) |
| fb-share-api-leaks-secrets | [CVE-2026-62684 / GHSA-833g-cqhp-h72j](https://github.com/filebrowser/filebrowser/security/advisories/GHSA-833g-cqhp-h72j) | CWE-200, 522, 212 | share/share.go 15-19, http/share.go 31-57, 59-78 | low | 2026-07-04 | [ec130546](https://github.com/filebrowser/filebrowser/commit/ec130546713c44cd24556907552ac554c7f809c9) |
| fb-signup-username-home-collision | [CVE-2026-62685 / GHSA-7rc3-g7h6-22m7](https://github.com/filebrowser/filebrowser/security/advisories/GHSA-7rc3-g7h6-22m7) | CWE-647, 706, 41, 863, 284 | settings/dir.go 24-30, 42-52, http/auth.go 186-196 | high | 2026-07-04 | [883a36f0](https://github.com/filebrowser/filebrowser/commit/883a36f02fcb69566a8628cb47f18fdc73348387) |
| fb-checksum-download-bypass | [CVE-2026-72834 / GHSA-7whw-q6gh-xr59](https://github.com/filebrowser/filebrowser/security/advisories/GHSA-7whw-q6gh-xr59) | CWE-863, 862, 285, 200 | http/resource.go 70-80 | medium | 2026-07-25 | [6c69b5cd](https://github.com/filebrowser/filebrowser/commit/6c69b5cd895e15b29e563200a9a6dfc27b06525e) |
| fb-recursive-ops-ignore-rules | [CVE-2026-73612 / GHSA-77x8-73f4-5485](https://github.com/filebrowser/filebrowser/security/advisories/GHSA-77x8-73f4-5485) | CWE-863, 285, 284, 862 | http/resource.go 221-223, 257-259, 114-116 | high | 2026-07-27 | [72faf6dd](https://github.com/filebrowser/filebrowser/commit/72faf6dd3c85628e332d3e567124b86708ce2695) |
| fb-provisioned-users-root-scope | [CVE-2026-72837 / GHSA-j7jh-37pf-mf8h](https://github.com/filebrowser/filebrowser/security/advisories/GHSA-j7jh-37pf-mf8h) | CWE-284, 863, 266, 269, 1188 | auth/proxy.go 48-58, auth/hook.go 159-180 | high | 2026-07-27 | [8ddd3d1d](https://github.com/filebrowser/filebrowser/commit/8ddd3d1db9b9f5727d0bf96ea0e7d9a25a8692b4) |

CWE lists include the advisory's ids plus close relatives a reviewer is likely to cite,
because matching needs an exact CWE id. `complete: false`: see the header of
[groundtruth.yaml](groundtruth.yaml) for real issues at this sha that are left out on
purpose (no code fix, opt-in features, platform-specific, DoS only).

## Caveats

- Several issues only apply with non-default settings: hook auth (1 and 11), proxy auth
  (11), signup with `createUserDir` (8), deny rules (2, 10). A finding that reports the
  flaw with that precondition is still a true positive.
- The symlink escape needs a symlink inside the user's scope that File Browser itself
  can't create (shared volumes, other tools). Findings may name `users/users.go` (the
  `BasePathFs` scope), `files/file.go` (`stat`) or a handler; the first two are listed.
- `http/resource.go` has three issues within about 50 lines that share CWE-863 and
  CWE-285; human labels override when a finding is tied to the wrong one.
