# SAST-MCP – Documentation

All detailed docs in one place: tool health, parallel scanning, multiprocess backend, async client, adaptive batching, and Kali/Windows setup.

---

## 1. Tool health and usage

- **Health:** `GET /health` runs a check command per tool (e.g. `semgrep scan --version`) via `execute_command(check_cmd, timeout=10)`. Result is in `tools_status`.
- **Client:** Use MCP tool `sast_server_health()` to get the same payload.
- **Essential tools (must be available):** semgrep, bandit, eslint, npm, safety, trufflehog, gitleaks.
- **Additional:** bearer, graudit, gosec, brakeman, checkov, tfsec, trivy, nodejsscan, dependency-check.
- **Kali:** nikto, nmap, sqlmap, wpscan, dirb, lynis, snyk, clamscan.
- **Alignment:** Health uses `{DEPENDENCY_CHECK_PATH} --version` so the same binary as scans is checked. nodejsscan is included in health.

---

## 2. Parallel scanning and project structure

- **Project structure:** `scan_project_structure(project_path)` finds dependency files and recommends tools per project type.
- **Scan queue:** Scans use a semaphore; default `MAX_PARALLEL_SCANS=4`, `SCAN_WAIT_TIMEOUT=1800` (30 min). Use `get_scan_statistics()` for active/queued/completed.
- **Env:** `MAX_PARALLEL_SCANS`, `SCAN_WAIT_TIMEOUT`, `DEFAULT_OUTPUT_DIR`, `MAX_WORKERS`, `JOB_RETENTION_HOURS`.

---

## 3. Multiprocess backend

- **Execution:** ProcessPoolExecutor for parallel scans; configurable workers and memory limit.
- **Features:** Result validation, checksum, retry with exponential backoff, error categorization (TOOL_NOT_FOUND, TIMEOUT, etc.), process health metrics.
- **Env:** `USE_MULTIPROCESSING`, `MAX_PARALLEL_SCANS`, `MAX_PROCESS_WORKERS`, `PROCESS_MEMORY_LIMIT_MB`, `SCAN_WAIT_TIMEOUT`, `MAX_RETRY_ATTEMPTS`, `RETRY_BACKOFF_BASE`, `ENABLE_RESULT_VALIDATION`, `ENABLE_CHECKSUM_VERIFICATION`, `MIN_RESULT_SIZE_BYTES`.
- **Sync mode:** `FORCE_SYNC_SCANS=1` (default) runs scans in the request thread to avoid job-queue/semaphore issues.

---

## 4. Async client (MCP)

- Scan tools use async/await and aiohttp; default max-accuracy options (e.g. Semgrep: `--max-memory 0 --timeout 0`).
- Background mode is forced for scan endpoints so the client gets a job_id and uses `get_scan_result_toon` / `get_job_status`.

---

## 5. Adaptive batching (weekly scan)

- `weekly_sast_scan.py` can use adaptive batching based on server capacity.
- Prerequisites: `pip install psutil requests`. Run with `--no-adaptive` to disable, `--project <name>` for a single project.

---

## 6. Kali + Windows (VMware) setup

- **Layout:** Windows `F:/work/` shared into Kali as `/mnt/work`. Server on Kali scans paths under `/mnt/work` and can write results there (visible on Windows).
- **VMware:** Shared Folders → Host path `F:\work`, name `work`. In Kali: `sudo mkdir -p /mnt/work`, `sudo vmhgfs-fuse .host:/work /mnt/work -o allow_other -o uid=1000`. Add to `/etc/fstab` for persistence.
- **Server .env:** `MOUNT_POINT=/mnt/work`, `WINDOWS_BASE=F:/work`, `DEFAULT_OUTPUT_DIR=/mnt/work/scan-results` (optional).
- **Test:** `python3 test_path_resolution.py`. From Claude (Windows): e.g. “Run Bandit on F:/work/MyProject”; server resolves to `/mnt/work/MyProject`.

---

## 7. Project structure (modular server)

```
sast-mcp/
├── client/              # MCP client
├── server/
│   ├── config.py        # Env and constants (single place to tune)
│   ├── core.py          # Execution, jobs, path, validation, retry (no Flask)
│   ├── routes/          # One module per category – edit here to fix/update a tool
│   │   ├── __init__.py  # register_all(app)
│   │   ├── sast.py      # Semgrep, Bearer, Graudit, Bandit, Gosec, Brakeman, NodeJSScan, ESLint
│   │   ├── secrets.py   # TruffleHog, Gitleaks
│   │   ├── dependencies.py  # Safety, npm audit, Dependency-Check, Snyk
│   │   ├── iac.py       # Checkov, tfsec
│   │   ├── container.py # Trivy
│   │   ├── kali.py      # Nikto, Nmap, SQLMap, WPScan, DIRB, Lynis, ClamAV
│   │   ├── util.py      # Command, batch-scan-dirs, scan-project-structure, scan-stats
│   │   ├── jobs.py      # List/get/cancel/cleanup jobs, result, result-toon, statistics
│   │   ├── analysis.py  # AI summary, summarize, toon-status
│   │   └── health.py    # GET /health
│   └── sast_server.py   # App creation, register_all(app), main (~60 lines)
├── tools/               # TOON, AI analysis, install script
├── README.md
├── DOCS.md
├── requirements.txt
├── .env.example
└── config.example.json
```

To fix or change a specific tool: edit the right file under `server/routes/` (e.g. `sast.py` for Semgrep/Bandit, `secrets.py` for TruffleHog/Gitleaks). Each module has a `register(app)` that attaches its endpoints.

---

## 8. TOON response format (AI save & analysis)

Every scan tool endpoint returns a **TOON-shaped** response so the AI can easily save and analyze results:

- **Shape:** `{ "success": bool, "result_format": "toon-analysis", "toon_result": { ... }, "job_id": "...", "tool": "tool_name" }`
- **toon_result** contains: `format`, `tool`, `job_id`, `analysis` (summary, risk, counts), and `findings` (normalized list, optionally raw). Built in `server/core.response_as_toon()` using `tools/ai_analysis.py` (`analyze_scan_results`, `create_toon_analysis_result`).
- **Sync Semgrep/Nikto** already return this shape from `run_scan_synchronously`. All other tools (Bearer, Bandit, TruffleHog, Safety, Checkov, Trivy, Nmap, etc.) wrap their raw result with `response_as_toon(tool_name, params, result)` before `jsonify`.
- On TOON build failure, the response still has `result_format: "toon-analysis"` with a minimal `toon_result` and `raw_result` for debugging.

## 9. Full-coverage repo scan (`POST /api/repo-scan`)

One call stages a repo, detects what it is, runs **every installed tool that
applies**, and cross-checks the reports into a single ranked finding set.

```bash
curl -X POST http://kali:6000/api/repo-scan \
  -H 'Content-Type: application/json' \
  -d '{"path": "F:/Resola/Deca/my-service"}'
```

### Tool matrix

Tools are selected by three gates — the language/marker must be present, the
binary must be installed (`server/tool_registry.py` probes once, cached), and
the caller must not have switched the group off. Anything skipped is reported in
`coverage`, never silently dropped.

| Group | Tools | Gate |
|---|---|---|
| SAST | semgrep/opengrep, bearer, graudit | any source file |
| Python | bandit | `.py` |
| JS/TS | nodejsscan, eslint-security | `.js/.ts/.jsx/.tsx/.vue` |
| Go | gosec | `.go` |
| Ruby | brakeman | `.rb` |
| Secrets | gitleaks, trufflehog | `secrets: true` |
| Deps | trivy, osv-scanner, safety, pip-audit, npm-audit, dependency-check, snyk | manifest/lockfile present |
| IaC | checkov, tfsec (or `trivy config`) | `.tf`, Dockerfile, compose, k8s YAML |

Toggles (all default `true` except `snyk`): `secrets`, `deps`, `iac`, `gosec`,
`bearer`, `graudit`, `eslint`, `snyk`.

### Cross-checking

`server/correlate.py` normalizes every tool's JSON into one schema, then
clusters findings that describe the same defect:

* **code** findings cluster on file + nearby line (`CORRELATE_LINE_WINDOW`,
  default 3) + normalized vulnerability category, derived from CWE first and
  rule/message keywords second — so `bandit:B602` at line 43 and
  `semgrep:subprocess-shell-true` at line 42 become one finding;
* **dependency** findings cluster on package + CVE, because file/line is
  meaningless there — `trivy` and `safety` agreeing on `CVE-2023-1111` in
  `django` is one finding, not two.

Each cluster is ranked:

| Confidence | Meaning |
|---|---|
| `confirmed` | a verified live credential (trufflehog verification) |
| `corroborated` | two or more independent tools agree |
| `single_tool` | one tool's claim — triage last |

The response carries `cross_check` (counts, `by_severity`, `by_category`,
`tool_agreement`) and `top_findings`; the full set is written to
`<output_dir>/cross_check.json`. Raw per-tool counts stay in `results[]`.

### Performance

* **Staging** uses a streamed `tar` pipe, not a per-file `shutil.copytree` — and
  `stage: "auto"` (default) skips the copy entirely when the source is already
  on local disk. Use `"always"` / `"never"` to override.
* **Scheduling** is weighted, not a flat worker count: `semgrep --jobs 8` counts
  as 8, `gitleaks` as 1, and the runner keeps the sum of in-flight weights under
  `REPO_SCAN_CPU_BUDGET` (0 = `cpu_count`). Expensive, long-tailed tools are
  started first. Lower the budget when scanning several repos concurrently.
* **Selection** skips uninstalled tools before spawning anything.

### Tuning env vars

| Var | Default | Purpose |
|---|---|---|
| `REPO_SCAN_CPU_BUDGET` | `0` (cpu_count) | total in-flight tool weight per repo scan |
| `REPO_SCAN_TOOL_CONCURRENCY` | `min(4, MAX_PROCESS_WORKERS)` | thread-pool floor |
| `REPO_SCAN_LOCAL_DIR` | `/var/tmp/sast-repos` | staging + report scratch |
| `TOOL_PROBE_TTL` | `900` | seconds a tool-availability probe stays cached |
| `CORRELATE_LINE_WINDOW` | `3` | line drift tolerated when clustering code findings |
| `OPENGREP_JOBS` | `0` (auto) | lower to 2 when scanning many repos at once |

## 10. Mounts and local private-repo scanning

### The problem this replaces

The server understood exactly one client→server mapping,
`WINDOWS_BASE` → `MOUNT_POINT`. A second VMware shared folder could be added to
`ALLOWED_MOUNTS` so it passed validation, but nothing could *translate* a client
path into it — `resolve_windows_path` fell through and returned the Windows
string unchanged, which then failed validation anyway. `util.py` also gated
translation on a literal `"F:"` drive letter. In practice every repo had to live
under one share.

`server/pathmap.py` now resolves across any number of mounts, longest-prefix
first, handling `F:/x`, `f:/x`, `/f:/x` (Git Bash) and backslashes.

### Configuring mounts

Sources are additive, in this order:

| Source | Example | Notes |
|---|---|---|
| `WINDOWS_BASE` + `MOUNT_POINT` | `F:/work` → `/mnt/work` | the original pair, still honored |
| `PATH_MAPPINGS` | `F:/Resola=/mnt/Resola,D:/code=/mnt/code` | comma-separated `CLIENT=SERVER` |
| `MOUNTS_CONFIG` | `/opt/sast-mcp/mounts.json` | see `mounts.json.example`; defaults to `./mounts.json` |
| `ALLOWED_MOUNTS` | `/srv/repos,/home/kali/projects` | server roots with no client twin |
| auto-discovery | `AUTO_DISCOVER_MOUNTS=1` (default) | shared folders under `/mnt`, `/media`, `/srv`, `/data` |

Auto-discovery is what makes "I mounted a new folder in VMware" just work: the
share becomes a scannable root with no config change. It only accepts real mount
points of shared-folder/network type under `AUTO_DISCOVER_PARENTS`, so system
paths are never included, and `validate_scan_target` still rejects anything
outside the resulting root set.

```bash
# after mounting a new share — no restart needed
curl -X POST http://kali:6000/api/util/mounts/reload
```

### Inspecting mounts

```bash
curl http://kali:6000/api/util/mounts
```

Returns each mapping with an `exists` flag, the allowed roots, what was
auto-discovered, and which config sources are active. This is the first thing to
check when a scan fails with *"outside the allowed mount roots"*. A compact
version is also in `GET /health` under `mounts`.

### Finding repos to scan

```bash
# every repo on every mounted share
curl -X POST http://kali:6000/api/util/find-repos -d '{}' -H 'Content-Type: application/json'

# one share, including non-git project dirs
curl -X POST http://kali:6000/api/util/find-repos \
  -H 'Content-Type: application/json' \
  -d '{"root": "F:/Resola", "require_git": false}'
```

Each result carries a `path` that can be posted straight to `/api/repo-scan`,
plus a sampled language mix and file count. Language sampling is capped per repo
so listing a few hundred repos stays interactive; `include_git_info: true` adds
branch and last commit at the cost of one git call per repo.

MCP tools: `find_repos`, `list_mounts`, `reload_mounts`.

### Removed hardcoding

`SAST_RESULTS_DIR` and the source-repo root no longer default to one
deployment's folder names. They derive from `MOUNT_POINT`, and are overridden by
`SAST_RESULTS_DIR` / `REPO_SRC_DIR`. `RESOLA_SRC_DIR` is still read as an alias,
so existing `.env` files keep working.

## 11. What a secret scan actually covers (working tree vs git history)

These answer different questions, and mixing them inflates or hides findings.

| | reads | sees | misses |
|---|---|---|---|
| **gitleaks** (`/api/secrets/gitleaks`) | git objects, `--log-opts=--max-count=1000` by default | every secret ever committed in that range, including ones deleted from HEAD | anything only in an uncommitted working tree |
| **working-tree scans** (`/api/repo-scan`, `opengrep_scan`, anything handed a directory) | files on disk | untracked and **gitignored** files | history — a secret removed from HEAD is invisible |

Two consequences worth knowing before triaging a result:

**A working-tree scan will flag your local dev files.** `/api/repo-scan` stages
with a streamed `tar`, which copies the working tree, so `.env` and friends are
included even when gitignored. During the 2026-10-04 Deca/IPS sweep, opengrep
reported AWS keys, JWTs and generic secrets in `deca-agents/apps/server/.env` —
that file is untracked *and* gitignored, so it is a developer's local config, not
an exposure. Confirm with:

```sh
git -C <repo> ls-files --error-unmatch <path>   # exit 0 = committed, so a real leak
git -C <repo> check-ignore -q <path>            # exit 0 = gitignored
```

**Deleting a file does not unleak it.** A secret removed from HEAD is still in
the history and still needs rotating. The same sweep found 46 high-confidence
secrets that exist only in history (22 removed from HEAD, 24 with the file
deleted), going back to 2018. Classify each finding as `LIVE_AT_HEAD`,
`HISTORY_ONLY` or `FILE_GONE_AT_HEAD` before deciding urgency — only the first
needs a code change, but all three need rotation.

**Also**: `--log-opts` is invalid in `--no-git` mode. Pass `--no-git` to scan a
directory that is not a repo (or a tree of repos) and the endpoint will omit the
history-depth limit automatically.
