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
