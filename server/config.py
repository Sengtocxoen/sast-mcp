"""
Server configuration from environment variables.
All timeouts, paths, and feature flags in one place for easy tuning.
"""
import os
import multiprocessing

# Load .env if available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Server
API_PORT = int(os.environ.get("API_PORT", 6000))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = int(os.environ.get("COMMAND_TIMEOUT", 3600))
MAX_TIMEOUT = int(os.environ.get("MAX_TIMEOUT", 86400))

# Tool timeouts (seconds)
NIKTO_TIMEOUT = int(os.environ.get("NIKTO_TIMEOUT", 3600))
NMAP_TIMEOUT = int(os.environ.get("NMAP_TIMEOUT", 7200))
SQLMAP_TIMEOUT = int(os.environ.get("SQLMAP_TIMEOUT", 7200))
WPSCAN_TIMEOUT = int(os.environ.get("WPSCAN_TIMEOUT", 3600))
DIRB_TIMEOUT = int(os.environ.get("DIRB_TIMEOUT", 7200))
LYNIS_TIMEOUT = int(os.environ.get("LYNIS_TIMEOUT", 1800))
SNYK_TIMEOUT = int(os.environ.get("SNYK_TIMEOUT", 3600))
CLAMAV_TIMEOUT = int(os.environ.get("CLAMAV_TIMEOUT", 14400))
OPENGREP_TIMEOUT = int(os.environ.get("OPENGREP_TIMEOUT", 7200))
BANDIT_TIMEOUT = int(os.environ.get("BANDIT_TIMEOUT", 1800))
TRUFFLEHOG_TIMEOUT = int(os.environ.get("TRUFFLEHOG_TIMEOUT", 3600))
DEPENDENCY_CHECK_TIMEOUT = int(os.environ.get("DEPENDENCY_CHECK_TIMEOUT", 1800))

DEPENDENCY_CHECK_PATH = os.environ.get("DEPENDENCY_CHECK_PATH", "dependency-check")

# Path resolution (Windows client -> Linux server)
MOUNT_POINT = os.environ.get("MOUNT_POINT", "/mnt/work")
WINDOWS_BASE = os.environ.get("WINDOWS_BASE", "F:/work")

# Mount roots that scan targets may live under. Assembled by pathmap from every
# configured source — the legacy WINDOWS_BASE/MOUNT_POINT pair, PATH_MAPPINGS,
# a mounts.json, explicit ALLOWED_MOUNTS, and auto-discovered shared folders —
# so adding a second VMware share no longer means editing code. See pathmap.py.
import pathmap as _pathmap

ALLOWED_MOUNTS = list(_pathmap.get().roots)

# Dashboard integration: where semgrep.json / bandit.json land per project.
# Defaults derive from the mount point rather than one deployment's folder names;
# SAST_RESULTS_DIR / REPO_SRC_DIR override them.
SAST_RESULTS_DIR = os.environ.get(
    "SAST_RESULTS_DIR", os.path.join(MOUNT_POINT, "Security", "sast-results"))
# Root under which source repos live. RESOLA_SRC_DIR is the old name, still read
# so existing .env files keep working.
REPO_SRC_DIR = os.environ.get("REPO_SRC_DIR") or os.environ.get("RESOLA_SRC_DIR") or MOUNT_POINT
RESOLA_SRC_DIR = REPO_SRC_DIR  # backward-compatible alias

# The source-repo root is always a valid scan/staging root, even if MOUNT_POINT
# is left at its generic default. Without this, a reset .env (MOUNT_POINT back to
# /mnt/work) makes every local-repo scan fail "outside allowed mount roots".
for _extra in (REPO_SRC_DIR, SAST_RESULTS_DIR):
    _e = (_extra or "").rstrip("/")
    if _e and _e not in ALLOWED_MOUNTS:
        ALLOWED_MOUNTS.append(_e)

# CORS: allow the local dashboard (port 8787) to call this API from the browser
CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "http://localhost:8787,http://127.0.0.1:8787")

# Jobs
DEFAULT_OUTPUT_DIR = os.environ.get("DEFAULT_OUTPUT_DIR", "/var/sast-mcp/scan-results")
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", 10))
JOB_RETENTION_HOURS = int(os.environ.get("JOB_RETENTION_HOURS", 72))

# Parallel scanning
MAX_PARALLEL_SCANS = int(os.environ.get("MAX_PARALLEL_SCANS", 4))
SCAN_WAIT_TIMEOUT = int(os.environ.get("SCAN_WAIT_TIMEOUT", 1800))
USE_MULTIPROCESSING = os.environ.get("USE_MULTIPROCESSING", "1").lower() in ("1", "true", "yes", "y")
MAX_PROCESS_WORKERS = int(os.environ.get("MAX_PROCESS_WORKERS", max(4, multiprocessing.cpu_count() - 1)))
PROCESS_MEMORY_LIMIT_MB = int(os.environ.get("PROCESS_MEMORY_LIMIT_MB", 2048))
# Hard memory cap (RSS) for each scan subprocess, enforced via a systemd-run
# transient cgroup scope when available. A runaway tool (e.g. gosec loading a
# huge generated package) is OOM-killed at this cap in isolation instead of
# dragging the whole host into swap-death. Independent of the Flask-process
# health threshold above. Set to 0 to disable the cap entirely.
SCAN_MEMORY_MAX_MB = int(os.environ.get("SCAN_MEMORY_MAX_MB", 3072))
# "auto" (default): use systemd-run only if a startup probe proves it works in
# this environment. "1"/"0": force enable/disable (enable still requires
# systemd-run to be usable, else it silently falls back to unwrapped).
SCAN_MEMORY_LIMIT_MODE = os.environ.get("SCAN_MEMORY_LIMIT_MODE", "auto").lower()
MAX_RETRY_ATTEMPTS = int(os.environ.get("MAX_RETRY_ATTEMPTS", 2))
RETRY_BACKOFF_BASE = float(os.environ.get("RETRY_BACKOFF_BASE", 2.0))

# Repo-scan tool matrix: how many independent scanners (semgrep, bandit,
# nodejsscan, gitleaks, trivy, ...) run concurrently WITHIN one /api/repo-scan
# call. They write separate report files and don't depend on each other, so this
# is a safe parallelism win; the ceiling is host CPU/RAM, so keep it
# <= MAX_PROCESS_WORKERS. 1 = legacy sequential behavior.
REPO_SCAN_TOOL_CONCURRENCY = int(os.environ.get("REPO_SCAN_TOOL_CONCURRENCY", min(4, MAX_PROCESS_WORKERS)))

# Total CPU budget for one /api/repo-scan call. The tool matrix is scheduled by
# WEIGHT, not headcount: semgrep with --jobs 8 counts as 8, gitleaks as 1. The
# runner keeps the sum of in-flight weights under this number, so many cheap
# tools can run alongside one expensive one without oversubscribing the host.
# 0 = auto (cpu_count). Lower this when several repos are scanned concurrently.
REPO_SCAN_CPU_BUDGET = int(os.environ.get("REPO_SCAN_CPU_BUDGET", 0))

# Native scanner (opengrep/semgrep) per-invocation footprint. Each scan uses
# OPENGREP_JOBS worker threads at OPENGREP_MAX_MEMORY_MB each. When running many
# scans in parallel, LOWER OPENGREP_JOBS so they don't oversubscribe the host
# cores (e.g. OPENGREP_JOBS=2). OPENGREP_JOBS=0 -> auto-size from cores/memory
# (the legacy behavior).
OPENGREP_JOBS = int(os.environ.get("OPENGREP_JOBS", 0))
OPENGREP_MAX_MEMORY_MB = int(os.environ.get("OPENGREP_MAX_MEMORY_MB", 512))

# Sync vs background
FORCE_SYNC_SCANS = os.environ.get("FORCE_SYNC_SCANS", "1").lower() in ("1", "true", "yes", "y")

# Pagination
DEFAULT_PAGE_SIZE = int(os.environ.get("DEFAULT_PAGE_SIZE", 20))
MAX_PAGE_SIZE = int(os.environ.get("MAX_PAGE_SIZE", 100))
SYNC_RESPONSE_INCLUDE_FINDINGS = os.environ.get("SYNC_RESPONSE_INCLUDE_FINDINGS", "0").lower() in ("1", "true", "yes", "y")
SYNC_RESPONSE_MAX_FINDINGS = int(os.environ.get("SYNC_RESPONSE_MAX_FINDINGS", 10))

# Validation
ENABLE_RESULT_VALIDATION = os.environ.get("ENABLE_RESULT_VALIDATION", "1").lower() in ("1", "true", "yes", "y")
ENABLE_CHECKSUM_VERIFICATION = os.environ.get("ENABLE_CHECKSUM_VERIFICATION", "1").lower() in ("1", "true", "yes", "y")
MIN_RESULT_SIZE_BYTES = int(os.environ.get("MIN_RESULT_SIZE_BYTES", 10))
