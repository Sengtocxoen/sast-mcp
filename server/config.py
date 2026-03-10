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
MAX_RETRY_ATTEMPTS = int(os.environ.get("MAX_RETRY_ATTEMPTS", 2))
RETRY_BACKOFF_BASE = float(os.environ.get("RETRY_BACKOFF_BASE", 2.0))

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
