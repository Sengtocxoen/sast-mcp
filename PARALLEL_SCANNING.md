# Parallel Scanning and Project Analysis Features

This document describes the new parallel scanning and project analysis features added to SAST-MCP.

## Features

### 1. Deep Project Structure Scanning

The client can now deeply scan project folders to find dependency files and packages, making scans more accurate.

**Client Tool: `scan_project_structure`**

Scans a project directory to detect:
- Project types (Python, Node.js, Go, Ruby, Java, PHP, Rust, .NET, Terraform, Docker, Kubernetes)
- Dependency files (requirements.txt, package.json, go.mod, Gemfile, pom.xml, etc.)
- Configuration files (.env, config files, etc.)
- Scan tool recommendations based on detected project types

**Example Usage:**
```python
# Scan current directory
result = scan_project_structure(".")

# Deep scan with hidden files
result = scan_project_structure("/path/to/project", deep_scan=True, include_hidden=True)
```

**Response includes:**
- `detected_types`: List of detected project types
- `found_files`: Dictionary of dependency files by project type
- `scan_recommendations`: Recommended SAST tools and commands for each project type
- `scan_statistics`: Summary of findings

### 2. Serial Scan Queue (One at a Time)

The server now processes scans **one at a time** to ensure accuracy, prevent resource exhaustion, and provide proper queuing when multiple scan requests are made.

**Configuration:**
- `MAX_PARALLEL_SCANS=1` (default) - Serial execution (one scan at a time)
- `SCAN_WAIT_TIMEOUT=1800` (default) - Wait timeout in seconds (30 minutes)

**How it works:**
1. Each scan job requests a "scan slot" from a semaphore
2. Only 1 scan can run at a time (serial execution)
3. If the slot is busy, new scans wait in queue for up to 30 minutes
4. After 30 minutes, if no slot is available, the scan fails with a timeout error
5. When a scan completes, it releases its slot for the next waiting scan in the queue

**Note:** You can increase `MAX_PARALLEL_SCANS` to allow parallel execution, but the default is 1 to prevent multiple processes from running simultaneously when Claude makes multiple scan requests.

**Client Tool: `get_scan_statistics`**

Check current scan status:
```python
stats = get_scan_statistics()
```

**Response includes:**
- `max_parallel_scans`: Maximum allowed (1 by default, configurable)
- `active_scans`: Currently running scans
- `queued_scans`: Scans waiting for slots
- `completed_scans`: Total completed
- `failed_scans`: Total failed
- `slots_available`: Available scan slots (0 or 1 for serial execution)

### 3. Wait Mechanism (30 Minutes)

When all scan slots are busy, the system:
1. **Queues the scan** - Job enters waiting state
2. **Waits for availability** - Up to 30 minutes (configurable)
3. **Executes when ready** - Starts scan when slot becomes available
4. **Fails gracefully** - Returns timeout error if no slot available after 30 minutes

**Benefits:**
- **Serial Execution**: Processes one scan at a time to ensure each scan gets full system resources
- **Fair Queuing**: First-come, first-served slot allocation
- **Graceful Handling**: Clear timeout errors instead of indefinite waits
- **Resource Management**: Prevents multiple processes from running simultaneously
- **Predictable Performance**: Each scan runs with full CPU/memory availability

## Environment Variables

```bash
# Serial scan queue configuration
MAX_PARALLEL_SCANS=1           # Max concurrent scans (default: 1 for serial execution)
SCAN_WAIT_TIMEOUT=1800         # Wait timeout in seconds (default: 1800 = 30 min)

# Background job configuration (existing)
MAX_WORKERS=10                 # Max background job threads (default: 10)
DEFAULT_OUTPUT_DIR=/var/sast-mcp/scan-results
JOB_RETENTION_HOURS=72
```

## API Endpoints

### POST /api/util/scan-project-structure
Deeply scan project structure to find dependency files.

**Request:**
```json
{
  "project_path": "/path/to/project",
  "deep_scan": true,
  "include_hidden": false
}
```

**Response:**
```json
{
  "success": true,
  "detected_types": ["python", "nodejs", "docker"],
  "found_files": {
    "python": ["requirements.txt", "setup.py"],
    "nodejs": ["package.json", "package-lock.json"],
    "docker": ["Dockerfile", "docker-compose.yml"]
  },
  "scan_recommendations": {
    "python": {
      "tools": ["bandit", "safety"],
      "targets": ["requirements.txt"],
      "commands": ["bandit -r /path/to/project", "safety check -r /path/to/project/requirements.txt"]
    },
    "nodejs": {
      "tools": ["npm-audit", "eslint-security"],
      "targets": ["package.json"],
      "commands": ["npm audit --json", "eslint /path/to/project"]
    }
  },
  "scan_statistics": {
    "total_dependency_files": 5,
    "project_types_detected": 3,
    "recommended_tools": ["bandit", "safety", "npm-audit", "eslint-security", "trivy", "checkov"]
  }
}
```

### GET /api/util/scan-stats
Get current parallel scan statistics.

**Response:**
```json
{
  "success": true,
  "max_parallel_scans": 1,
  "scan_wait_timeout_seconds": 1800,
  "statistics": {
    "active_scans": 1,
    "total_scans": 15,
    "queued_scans": 2,
    "completed_scans": 12,
    "failed_scans": 0
  },
  "slots_available": 0
}
```

## Workflow Example

### 1. Scan project structure first
```python
# Discover project dependencies and get scan recommendations
project_info = scan_project_structure("/path/to/project")

# Review detected types and recommended tools
print(f"Detected: {project_info['detected_types']}")
print(f"Recommended tools: {project_info['scan_statistics']['recommended_tools']}")
```

### 2. Run scans based on recommendations
```python
# For Python project
if "python" in project_info['detected_types']:
    # Run bandit scan
    bandit_result = bandit_scan(target="/path/to/project", format="json")

    # Check for requirements.txt
    if any("requirements.txt" in f for f in project_info['found_files'].get('python', [])):
        safety_result = safety_check(requirements_file="/path/to/project/requirements.txt")

# For Node.js project
if "nodejs" in project_info['detected_types']:
    npm_result = npm_audit(target="/path/to/project")
    eslint_result = eslint_security_scan(target="/path/to/project")
```

### 3. Monitor scan progress
```python
# Check scan statistics
stats = get_scan_statistics()
print(f"Active scans: {stats['statistics']['active_scans']}/{stats['max_parallel_scans']}")
print(f"Available slots: {stats['slots_available']}")
print(f"Queued scans: {stats['statistics']['queued_scans']}")
print(f"Note: With serial execution (max=1), only 1 scan runs at a time")
```

## Benefits

### Improved Scan Accuracy
1. **Dependency Detection**: Automatically finds all dependency files
2. **Context-Aware Scanning**: Recommends appropriate tools for each project type
3. **Comprehensive Coverage**: Scans all relevant files and directories

### Resource Management
1. **Serial Execution**: One scan at a time prevents resource exhaustion and process overload
2. **Fair Queuing**: First-come, first-served ensures fairness
3. **Graceful Timeouts**: 30-minute wait prevents indefinite hangs
4. **No Process Flooding**: Prevents multiple subprocess executions when Claude makes multiple requests

### Better User Experience
1. **Smart Recommendations**: Suggests the right tools automatically
2. **Progress Visibility**: Real-time scan statistics
3. **Clear Error Messages**: Timeout errors explain exactly what happened

## Migration Notes

### Backward Compatibility
- All existing scan tools continue to work
- Background scanning is still enabled by default
- No breaking changes to existing API

### New Behavior
- Scans now execute serially (one at a time by default)
- Scans wait in queue if a scan is already running
- Scans may wait up to 30 minutes if the slot is busy
- Job failures now include timeout information
- Prevents multiple processes from running when Claude makes multiple scan requests

## Troubleshooting

### "Timeout waiting for scan slot"
**Problem**: The scan slot was busy for 30+ minutes (another scan is taking too long)
**Solutions**:
1. Increase `SCAN_WAIT_TIMEOUT` (e.g., 3600 for 1 hour)
2. Increase `MAX_PARALLEL_SCANS` to allow parallel execution (e.g., 2 or 3)
3. Check for stuck scans using `get_scan_statistics()`
4. Review server logs for long-running scans
5. Consider optimizing scan targets to reduce scan time

### Scans queuing too long
**Problem**: Many scans waiting for the single slot
**Solutions**:
1. Increase `MAX_PARALLEL_SCANS` to allow some parallel execution (e.g., 2 or 3)
   - Trade-off: May cause resource contention and process flooding
2. Optimize scan targets (use project structure scan to focus on relevant files)
3. Increase server resources (CPU/memory) if enabling parallel scans
4. Break large scans into smaller, focused scans

### Project structure scan not finding files
**Problem**: Missing dependency files in scan results
**Solutions**:
1. Set `deep_scan=True` to search subdirectories
2. Set `include_hidden=True` to scan hidden directories
3. Check file permissions on the project directory
4. Verify the project path is correct and accessible

## Performance Tuning

### Default Configuration (Recommended)
```bash
MAX_PARALLEL_SCANS=1           # Serial execution - prevents process flooding
SCAN_WAIT_TIMEOUT=1800         # 30 minutes
MAX_WORKERS=10
```

### For Small Projects (<1000 files) - Allow Some Parallelism
```bash
MAX_PARALLEL_SCANS=2           # Allow 2 concurrent scans
SCAN_WAIT_TIMEOUT=1800
```

### For Large Projects (>10000 files) - Keep Serial
```bash
MAX_PARALLEL_SCANS=1           # Keep serial to prevent resource exhaustion
SCAN_WAIT_TIMEOUT=3600         # Increase timeout to 1 hour
```

### For High-Volume Scanning - Controlled Parallelism
```bash
MAX_PARALLEL_SCANS=2           # Limited parallelism
MAX_WORKERS=20                 # More job slots
SCAN_WAIT_TIMEOUT=2400         # 40 minutes
```

**Important**: Increasing `MAX_PARALLEL_SCANS` above 1 may cause multiple processes to run simultaneously, which was the original issue. Only increase if you have sufficient resources and understand the trade-offs.
