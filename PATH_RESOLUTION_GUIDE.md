# Path Resolution Guide for MCP SAST Server

## Summary

I've added the `resolve_windows_path()` function to your `sast_server.py` file at **lines 65-114**.

The path resolver is now integrated into your code, but you need to **update each endpoint** to use it.

---

## What Was Added

### 1. Configuration Variables (Lines 55-57)

```python
# Path resolution configuration
MOUNT_POINT = os.environ.get("MOUNT_POINT", "/mnt/work")
WINDOWS_BASE = os.environ.get("WINDOWS_BASE", "F:/work/Resola/Deca")
```

### 2. Path Resolution Function (Lines 65-114)

```python
def resolve_windows_path(windows_path: str) -> str:
    """
    Convert Windows path to Linux mount path

    Examples:
        F:/work/Resola/Deca/deca-chatbox-api -> /mnt/work/deca-chatbox-api
        F:\\work\\Resola\\Deca\\deca-chatbox-api -> /mnt/work/deca-chatbox-api
    """
    # ... (full implementation in your file)
```

### 3. Mount Verification Function (Lines 117-157)

```python
def verify_mount() -> Dict[str, Any]:
    """
    Verify that the Windows share is mounted and accessible
    """
    # ... (full implementation in your file)
```

---

## How to Use It in Endpoints

For **EVERY endpoint** that accepts a `target` parameter, you need to add this line:

### Before (Current Code - Line 119):
```python
target = params.get("target", ".")
```

### After (What You Need to Add - Line 126):
```python
target = params.get("target", ".")

# Resolve Windows path to Linux mount path
resolved_target = resolve_windows_path(target)
```

### Then Update the Command (Line 139):
```python
# OLD:
command += f" {target}"

# NEW:
command += f" {resolved_target}"
```

### And Add to Result (After line 141):
```python
result = execute_command(command, timeout=600)

# Add path resolution info to result
result["original_path"] = target
result["resolved_path"] = resolved_target
```

---

## Example: Updating Semgrep Endpoint

Here's the complete pattern for the Semgrep endpoint (starting at line 104):

```python
@app.route("/api/sast/semgrep", methods=["POST"])
def semgrep():
    try:
        params = request.json
        target = params.get("target", ".")  # Line 119
        config = params.get("config", "auto")
        # ... other params ...

        # ⭐ ADD THIS: Resolve Windows path
        resolved_target = resolve_windows_path(target)

        command = f"semgrep --config={config}"
        # ... build command ...

        # ⭐ CHANGE THIS: Use resolved_target instead of target
        command += f" {resolved_target}"  # Instead of: command += f" {target}"

        result = execute_command(command, timeout=600)

        # ⭐ ADD THIS: Include path info in result
        result["original_path"] = target
        result["resolved_path"] = resolved_target

        # ... rest of the function ...
        return jsonify(result)
```

---

## Endpoints That Need Updating

You need to update ALL these endpoints (17 total):

### SAST Tools:
1. ✅ `semgrep()` - Line 104 **(I showed the pattern above)**
2. ⏸️ `bearer()` - Line 157
3. ⏸️ `graudit()` - Line 210
4. ⏸️ `bandit()` - Line 241
5. ⏸️ `gosec()` - Line 287
6. ⏸️ `brakeman()` - Line 335
7. ⏸️ `nodejsscan()` - Line 376
8. ⏸️ `eslint_security()` - Line 403

### Secret Scanning:
9. ⏸️ `trufflehog()` - Line 453
10. ⏸️ `gitleaks()` - Line 504

### Dependency Scanning:
11. ⏸️ `safety()` - Line 564
12. ⏸️ `npm_audit()` - Line 608 (uses `cwd` parameter)
13. ⏸️ `dependency_check()` - Line 657

### IaC Scanning:
14. ⏸️ `checkov()` - Line 717
15. ⏸️ `tfsec()` - Line 768
16. ⏸️ `trivy()` - Line 813

### Utility:
17. ⏸️ `generic_command()` - Line 865 (if needed)

---

## Special Case: npm_audit

The `npm_audit` endpoint uses `cwd` instead of directly in the command:

```python
@app.route("/api/dependencies/npm-audit", methods=["POST"])
def npm_audit():
    try:
        params = request.json
        target = params.get("target", ".")

        # ⭐ ADD THIS: Resolve path
        resolved_target = resolve_windows_path(target)

        command = "npm audit"
        # ... build command ...

        # ⭐ CHANGE THIS: Use resolved_target for cwd
        result = execute_command(command, cwd=resolved_target, timeout=180)

        # ⭐ ADD THIS: Include path info
        result["original_path"] = target
        result["resolved_path"] = resolved_target

        return jsonify(result)
```

---

## Quick Sed/Awk Script to Help

If you want to automate some of this, here's a helper script:

```bash
# This will show you where to make changes (run in Kali)
cd /path/to/MCP-SAST-Server

grep -n 'target = params.get("target"' sast_server.py
# This shows all lines where target is extracted
```

---

## Testing the Path Resolution

### 1. Test from Python directly:

```python
# In Kali terminal
python3 -c "
import sys
sys.path.insert(0, '/path/to/MCP-SAST-Server')
from sast_server import resolve_windows_path

# Test cases
print(resolve_windows_path('F:/work/Resola/Deca/deca-chatbox-api'))
print(resolve_windows_path('F:\\\\work\\\\Resola\\\\Deca\\\\deca-chatbox-api'))
print(resolve_windows_path('/mnt/work/deca-chatbox-api'))
"
```

### 2. Test the health endpoint:

```bash
curl http://localhost:6000/health
```

---

## Environment Variables

You can customize the paths using environment variables:

```bash
# In Kali, before starting the server:
export MOUNT_POINT="/mnt/my_custom_mount"
export WINDOWS_BASE="F:/different/path"

python3 sast_server.py
```

Or in the systemd service file:

```ini
[Service]
Environment="MOUNT_POINT=/mnt/work"
Environment="WINDOWS_BASE=F:/work/Resola/Deca"
ExecStart=/usr/bin/python3 /path/to/sast_server.py
```

---

## Next Steps

1. ✅ **Path resolver added** (Done!)
2. ⏸️ **Update all 17 endpoints** (Your next task)
3. ⏸️ **Setup VMware shared folder** (Follow the guide I gave you earlier)
4. ⏸️ **Test with one endpoint first** (Semgrep is a good start)
5. ⏸️ **Then update the rest**

---

## Quick Test After Updates

```bash
# From Windows (in Claude Code)
# This should now work:
mcp__sast_tools__semgrep_scan(target="F:/work/Resola/Deca/deca-chatbox-api")

# The MCP server will:
# 1. Receive: F:/work/Resola/Deca/deca-chatbox-api
# 2. Resolve to: /mnt/work/deca-chatbox-api
# 3. Run: semgrep --config=auto /mnt/work/deca-chatbox-api
# 4. Return results with both paths in the response
```

---

## Need Help?

If you get errors, check:

1. **Mount Point Exists**: `ls -la /mnt/work` (in Kali)
2. **VMware Shared Folder**: `vmware-hgfsclient` (should show "work")
3. **Permissions**: `ls -la /mnt/work` (should be readable)
4. **Path Resolution**: Check the logs in sast_server output

---

**Status**: Path resolver is integrated. Now you need to update each endpoint to use `resolve_windows_path(target)`.
