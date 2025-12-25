# Async Scanning Implementation

## Overview

All SAST MCP scan tools have been upgraded to use **async/await** for better performance and **maximum accuracy mode** by default for the most thorough security scanning possible.

## Key Changes

### 1. Async/Await Implementation

- **All scan tools are now asynchronous** using Python's `async`/`await` syntax
- Uses `aiohttp` instead of `requests` for non-blocking HTTP calls
- Better performance when running multiple scans
- Improved resource utilization

### 2. Maximum Accuracy Mode

All scan tools now include a `max_accuracy` parameter (default: `True`) that enables:

- **Semgrep**: Unlimited memory, no timeouts, no file size limits
  - Flags: `--max-memory 0 --timeout 0 --max-target-bytes 0`

- **Bandit**: Verbose output for comprehensive results
  - Flags: `--verbose`

- **Gosec**: Verbose text output for detailed analysis
  - Flags: `-verbose=text`

- **Brakeman**: Interprocedural analysis for deep inspection
  - Flags: `--interprocedural`

- **ESLint**: Report all warnings and unused directives
  - Flags: `--report-unused-disable-directives --max-warnings 0`

- **Bearer**: Full output with all checks enabled
  - Flags: `--skip-path= --disable-default-rules=false`

### 3. Performance vs Accuracy Trade-off

By default, all tools prioritize **accuracy over speed**:

- ✅ **Maximum thoroughness** - No shortcuts or quick scans
- ✅ **Complete coverage** - Scans all files and patterns
- ✅ **Detailed output** - Verbose reporting for better analysis
- ⏱️ **Slower execution** - Takes more time but finds more issues

**To use fast mode** (if needed):
```python
# Set max_accuracy=False for faster but less thorough scans
result = await semgrep_scan(target=".", max_accuracy=False)
```

## Technical Details

### Async Client Architecture

```python
class SASTToolsClient:
    - Uses aiohttp.ClientSession for connection pooling
    - Automatic session management and cleanup
    - Non-blocking HTTP requests
    - Configurable timeouts (default: 600 seconds)
```

### Tool Function Pattern

All scan tools now follow this pattern:

```python
@mcp.tool()
async def tool_name_scan(
    target: str = ".",
    # ... other parameters ...
    max_accuracy: bool = True,
    additional_args: str = ""
) -> Dict[str, Any]:
    # Add accuracy flags if enabled
    accuracy_flags = ""
    if max_accuracy:
        accuracy_flags = " --flag1 --flag2"

    combined_args = f"{accuracy_flags} {additional_args}".strip()

    # Async HTTP call
    return await sast_client.safe_post("api/endpoint", data)
```

## Benefits

1. **Better Performance**: Non-blocking I/O allows concurrent scanning
2. **More Accurate**: Maximum accuracy mode finds more security issues
3. **Resource Efficient**: Async operations use system resources better
4. **Scalable**: Can handle more concurrent scans without blocking

## Migration Notes

### For Users

- **No changes required** - Tools work the same way
- Scans now run asynchronously under the hood
- Results are more comprehensive by default
- Scans may take longer but will be more thorough

### For Developers

- All tool functions are now `async`
- Must use `await` when calling tools
- Session management is handled automatically
- Health checks are async

## Examples

### Basic Async Scan
```python
# Comprehensive scan with maximum accuracy (default)
result = await semgrep_scan(
    target="/path/to/code",
    config="p/security-audit"
)
```

### Fast Scan (Lower Accuracy)
```python
# Faster scan with max_accuracy disabled
result = await semgrep_scan(
    target="/path/to/code",
    config="p/security-audit",
    max_accuracy=False
)
```

### Multiple Concurrent Scans
```python
import asyncio

# Run multiple scans concurrently
results = await asyncio.gather(
    semgrep_scan(target="./backend"),
    bandit_scan(target="./backend"),
    trufflehog_scan(target="./backend")
)
```

## Dependencies

New dependency added:
- `aiohttp` - Async HTTP client library

Install with:
```bash
pip install aiohttp
```

## Future Enhancements

- [ ] Progress callbacks for long-running scans
- [ ] Configurable accuracy levels (fast/balanced/thorough)
- [ ] Parallel scan orchestration
- [ ] Streaming results for large scans
- [ ] Automatic retry with exponential backoff

## Summary

This update transforms the SAST MCP client into a high-performance, accuracy-focused security scanning platform. While scans may take longer, they will be significantly more thorough and comprehensive, ensuring maximum security coverage for your codebase.

**Default Behavior**: Slow and accurate - because security is worth the wait! 🔒
