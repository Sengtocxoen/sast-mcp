# CPU-Aware SAST Scanning - Quick Start

## Overview

Enhanced SAST scanning with **intelligent resource monitoring** that automatically adjusts batch size based on server capacity.

## Quick Start

### Prerequisites

```bash
pip install psutil requests
```

### Basic Usage

```bash
# Run with adaptive batching (recommended)
python weekly_sast_scan.py

# Disable adaptive batching
python weekly_sast_scan.py --no-adaptive

# Scan single project
python weekly_sast_scan.py --project mp-api

# Test resource monitoring
python test_resource_monitor.py
```

## How It Works

The scanner now:
1. **Checks server capacity** before each batch
2. **Adjusts batch size** (1-6 scans) based on:
   - Available scan slots
   - Server CPU % (reduces if > 80%)
   - Server memory % (reduces if > 85%)
3. **Tracks PIDs** from completed scans
4. **Uses adaptive polling** (5-15s based on load)

## Benefits

✅ **Better Throughput** - Uses max capacity when idle  
✅ **System Protection** - Backs off when overloaded  
✅ **Resource Visibility** - See real-time CPU/memory stats  
✅ **Automatic Adaptation** - No manual tuning needed

## Configuration

### Batch Size Limits

Edit `weekly_sast_scan.py`:

```python
MIN_BATCH_SIZE = 1      # Minimum (when overloaded)
MAX_BATCH_SIZE = 6      # Maximum (when idle)
DEFAULT_BATCH_SIZE = 3  # Fallback
```

### Resource Thresholds

Edit `resource_monitor.py`:

```python
CPU_THRESHOLD_HIGH = 80.0      # Reduce batch if CPU > 80%
MEMORY_THRESHOLD_HIGH = 85.0   # Reduce batch if Memory > 85%
```

## Output Example

```
🧠 Mode: Adaptive batching (CPU-aware, batch size 1-6)

[1/28] Deca/mp-api
================================================================================
  📊 Server: 2/4 scans active | CPU: 45.2% | Memory: 38.5%

🔄 Batch 1: Running 2 tool(s)
  🧠 Adaptive: Batch size 2: 2 slots available
  ✅ Completed: Semgrep: mp-api (PID: 67890, 42.3s)
  ✅ Completed: Bandit: mp-api (PID: 67891, 15.7s)
```

## Files

| File | Purpose |
|------|---------|
| `weekly_sast_scan.py` | Main scanner with adaptive batching |
| `resource_monitor.py` | CPU/memory monitoring & batch calculations |
| `test_resource_monitor.py` | Test utility |

## Troubleshooting

**Error: `ModuleNotFoundError: No module named 'psutil'`**
```bash
pip install psutil
```

**Server stats unavailable**
- Falls back to static batching automatically
- Check server is running: `curl http://192.168.204.160:6000/health`

**Batch size always 1**
- Server might be overloaded
- Check server stats: `curl http://192.168.204.160:6000/api/scan/statistics`
- Consider increasing thresholds in `resource_monitor.py`

## See Also

- **Full Guide**: `WEEKLY_SAST_GUIDE.md`
- **Implementation Plan**: See artifacts directory
- **Server Docs**: `server/MULTIPROCESS_BACKEND.md`
