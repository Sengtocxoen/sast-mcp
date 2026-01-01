# Kali Linux + Windows VMware Setup Guide

This guide explains how to set up SAST-MCP when:
- **Windows PC** has a folder `F:/work/` containing your projects
- **Kali Linux VM** (running in VMware on the same PC) acts as the scanning backend
- The Windows folder is mounted in Kali as `/mnt/work`

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│  Windows PC (Host)                                          │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  F:/work/                                            │   │
│  │  ├── MyProject/                                      │   │
│  │  ├── scan-results/                                   │   │
│  │  └── sast-mcp/                                       │   │
│  └──────────────────────────────────────────────────────┘   │
│                      │                                       │
│                      │ VMware Shared Folder                  │
│                      ▼                                       │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Kali Linux VM                                       │   │
│  │  ┌────────────────────────────────────────────────┐  │   │
│  │  │  /mnt/work/  (mounted from F:/work/)          │  │   │
│  │  │  ├── MyProject/                                │  │   │
│  │  │  ├── scan-results/                             │  │   │
│  │  │  └── sast-mcp/                                 │  │   │
│  │  └────────────────────────────────────────────────┘  │   │
│  │                                                       │   │
│  │  SAST-MCP Backend Server Running                     │   │
│  │  - Scans: /mnt/work/MyProject/                       │   │
│  │  - Outputs: /mnt/work/scan-results/                  │   │
│  │                                                       │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Key Concept

The Kali VM acts as your **scanning engine**:
- Projects to scan are in `/mnt/work/` (which maps to Windows `F:/work/`)
- Security tools (Semgrep, Bandit, etc.) run on Kali
- Scan results are saved to `/mnt/work/scan-results/` (which maps to Windows `F:/work/scan-results/`)
- You can access results from both Kali and Windows since they're on the shared folder

## Setup Instructions

### 1. Configure VMware Shared Folder

In VMware, share the Windows folder with Kali:

1. Go to **VM Settings** > **Options** > **Shared Folders**
2. Enable **Always enabled**
3. Add a shared folder:
   - **Host path**: `F:\work`
   - **Name**: `work`
4. In Kali, mount the shared folder:
   ```bash
   sudo mkdir -p /mnt/work
   sudo vmhgfs-fuse .host:/work /mnt/work -o allow_other -o uid=1000
   ```

5. Make it permanent by adding to `/etc/fstab`:
   ```bash
   echo ".host:/work /mnt/work fuse.vmhgfs-fuse allow_other,uid=1000 0 0" | sudo tee -a /etc/fstab
   ```

### 2. Configure SAST-MCP Server

On Kali Linux:

1. Create `.env` file:
   ```bash
   cd /mnt/work/sast-mcp  # or wherever you cloned the repo
   cp .env.example .env
   ```

2. Edit `.env` to ensure these settings:
   ```bash
   # Path mapping configuration
   MOUNT_POINT=/mnt/work
   WINDOWS_BASE=F:/work

   # Output directory (will be accessible from Windows)
   DEFAULT_OUTPUT_DIR=/mnt/work/scan-results
   ```

3. Start the server:
   ```bash
   python3 server/sast_server.py --port 6000
   ```

### 3. Verify Path Resolution

Test that paths are being resolved correctly:

```bash
# Run the test script
python3 test_path_resolution.py
```

Expected output: All tests should pass ✓

### 4. Test Scanning

From Claude Code (on Windows), you can now run scans like:

```
@sast_tools

Run a Bandit scan on F:/work/MyProject
```

The backend will:
1. Receive: `F:/work/MyProject`
2. Resolve to: `/mnt/work/MyProject`
3. Scan the project using Bandit on Kali
4. Save results to `/mnt/work/scan-results/`
5. You can access results from Windows at `F:/work/scan-results/`

## Path Mapping Examples

| Windows Path (Input)                    | Kali Path (Resolved)                  |
|-----------------------------------------|---------------------------------------|
| `F:/work/MyProject/app.py`              | `/mnt/work/MyProject/app.py`          |
| `F:\work\backend\requirements.txt`      | `/mnt/work/backend/requirements.txt`  |
| `F:/work/scan-results/output.json`      | `/mnt/work/scan-results/output.json`  |
| `f:/work/project/file.txt`              | `/mnt/work/project/file.txt`          |

## Troubleshooting

### Paths Not Resolving

**Problem**: Scans fail with "path not found"

**Solution**:
1. Verify mount is working:
   ```bash
   ls /mnt/work
   ```
2. Check `.env` configuration matches your setup
3. Verify WINDOWS_BASE and MOUNT_POINT settings

### Permission Issues

**Problem**: "Permission denied" errors

**Solution**:
1. Ensure shared folder has correct permissions in VMware settings
2. Mount with `allow_other` and correct `uid`:
   ```bash
   sudo vmhgfs-fuse .host:/work /mnt/work -o allow_other -o uid=1000
   ```

### Mount Not Persistent

**Problem**: Mount disappears after reboot

**Solution**:
Add to `/etc/fstab`:
```bash
.host:/work /mnt/work fuse.vmhgfs-fuse allow_other,uid=1000 0 0
```

## Benefits of This Setup

1. **Best of Both Worlds**: Use Windows for development, Kali for security scanning
2. **Shared Storage**: Results accessible from both systems
3. **Resource Isolation**: Heavy scans don't impact your Windows desktop
4. **Security Tools**: Access to all Kali's pre-installed security tools
5. **Easy Workflow**: Scan Windows projects without moving files

## Advanced Configuration

### Custom Output Directory

To save results to a different location:

```bash
# In .env
DEFAULT_OUTPUT_DIR=/mnt/work/my-custom-results
```

### Scanning Different Drives

If you have multiple Windows drives:

```bash
# For D: drive
MOUNT_POINT=/mnt/d_drive
WINDOWS_BASE=D:/projects
```

### Network Access

To access the server from another machine on your network:

1. Find Kali's IP:
   ```bash
   ip addr show
   ```

2. Configure firewall:
   ```bash
   sudo ufw allow 6000/tcp
   ```

3. Update `.claude.json` with Kali's IP address
