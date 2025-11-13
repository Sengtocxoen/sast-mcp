# Troubleshooting Guide

Common issues and solutions for SAST-MCP installation and operation.

## Installation Issues

### Script Stuck on Semgrep Installation

**Problem:** Installation hangs at Semgrep or shows pip timeout errors.

**Solutions:**
```bash
# Try installing with increased timeout
pip3 install --timeout=120 semgrep

# Or use alternative mirror
pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple semgrep

# Or install system-wide
sudo pip3 install semgrep
```

### Gitleaks Download Fails

**Problem:** "Could not fetch latest version" or download URL returns 404.

**Solutions:**
```bash
# Method 1: Install via apt (Kali/Debian)
sudo apt update
sudo apt install gitleaks

# Method 2: Install via Go
go install github.com/gitleaks/gitleaks/v8@latest
sudo ln -s ~/go/bin/gitleaks /usr/local/bin/gitleaks

# Method 3: Manual download (check latest version)
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_x64.tar.gz
tar -xzf gitleaks_8.18.1_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/
```

### Bearer Installation Fails

**Problem:** "Bearer installation failed" or curl returns errors.

**Solutions:**
```bash
# Try alternative installation
curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | sudo sh

# Or skip Bearer (optional tool)
# The server will work without it
```

### OWASP Dependency-Check Download Issues

**Problem:** Version detection fails or download hangs.

**Solutions:**
```bash
# Manual installation with specific version
cd /opt
VERSION="9.0.9"  # Check https://github.com/jeremylong/DependencyCheck/releases
wget https://github.com/jeremylong/DependencyCheck/releases/download/v${VERSION}/dependency-check-${VERSION}-release.zip
unzip dependency-check-${VERSION}-release.zip
sudo ln -s /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/
```

### Trivy Repository Key Issues

**Problem:** "GPG error" or "public key is not available".

**Solutions:**
```bash
# Remove old Trivy repo
sudo rm /etc/apt/sources.list.d/trivy.list

# Add new repo with proper signing
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo gpg --dearmor -o /usr/share/keyrings/trivy.gpg
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt update
sudo apt install trivy
```

### Go Tools Not Found (Gosec, tfsec)

**Problem:** Tools installed but not found in PATH.

**Solutions:**
```bash
# Add Go bin to PATH
echo 'export PATH=$PATH:/root/go/bin' >> ~/.bashrc
source ~/.bashrc

# Or create symlinks
sudo ln -s /root/go/bin/gosec /usr/local/bin/gosec
sudo ln -s /root/go/bin/tfsec /usr/local/bin/tfsec
```

### ClamAV Update Fails

**Problem:** "freshclam update failed" or database errors.

**Solutions:**
```bash
# Stop freshclam service
sudo systemctl stop clamav-freshclam

# Update manually
sudo freshclam

# Start service again
sudo systemctl start clamav-freshclam

# If still fails, check mirror
sudo nano /etc/clamav/freshclam.conf
# Comment out DatabaseMirror line and try again
```

## Runtime Issues

### Server Won't Start - Port Already in Use

**Problem:** `Address already in use` error on port 6000.

**Solutions:**
```bash
# Check what's using the port
sudo netstat -tlnp | grep 6000
sudo lsof -i :6000

# Kill the process
sudo kill -9 <PID>

# Or use different port
python3 sast_server.py --port 6001
```

### Tool Timeout Errors

**Problem:** Scans timeout before completing.

**Solutions:**
```bash
# Edit .env file
nano .env

# Increase timeout for specific tool
NMAP_TIMEOUT=14400    # 4 hours
SEMGREP_TIMEOUT=7200  # 2 hours
MAX_TIMEOUT=86400     # 24 hours

# Or pass as environment variable
export NMAP_TIMEOUT=14400
python3 sast_server.py --port 6000
```

### Windows Path Not Resolving

**Problem:** "No such file or directory" for F:/ paths.

**Solutions:**
```bash
# Check your mount point
df -h | grep mnt

# Update .env with correct mount
MOUNT_POINT=/mnt/f
WINDOWS_BASE=F:/

# Or in WSL
MOUNT_POINT=/mnt/f
WINDOWS_BASE=F:/

# Verify mount
ls /mnt/f/work
```

### MCP Client Connection Refused

**Problem:** "Connection refused" when Claude tries to connect.

**Solutions:**
```bash
# Check server is running
curl http://localhost:6000/health

# Check firewall
sudo ufw allow 6000/tcp

# If remote connection, check IP binding
# Server should bind to 0.0.0.0 (check sast_server.py line with app.run)

# Test from Windows
curl http://<kali-ip>:6000/health
```

### Tool Returns "Command Not Found"

**Problem:** Server says tool is not available.

**Solutions:**
```bash
# Verify tool is installed
which semgrep
which nmap

# Check PATH
echo $PATH

# Reinstall specific tool
sudo bash install_tools.sh

# Or install manually (example for semgrep)
pip3 install semgrep

# Check server health endpoint
curl http://localhost:6000/health | jq .tools_status
```

### Scan Results Too Large / Token Limit

**Problem:** Results exceed token limit or memory issues.

**Solutions:**
```bash
# Use output_file parameter to save to disk
# Example via Claude:
@sast_tools
Run Semgrep on F:/work/project and save results to F:/work/semgrep-results.json

# Results will be in file, less returned to Claude
```

## Network Issues

### Slow Download During Installation

**Solutions:**
```bash
# Use faster DNS
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf

# Use apt mirror closer to you
sudo nano /etc/apt/sources.list
# Change to your country's mirror

# Retry installation
sudo bash install_tools.sh
```

### SSL Certificate Errors

**Problem:** Certificate verification failed during downloads.

**Solutions:**
```bash
# Update ca-certificates
sudo apt update
sudo apt install ca-certificates
sudo update-ca-certificates

# If behind corporate proxy
export http_proxy=http://proxy.company.com:8080
export https_proxy=http://proxy.company.com:8080
```

## Permission Issues

### Permission Denied Errors

**Problem:** Tools can't access files or directories.

**Solutions:**
```bash
# Run server as root (for system scans)
sudo python3 sast_server.py --port 6000

# Or fix file permissions
sudo chmod -R 755 /path/to/project

# Check mount permissions (WSL)
sudo mount -o remount,uid=1000,gid=1000 /mnt/f
```

## Getting Help

If issues persist:

1. **Check Logs:**
   ```bash
   # Server logs
   python3 sast_server.py --debug
   ```

2. **Test Individual Tools:**
   ```bash
   # Test tool directly
   semgrep --version
   nmap --version
   ```

3. **Health Check:**
   ```bash
   curl http://localhost:6000/health | jq
   ```

4. **Report Issue:**
   - GitHub: https://github.com/anthropics/claude-code/issues
   - Include: OS version, error messages, output of health check

## Quick Fixes

### Complete Reset

```bash
# Stop server
sudo pkill -f sast_server.py

# Remove all installed tools
sudo apt remove semgrep bandit nikto nmap sqlmap wpscan dirb lynis trivy
sudo pip3 uninstall -y semgrep bandit safety checkov truffleHog
sudo rm -rf /opt/dependency-check /opt/graudit

# Reinstall
sudo bash install_tools.sh
```

### Minimal Installation

If full installation fails, install only essential tools:

```bash
# Core SAST
sudo pip3 install semgrep bandit

# Secrets
sudo pip3 install truffleHog
sudo apt install gitleaks

# Kali basics
sudo apt install nmap nikto

# Dependencies
sudo pip3 install flask python-dotenv requests mcp
```

This gives you a working baseline. Add other tools manually as needed.
