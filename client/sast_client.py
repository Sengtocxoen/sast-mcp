#!/usr/bin/env python3
"""
Distributed SAST Client - Windows Host
=======================================

Windows client that submits SAST scans to Kali Linux VM server.
Features Rich terminal UI with progress bars, job tracking, and server monitoring.

Usage:
    python sast_client.py --base-path F:\\work\\Resola
    python sast_client.py --project F:\\work\\Resola\\mp-api
    python sast_client.py --base-path F:\\work\\Resola --tools semgrep,bandit
    python sast_client.py --help

Author: Security Team  
Date: 2026-01-29
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datetime import datetime
import requests

# Rich UI components
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.panel import Panel
    from rich.live import Live
    from rich.layout import Layout
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("⚠️  Rich library not installed. Install with: pip install rich")
    print("⚠️  Falling back to basic console output...")

# Import configuration
try:
    from config import (
        SAST_SERVER_URL,
        HEALTH_CHECK_TIMEOUT,
        SUBMIT_TIMEOUT,
        POLL_INTERVAL,
        MAX_POLL_TIME,
        DEFAULT_TOOLS,
        EXCLUDE_DIRS,
        PROJECT_MARKERS,
        ENABLE_RICH_UI,
        SHOW_SERVER_STATS,
        get_tool_endpoint,
        get_tool_display_name,
        translate_path_to_linux,
        validate_windows_path
    )
except ImportError:
    print("❌ Error: config.py not found!")
    print("Make sure config.py is in the same directory as sast_client.py")
    sys.exit(1)

# Initialize Rich console
console = Console() if RICH_AVAILABLE and ENABLE_RICH_UI else None


# ============================================================================
# SERVER COMMUNICATION
# ============================================================================

def check_server_health() -> bool:
    """
    Check if SAST server is running and healthy.
    
    Returns:
        True if server is healthy, False otherwise
    """
    try:
        response = requests.get(
            f"{SAST_SERVER_URL}/health",
            timeout=HEALTH_CHECK_TIMEOUT
        )
        return response.status_code == 200
    except requests.RequestException as e:
        if console:
            console.print(f"[red]✗ Server health check failed: {e}[/red]")
        else:
            print(f"✗ Server health check failed: {e}")
        return False


def get_server_statistics() -> Optional[Dict]:
    """
    Get server statistics (CPU, memory, active scans).
    
    Returns:
        Dictionary with server stats or None if unavailable
    """
    try:
        response = requests.get(
            f"{SAST_SERVER_URL}/api/scan/statistics",
            timeout=HEALTH_CHECK_TIMEOUT
        )
        if response.status_code == 200:
            return response.json()
        return None
    except requests.RequestException:
        return None


def submit_scan(project_path: str, tool: str) -> Optional[str]:
    """
    Submit a scan job to the server.
    
    Args:
        project_path: Windows path to project (e.g., 'F:/work/Resola/mp-api')
        tool: Tool name (e.g., 'semgrep', 'bandit')
        
    Returns:
        Job ID if successful, None otherwise
    """
    try:
        endpoint = get_tool_endpoint(tool)
        
        payload = {
            "target": project_path,
            "background": True
        }
        
        response = requests.post(
            f"{SAST_SERVER_URL}/api/{endpoint}",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=SUBMIT_TIMEOUT
        )
        
        if response.status_code == 200:
            data = response.json()
            return data.get("job_id")
        else:
            if console:
                console.print(f"[red]✗ Scan submission failed: HTTP {response.status_code}[/red]")
            else:
                print(f"✗ Scan submission failed: HTTP {response.status_code}")
            return None
            
    except requests.RequestException as e:
        if console:
            console.print(f"[red]✗ Error submitting scan: {e}[/red]")
        else:
            print(f"✗ Error submitting scan: {e}")
        return None


def get_job_status(job_id: str) -> Optional[Dict]:
    """
    Get current status of a job.
    
    Args:
        job_id: Job ID from submit_scan()
        
    Returns:
        Job status dictionary or None if error
    """
    try:
        response = requests.get(
            f"{SAST_SERVER_URL}/api/jobs/{job_id}",
            timeout=HEALTH_CHECK_TIMEOUT
        )
        
        if response.status_code == 200:
            return response.json().get("job", {})
        return None
        
    except requests.RequestException:
        return None


# ============================================================================
# PROJECT DISCOVERY
# ============================================================================

def is_project_root(path: Path) -> bool:
    """
    Check if directory is a project root.
    
    Looks for project markers like package.json, requirements.txt, etc.
    
    Args:
        path: Directory path to check
        
    Returns:
        True if directory appears to be a project root
    """
    for marker in PROJECT_MARKERS:
        if (path / marker).exists():
            return True
    return False


def discover_projects(base_path: Path, exclude: List[str] = EXCLUDE_DIRS) -> List[Path]:
    """
    Recursively discover projects under base path.
    
    Args:
        base_path: Root directory to search
        exclude: List of directory names to exclude
        
    Returns:
        List of project root directories
    """
    projects = []
    
    try:
        for item in base_path.iterdir():
            # Skip excluded directories
            if item.name in exclude or item.name.startswith('.'):
                continue
            
            # Skip files
            if not item.is_dir():
                continue
            
            # Check if this is a project root
            if is_project_root(item):
                projects.append(item)
            else:
                # Recurse into subdirectories
                projects.extend(discover_projects(item, exclude))
    
    except PermissionError:
        pass  # Skip directories we can't access
    
    return projects


# ============================================================================
# POLLING LOOP
# ============================================================================

def wait_for_completion(job_id: str, job_name: str, progress_task=None, progress=None) -> Dict:
    """
    Poll server until job completes.
    
    Args:
        job_id: Job ID to monitor
        job_name: Human-readable job name for display
        progress_task: Rich progress task ID (optional)
        progress: Rich Progress object (optional)
        
    Returns:
        Final job status dictionary
    """
    start_time = time.time()
    poll_count = 0
    
    while True:
        # Check if max time exceeded
        elapsed = time.time() - start_time
        if elapsed > MAX_POLL_TIME:
            return {
                "status": "timeout",
                "error": f"Job exceeded maximum wait time ({MAX_POLL_TIME}s)"
            }
        
        # Get job status
        job_status = get_job_status(job_id)
        
        if not job_status:
            time.sleep(POLL_INTERVAL)
            continue
        
        status = job_status.get("status", "unknown")
        
        # Update progress if Rich UI available
        if progress and progress_task is not None:
            if status == "running":
                progress.update(progress_task, description=f"[cyan]{job_name}[/cyan] Running...")
            elif status == "completed":
                duration = job_status.get("duration_seconds", elapsed)
                progress.update(
                    progress_task,
                    description=f"[green]{job_name}[/green] ✓ ({duration:.1f}s)",
                    completed=100
                )
            elif status == "failed":
                error = job_status.get("error", "Unknown error")
                progress.update(
                    progress_task,
                    description=f"[red]{job_name}[/red] ✗ {error}",
                    completed=100
                )
        
        # Check if complete
        if status in ["completed", "failed", "cancelled"]:
            return job_status
        
        # Adaptive polling: slow down for long-running jobs
        poll_count += 1
        interval = POLL_INTERVAL if poll_count < 10 else min(POLL_INTERVAL * 2, 15)
        time.sleep(interval)


# ============================================================================
# RICH UI COMPONENTS
# ============================================================================

def display_server_stats():
    """Display server statistics in a nice panel."""
    if not console:
        return
    
    stats = get_server_statistics()
    if not stats:
        console.print("[yellow]⚠ Server statistics unavailable[/yellow]")
        return
    
    scan_stats = stats.get("scan_statistics", {})
    process_health = stats.get("process_health", {})
    system_info = stats.get("system_info", {})
    
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")
    
    # Active scans
    active = scan_stats.get("active_scans", 0)
    max_scans = system_info.get("max_parallel_scans", 4)
    table.add_row("Active Scans", f"{active}/{max_scans}")
    
    # Completed/Failed
    completed = scan_stats.get("completed_scans", 0)
    failed = scan_stats.get("failed_scans", 0)
    table.add_row("Completed", str(completed))
    table.add_row("Failed", str(failed))
    
    # CPU/Memory
    cpu = process_health.get("cpu_percent", 0)
    memory = process_health.get("memory_percent", 0)
    table.add_row("CPU Usage", f"{cpu:.1f}%")
    table.add_row("Memory Usage", f"{memory:.1f}%")
    
    # Health
    healthy = process_health.get("healthy", True)
    health_str = "[green]✓ Healthy[/green]" if healthy else "[red]✗ Unhealthy[/red]"
    table.add_row("Server Status", health_str)
    
    panel = Panel(
        table,
        title="[bold cyan]SAST Server Status[/bold cyan]",
        border_style="cyan"
    )
    console.print(panel)
    console.print()


def display_project_list(projects: List[Path]):
    """Display discovered projects in a table."""
    if not console:
        print(f"\nDiscovered {len(projects)} projects:")
        for i, proj in enumerate(projects, 1):
            print(f"  {i}. {proj.name}")
        print()
        return
    
    table = Table(title=f"Discovered Projects ({len(projects)})", box=box.ROUNDED)
    table.add_column("#", style="dim", width=4)
    table.add_column("Project Name", style="cyan")
    table.add_column("Path", style="dim")
    
    for i, proj in enumerate(projects, 1):
        table.add_row(str(i), proj.name, str(proj.parent))
    
    console.print(table)
    console.print()


def display_scan_summary(results: List[Dict], total_duration: float):
    """Display final scan summary."""
    completed = sum(1 for r in results if r.get("status") == "completed")
    failed = sum(1 for r in results if r.get("status") in ["failed", "timeout"])
    
    if console:
        table = Table(box=box.DOUBLE, show_header=False, padding=(0, 2))
        table.add_column("Metric", style="bold cyan")
        table.add_column("Value", style="bold white")
        
        table.add_row("Total Scans", str(len(results)))
        table.add_row("[green]Completed[/green]", str(completed))
        table.add_row("[red]Failed[/red]", str(failed))
        table.add_row("Duration", f"{total_duration:.1f}s")
        
        success_rate = (completed / len(results) * 100) if results else 0
        table.add_row("Success Rate", f"{success_rate:.1f}%")
        
        panel = Panel(
            table,
            title="[bold green]Scan Summary[/bold green]",
            border_style="green"
        )
        console.print("\n")
        console.print(panel)
    else:
        print("\n" + "="*80)
        print("SCAN SUMMARY")
        print("="*80)
        print(f"Total Scans: {len(results)}")
        print(f"Completed: {completed}")
        print(f"Failed: {failed}")
        print(f"Duration: {total_duration:.1f}s")
        print("="*80)


# ============================================================================
# MAIN SCAN ORCHESTRATION
# ============================================================================

def scan_projects(projects: List[Path], tools: List[str], dry_run: bool = False):
    """
    Scan multiple projects with specified tools.
    
    Args:
        projects: List of project paths to scan
        tools: List of tool names to run
        dry_run: If True, don't actually submit scans
    """
    if dry_run:
        if console:
            console.print("[yellow]DRY RUN MODE - No scans will be submitted[/yellow]\n")
        else:
            print("DRY RUN MODE - No scans will be submitted\n")
        return
    
    # Calculate total jobs
    total_jobs = len(projects) * len(tools)
    results = []
    start_time = time.time()
    
    if console and RICH_AVAILABLE:
        # Rich UI with progress bars
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            
            overall_task = progress.add_task(
                "[cyan]Overall Progress",
                total=total_jobs
            )
            
            for project in projects:
                project_name = project.name
                
                for tool in tools:
                    tool_name = get_tool_display_name(tool)
                    job_name = f"{tool_name}: {project_name}"
                    
                    # Submit scan
                    job_task = progress.add_task(
                        f"[yellow]{job_name}[/yellow] Submitting...",
                        total=100
                    )
                    
                    job_id = submit_scan(str(project), tool)
                    
                    if not job_id:
                        progress.update(
                            job_task,
                            description=f"[red]{job_name}[/red] ✗ Submission failed",
                            completed=100
                        )
                        results.append({"status": "failed", "job_name": job_name})
                        progress.advance(overall_task)
                        continue
                    
                    # Wait for completion
                    result = wait_for_completion(job_id, job_name, job_task, progress)
                    results.append({
                        "status": result.get("status"),
                        "job_name": job_name,
                        "duration": result.get("duration_seconds", 0)
                    })
                    
                    progress.advance(overall_task)
    else:
        # Basic console output
        print(f"\nScanning {len(projects)} projects with {len(tools)} tools...")
        print(f"Total jobs: {total_jobs}\n")
        
        job_num = 0
        for project in projects:
            project_name = project.name
            
            for tool in tools:
                job_num += 1
                tool_name = get_tool_display_name(tool)
                job_name = f"{tool_name}: {project_name}"
                
                print(f"[{job_num}/{total_jobs}] {job_name}... ", end="", flush=True)
                
                # Submit scan
                job_id = submit_scan(str(project), tool)
                
                if not job_id:
                    print("✗ Submission failed")
                    results.append({"status": "failed", "job_name": job_name})
                    continue
                
                # Wait for completion
                result = wait_for_completion(job_id, job_name)
                status = result.get("status")
                
                if status == "completed":
                    duration = result.get("duration_seconds", 0)
                    print(f"✓ Completed ({duration:.1f}s)")
                else:
                    error = result.get("error", "Unknown error")
                    print(f"✗ Failed: {error}")
                
                results.append({
                    "status": status,
                    "job_name": job_name,
                    "duration": result.get("duration_seconds", 0)
                })
    
    # Display summary
    total_duration = time.time() - start_time
    display_scan_summary(results, total_duration)


# ============================================================================
# CLI INTERFACE
# ============================================================================

def main():
    """Main entry point for distributed SAST client."""
    parser = argparse.ArgumentParser(
        description="Distributed SAST Client - Submit scans to Kali VM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan all projects in Resola folder
  python sast_client.py --base-path F:\\work\\Resola
  
  # Scan specific project
  python sast_client.py --project F:\\work\\Resola\\mp-api
  
  # Use specific tools
  python sast_client.py --base-path F:\\work\\Resola --tools semgrep,bandit
  
  # Dry run (preview projects)
  python sast_client.py --base-path F:\\work\\Resola --dry-run
        """
    )
    
    parser.add_argument(
        '--base-path',
        type=str,
        help='Base path to discover projects'
    )
    parser.add_argument(
        '--project',
        type=str,
        help='Scan a specific project path'
    )
    parser.add_argument(
        '--tools',
        type=str,
        default=','.join(DEFAULT_TOOLS),
        help=f'Comma-separated list of tools (default: {",".join(DEFAULT_TOOLS)})'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Preview projects without scanning'
    )
    
    args = parser.parse_args()
    
    # Banner
    if console:
        console.print("\n[bold magenta]" + "="*80 + "[/bold magenta]")
        console.print("[bold magenta]        Distributed SAST Client - Windows → Kali VM[/bold magenta]")
        console.print("[bold magenta]" + "="*80 + "[/bold magenta]")
        console.print(f"[cyan]Server: {SAST_SERVER_URL}[/cyan]")
        console.print(f"[cyan]Tools: {args.tools}[/cyan]")
        console.print("[bold magenta]" + "="*80 + "[/bold magenta]\n")
    else:
        print("\n" + "="*80)
        print("        Distributed SAST Client - Windows → Kali VM")
        print("="*80)
        print(f"Server: {SAST_SERVER_URL}")
        print(f"Tools: {args.tools}")
        print("="*80 + "\n")
    
    # Check server health
    if console:
        console.print("[cyan]Checking server health...[/cyan]")
    else:
        print("Checking server health...")
    
    if not check_server_health():
        if console:
            console.print("[red]✗ Server is not responding. Please check:[/red]")
            console.print(f"[red]  1. Is the Kali VM running?[/red]")
            console.print(f"[red]  2. Is sast_server.py running on {SAST_SERVER_URL}?[/red]")
            console.print(f"[red]  3. Can you ping 192.168.204.160?[/red]")
        else:
            print("✗ Server is not responding. Please check:")
            print("  1. Is the Kali VM running?")
            print(f"  2. Is sast_server.py running on {SAST_SERVER_URL}?")
            print("  3. Can you ping 192.168.204.160?")
        sys.exit(1)
    
    if console:
        console.print("[green]✓ Server is healthy[/green]\n")
    else:
        print("✓ Server is healthy\n")
    
    # Show server stats
    if SHOW_SERVER_STATS:
        display_server_stats()
    
    # Discover or validate projects
    if args.project:
        # Single project mode
        project_path = Path(args.project)
        if not project_path.exists():
            if console:
                console.print(f"[red]✗ Project not found: {args.project}[/red]")
            else:
                print(f"✗ Project not found: {args.project}")
            sys.exit(1)
        
        projects = [project_path]
    elif args.base_path:
        # Discovery mode
        base_path = Path(args.base_path)
        if not base_path.exists():
            if console:
                console.print(f"[red]✗ Base path not found: {args.base_path}[/red]")
            else:
                print(f"✗ Base path not found: {args.base_path}")
            sys.exit(1)
        
        if console:
            console.print(f"[cyan]Discovering projects in {args.base_path}...[/cyan]\n")
        else:
            print(f"Discovering projects in {args.base_path}...\n")
        
        projects = discover_projects(base_path)
        
        if not projects:
            if console:
                console.print("[yellow]⚠ No projects discovered[/yellow]")
            else:
                print("⚠ No projects discovered")
            sys.exit(0)
    else:
        parser.print_help()
        sys.exit(1)
    
    # Display projects
    display_project_list(projects)
    
    # Parse tools
    tools = [t.strip() for t in args.tools.split(',')]
    
    # Start scanning
    scan_projects(projects, tools, args.dry_run)


if __name__ == "__main__":
    main()
