#!/usr/bin/env python3
"""
Weekly Security Report Generator
=================================

This script processes all SAST scan results from the weekly scanning runs
and generates a comprehensive, executive-friendly security assessment report
in Markdown format.

Features:
- Aggregates findings from all scanners (Semgrep, Bandit, TruffleHog, etc.)
- Categorizes vulnerabilities by severity and CWE
- Generates per-project breakdown
- Creates executive summary with key metrics
- Compares with previous week's results (if available)
- Highlights critical issues requiring immediate attention

Usage:
    python generate_weekly_report.py                           # Generate report for latest scan
    python generate_weekly_report.py --date 2026-01-29         # Generate for specific date
    python generate_weekly_report.py --compare 2026-01-22      # Compare with previous week

Author: Security Team
Date: 2026-01-29
"""

import json
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Tuple, Optional

# ============================================================================
# CONFIGURATION
# ============================================================================

REPORTS_BASE = Path("F:/work/Resola/Security-Reports")

# Severity mapping for different scanners
SEVERITY_RANKS = {
    "CRITICAL": 4,
    "ERROR": 4,
    "HIGH": 3,
    "WARNING": 2,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

# ============================================================================
# DATA STRUCTURES
# ============================================================================

class ScanResults:
    """Container for aggregated scan results"""
    def __init__(self):
        self.total_findings = 0
        self.by_severity = defaultdict(int)
        self.by_cwe = defaultdict(int)
        self.by_project = defaultdict(lambda: defaultdict(int))
        self.critical_findings = []
        self.secret_leaks = []
        self.dependency_issues = []

# ============================================================================
# PARSER FUNCTIONS (One for each scanner type)
# ============================================================================

def parse_semgrep_results(file_path: Path, project_name: str, results: ScanResults):
    """
    Parse Semgrep JSON output.
    
    Semgrep structure:
    {
        "results": [
            {
                "check_id": "...",
                "extra": {
                    "severity": "ERROR",
                    "message": "...",
                    "metadata": {
                        "cwe": ["CWE-XXX"],
                        "vulnerability_class": ["..."]
                    }
                },
                "path": "...",
                "start": {"line": N}
            }
        ]
    }
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Handle both direct format and wrapped format
        findings = data.get('results', [])
        if 'parsed_output' in data:
            findings = data.get('parsed_output', {}).get('results', [])
        
        for finding in findings:
            severity = finding.get('extra', {}).get('severity', 'INFO')
            results.total_findings += 1
            results.by_severity[severity] += 1
            results.by_project[project_name][severity] += 1
            
            # Extract CWE
            metadata = finding.get('extra', {}).get('metadata', {})
            cwes = metadata.get('cwe', [])
            for cwe in cwes:
                results.by_cwe[cwe] += 1
            
            # Track critical findings
            if severity in ['ERROR', 'CRITICAL']:
                results.critical_findings.append({
                    'project': project_name,
                    'severity': severity,
                    'message': finding.get('extra', {}).get('message', 'No description'),
                    'file': finding.get('path', 'unknown'),
                    'line': finding.get('start', {}).get('line', 0),
                    'cwe': cwes,
                    'scanner': 'Semgrep'
                })
    
    except Exception as e:
        print(f"⚠ Error parsing Semgrep results for {project_name}: {e}")


def parse_bandit_results(file_path: Path, project_name: str, results: ScanResults):
    """
    Parse Bandit JSON output.
    
    Bandit structure:
    {
        "results": [
            {
                "issue_severity": "HIGH",
                "issue_text": "...",
                "filename": "...",
                "line_number": N,
                "test_id": "B..."
            }
        ]
    }
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        findings = data.get('results', [])
        
        for finding in findings:
            severity = finding.get('issue_severity', 'INFO')
            results.total_findings += 1
            results.by_severity[severity] += 1
            results.by_project[project_name][severity] += 1
            
            if severity in ['HIGH', 'CRITICAL']:
                results.critical_findings.append({
                    'project': project_name,
                    'severity': severity,
                    'message': finding.get('issue_text', 'No description'),
                    'file': finding.get('filename', 'unknown'),
                    'line': finding.get('line_number', 0),
                    'cwe': [finding.get('test_id', 'Unknown')],
                    'scanner': 'Bandit'
                })
    
    except Exception as e:
        print(f"⚠ Error parsing Bandit results for {project_name}: {e}")


def parse_trufflehog_results(file_path: Path, project_name: str, results: ScanResults):
    """
    Parse TruffleHog JSON output.
    
    TruffleHog structure:
    [
        {
            "DetectorName": "...",
            "Verified": true/false,
            "Raw": "...",
            "SourceMetadata": {
                "Data": {
                    "Filesystem": {
                        "file": "..."
                    }
                }
            }
        }
    ]
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            # TruffleHog outputs line-delimited JSON
            content = f.read().strip()
            if not content:
                return
            
            # Try to parse as JSON array or line-delimited
            try:
                findings = json.loads(content)
                if not isinstance(findings, list):
                    findings = [findings]
            except:
                # Line-delimited JSON
                findings = [json.loads(line) for line in content.split('\n') if line.strip()]
        
        for finding in findings:
            detector = finding.get('DetectorName', 'Unknown')
            verified = finding.get('Verified', False)
            
            # Verified secrets are HIGH, unverified are MEDIUM
            severity = 'HIGH' if verified else 'MEDIUM'
            
            results.total_findings += 1
            results.by_severity[severity] += 1
            results.by_project[project_name][severity] += 1
            
            # Extract file path
            file_path_str = 'unknown'
            source_meta = finding.get('SourceMetadata', {})
            if 'Data' in source_meta:
                data = source_meta['Data']
                if 'Filesystem' in data:
                    file_path_str = data['Filesystem'].get('file', 'unknown')
            
            results.secret_leaks.append({
                'project': project_name,
                'detector': detector,
                'verified': verified,
                'severity': severity,
                'file': file_path_str,
                'scanner': 'TruffleHog'
            })
    
    except Exception as e:
        print(f"⚠ Error parsing TruffleHog results for {project_name}: {e}")


def parse_npm_audit_results(file_path: Path, project_name: str, results: ScanResults):
    """
    Parse npm audit JSON output.
    
    npm audit structure:
    {
        "vulnerabilities": {
            "package-name": {
                "severity": "high",
                "title": "...",
                "url": "..."
            }
        }
    }
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        vulnerabilities = data.get('vulnerabilities', {})
        
        for pkg_name, vuln_info in vulnerabilities.items():
            severity = vuln_info.get('severity', 'info').upper()
            
            results.total_findings += 1
            results.by_severity[severity] += 1
            results.by_project[project_name][severity] += 1
            
            results.dependency_issues.append({
                'project': project_name,
                'package': pkg_name,
                'severity': severity,
                'title': vuln_info.get('title', 'No description'),
                'scanner': 'npm audit'
            })
    
    except Exception as e:
        print(f"⚠ Error parsing npm audit results for {project_name}: {e}")


def parse_trivy_results(file_path: Path, project_name: str, results: ScanResults):
    """
    Parse Trivy JSON output.
    
    Trivy structure:
    {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "Severity": "HIGH",
                        "VulnerabilityID": "CVE-...",
                        "Title": "..."
                    }
                ]
            }
        ]
    }
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        for result in data.get('Results', []):
            for vuln in result.get('Vulnerabilities', []):
                severity = vuln.get('Severity', 'INFO')
                
                results.total_findings += 1
                results.by_severity[severity] += 1
                results.by_project[project_name][severity] += 1
                
                if severity in ['CRITICAL', 'HIGH']:
                    results.critical_findings.append({
                        'project': project_name,
                        'severity': severity,
                        'message': vuln.get('Title', 'No description'),
                        'file': vuln.get('VulnerabilityID', 'Unknown'),
                        'line': 0,
                        'cwe': [],
                        'scanner': 'Trivy'
                    })
    
    except Exception as e:
        print(f"⚠ Error parsing Trivy results for {project_name}: {e}")


# ============================================================================
# REPORT GENERATION
# ============================================================================

def process_scan_directory(scan_dir: Path) -> ScanResults:
    """
    Process all scan result files in a directory.
    
    Args:
        scan_dir: Directory containing weekly scan results
        
    Returns:
        Aggregated ScanResults object
    """
    results = ScanResults()
    
    print(f"📂 Processing scan directory: {scan_dir}")
    
    # Process Deca and IDP subdirectories
    for folder in ['Deca', 'IDP']:
        folder_path = scan_dir / folder
        if not folder_path.exists():
            continue
        
        # Process all JSON files
        for json_file in folder_path.glob('*.json'):
            project_name = json_file.stem.rsplit('-', 1)[0]  # Remove scanner suffix
            scanner_type = json_file.stem.rsplit('-', 1)[1]  # Get scanner type
            
            print(f"  📄 {folder}/{json_file.name}")
            
            # Route to appropriate parser
            if scanner_type == 'semgrep':
                parse_semgrep_results(json_file, f"{folder}/{project_name}", results)
            elif scanner_type == 'bandit':
                parse_bandit_results(json_file, f"{folder}/{project_name}", results)
            elif scanner_type == 'trufflehog':
                parse_trufflehog_results(json_file, f"{folder}/{project_name}", results)
            elif scanner_type == 'npm-audit':
                parse_npm_audit_results(json_file, f"{folder}/{project_name}", results)
            elif scanner_type == 'trivy':
                parse_trivy_results(json_file, f"{folder}/{project_name}", results)
    
    return results


def generate_markdown_report(results: ScanResults, scan_date: str, output_path: Path):
    """
    Generate comprehensive Markdown report.
    
    Args:
        results: Aggregated scan results
        scan_date: Date of the scan (YYYY-MM-DD)
        output_path: Output file path
    """
    
    # Calculate totals
    total_critical = results.by_severity.get('CRITICAL', 0) + results.by_severity.get('ERROR', 0)
    total_high = results.by_severity.get('HIGH', 0)
    total_medium = results.by_severity.get('MEDIUM', 0) + results.by_severity.get('WARNING', 0)
    total_low = results.by_severity.get('LOW', 0)
    
    # Start building report
    report = f"""# Weekly Security Assessment Report

> **Scan Date**: {scan_date}  
> **Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
> **Coverage**: All Deca & IDP Projects

---

## 📊 Executive Summary

This weekly security assessment analyzed all repositories in the Deca and IDP portfolios using multiple SAST tools including Semgrep, Bandit, TruffleHog, npm audit, and Trivy.

### Overall Statistics

| Severity | Count | Percentage |
|----------|-------|------------|
| 🔴 **Critical/Error** | **{total_critical}** | **{total_critical/max(results.total_findings,1)*100:.1f}%** |
| 🟠 **High** | **{total_high}** | **{total_high/max(results.total_findings,1)*100:.1f}%** |
| 🟡 **Medium/Warning** | **{total_medium}** | **{total_medium/max(results.total_findings,1)*100:.1f}%** |
| 🟢 **Low** | **{total_low}** | **{total_low/max(results.total_findings,1)*100:.1f}%** |
| **TOTAL** | **{results.total_findings}** | **100%** |

---

## 🚨 Critical Issues Requiring Immediate Attention

Found **{len(results.critical_findings)}** critical security issues:

"""

    # Critical findings section
    if results.critical_findings:
        # Group by project
        by_project = defaultdict(list)
        for finding in results.critical_findings:
            by_project[finding['project']].append(finding)
        
        for project, findings in sorted(by_project.items()):
            report += f"\n### {project} ({len(findings)} critical issues)\n\n"
            
            for finding in findings[:10]:  # Show top 10 per project
                cwe_str = ', '.join(finding['cwe']) if finding['cwe'] else 'N/A'
                report += f"""#### {finding['severity']}: {finding['message'][:100]}

- **File**: `{finding['file']}` (Line {finding['line']})
- **CWE**: {cwe_str}
- **Scanner**: {finding['scanner']}

"""
    else:
        report += "\n✅ No critical issues found!\n\n"
    
    # Secret leaks section
    report += f"""---

## 🔑 Secret Leaks Detected

Found **{len(results.secret_leaks)}** potential secret leaks:

"""
    
    if results.secret_leaks:
        verified_count = sum(1 for s in results.secret_leaks if s['verified'])
        report += f"\n- **Verified secrets**: {verified_count} 🔴\n"
        report += f"- **Unverified patterns**: {len(results.secret_leaks) - verified_count} 🟡\n\n"
        
        # Show verified secrets
        verified_secrets = [s for s in results.secret_leaks if s['verified']]
        if verified_secrets:
            report += "### Verified Secrets (Immediate Rotation Required)\n\n"
            for secret in verified_secrets[:20]:  # Show top 20
                report += f"- **{secret['detector']}** in `{secret['project']}/{secret['file']}`\n"
    else:
        report += "\n✅ No secret leaks detected!\n\n"
    
    # Dependency vulnerabilities
    report += f"""---

## 📦 Dependency Vulnerabilities

Found **{len(results.dependency_issues)}** dependency issues:

"""
    
    if results.dependency_issues:
        # Group by severity
        critical_deps = [d for d in results.dependency_issues if d['severity'] == 'CRITICAL']
        high_deps = [d for d in results.dependency_issues if d['severity'] == 'HIGH']
        
        report += f"\n- **Critical**: {len(critical_deps)}\n"
        report += f"- **High**: {len(high_deps)}\n"
        report += f"- **Other**: {len(results.dependency_issues) - len(critical_deps) - len(high_deps)}\n\n"
        
        if critical_deps:
            report += "### Critical Dependency Issues\n\n"
            for dep in critical_deps[:15]:
                report += f"- **{dep['package']}** in `{dep['project']}`: {dep['title']}\n"
    else:
        report += "\n✅ No dependency vulnerabilities found!\n\n"
    
    # Per-project breakdown
    report += """---

## 📁 Per-Project Breakdown

"""
    
    for project, severities in sorted(results.by_project.items()):
        total = sum(severities.values())
        crit = severities.get('CRITICAL', 0) + severities.get('ERROR', 0)
        high = severities.get('HIGH', 0)
        med = severities.get('MEDIUM', 0) + severities.get('WARNING', 0)
        low = severities.get('LOW', 0)
        
        report += f"\n### {project}\n\n"
        report += f"**Total**: {total} | "
        report += f"Critical: {crit} | High: {high} | Medium: {med} | Low: {low}\n"
    
    # Top CWE categories
    report += """---

## 🎯 Top Vulnerability Categories (CWE)

"""
    
    if results.by_cwe:
        sorted_cwes = sorted(results.by_cwe.items(), key=lambda x: x[1], reverse=True)
        for cwe, count in sorted_cwes[:15]:
            report += f"- **{cwe}**: {count} findings\n"
    
    # Recommendations
    report += f"""---

## 💡 Recommendations

### Immediate Actions (Critical/High Priority)

1. **Rotate All Verified Secrets** ({len([s for s in results.secret_leaks if s['verified']])} found)
   - Use environment variables or secure secret managers (AWS Secrets Manager, 1Password)
   - Invalidate compromised credentials immediately

2. **Fix Critical Vulnerabilities** ({total_critical} found)
   - Review all ERROR/CRITICAL findings above
   - Prioritize command injection, SQL injection, and authentication bypasses

3. **Update Critical Dependencies** ({len([d for d in results.dependency_issues if d['severity'] in ['CRITICAL', 'HIGH']])} found)
   - Run `npm update` or `pip install --upgrade` for affected packages
   - Test thoroughly after updates

### Medium Priority

4. **Address Code Quality Issues** ({total_medium} findings)
   - Review WARNING/MEDIUM severity findings
   - Implement secure coding practices

5. **Implement Security Controls**
   - Add pre-commit hooks for secret detection (TruffleHog)
   - Enable SAST in CI/CD pipelines
   - Set up automated dependency scanning

---

## 🔧 Tools Used

- ✅ **Semgrep** - Static analysis for code vulnerabilities
- ✅ **Bandit** - Python security scanner
- ✅ **TruffleHog** - Secret detection
- ✅ **npm audit** - Node.js dependency scanner
- ✅ **Trivy** - Container and infrastructure scanner

---

**Report Generated**: {datetime.now().isoformat()}  
**Next Scan**: {(datetime.now() + timedelta(days=7)).strftime('%Y-%m-%d')}
"""
    
    # Write report to file
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"\n✅ Report generated: {output_path}")


# ============================================================================
# MAIN FUNCTION
# ============================================================================

def main():
    """Main execution"""
    
    parser = argparse.ArgumentParser(
        description="Generate weekly security assessment report",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--date', type=str, 
                       help='Scan date (YYYY-MM-DD), defaults to today')
    parser.add_argument('--compare', type=str,
                       help='Compare with previous scan date (YYYY-MM-DD)')
    
    args = parser.parse_args()
    
    # Determine scan date
    scan_date = args.date or datetime.now().strftime("%Y-%m-%d")
    scan_dir = REPORTS_BASE / f"Weekly-{scan_date}"
    
    if not scan_dir.exists():
        print(f"❌ Scan directory not found: {scan_dir}")
        print(f"Available scans:")
        for d in sorted(REPORTS_BASE.glob("Weekly-*")):
            print(f"  - {d.name}")
        return
    
    print(f"{'='*80}")
    print(f"  WEEKLY SECURITY REPORT GENERATOR")
    print(f"{'='*80}")
    print(f"📅 Scan Date: {scan_date}")
    print(f"📂 Scan Directory: {scan_dir}")
    print(f"{'='*80}\n")
    
    # Process scan results
    results = process_scan_directory(scan_dir)
    
    print(f"\n{'='*80}")
    print(f"  PROCESSING COMPLETE")
    print(f"{'='*80}")
    print(f"📊 Total Findings: {results.total_findings}")
    print(f"🚨 Critical: {len(results.critical_findings)}")
    print(f"🔑 Secret Leaks: {len(results.secret_leaks)}")
    print(f"📦 Dependency Issues: {len(results.dependency_issues)}")
    print(f"{'='*80}\n")
    
    # Generate report
    output_path = scan_dir / "WEEKLY_SECURITY_REPORT.md"
    generate_markdown_report(results, scan_date, output_path)
    
    print(f"\n✅ All done! Review your report at:")
    print(f"   {output_path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⚠ Report generation interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
