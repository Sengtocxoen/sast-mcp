#!/usr/bin/env python3
"""
Test script for path resolution functionality

This script tests the dynamic path resolution that uses WINDOWS_BASE and MOUNT_POINT
environment variables instead of hardcoded values.

Usage:
    python3 test_path_resolution.py
"""

import os
import re

# Configuration (simulating environment variables)
MOUNT_POINT = os.environ.get("MOUNT_POINT", "/mnt/work")
WINDOWS_BASE = os.environ.get("WINDOWS_BASE", "F:/work")

def resolve_windows_path(windows_path: str) -> str:
    """
    Convert Windows path to Linux mount path using configured WINDOWS_BASE and MOUNT_POINT

    Mount mapping: WINDOWS_BASE <-> MOUNT_POINT
    """
    # Normalize path separators
    normalized_path = windows_path.replace('\\', '/')

    print(f"Resolving path: {windows_path} -> normalized: {normalized_path}")
    print(f"Using mapping: {WINDOWS_BASE} -> {MOUNT_POINT}")

    # Normalize WINDOWS_BASE for comparison (remove trailing slash for consistency)
    windows_base_normalized = WINDOWS_BASE.replace('\\', '/').rstrip('/')
    mount_point_normalized = MOUNT_POINT.rstrip('/')

    # Build dynamic patterns based on environment variables
    # Support various formats: F:/work, f:/work, /f:/work (Git Bash)
    patterns = [
        (rf'^{re.escape(windows_base_normalized)}/', f'{mount_point_normalized}/'),  # F:/work/... -> /mnt/work/...
        (rf'^{re.escape(windows_base_normalized)}$', mount_point_normalized),        # F:/work -> /mnt/work
        (rf'^/{re.escape(windows_base_normalized.lower())}/', f'{mount_point_normalized}/'),  # Git bash: /f:/work/... -> /mnt/work/...
        (rf'^/{re.escape(windows_base_normalized.lower())}$', mount_point_normalized),        # Git bash: /f:/work -> /mnt/work
        (rf'^{re.escape(windows_base_normalized.lower())}/', f'{mount_point_normalized}/'),   # Lowercase: f:/work/... -> /mnt/work/...
        (rf'^{re.escape(windows_base_normalized.lower())}$', mount_point_normalized),         # Lowercase: f:/work -> /mnt/work
    ]

    for pattern, replacement in patterns:
        if re.match(pattern, normalized_path, re.IGNORECASE):
            # Replace the Windows base with Linux mount point
            linux_path = re.sub(pattern, replacement, normalized_path, flags=re.IGNORECASE)

            print(f"✓ Pattern matched: {pattern}")
            print(f"✓ Path resolved: {windows_path} -> {linux_path}")
            return linux_path

    # If path is already a valid Linux path starting with mount point, return as-is
    if normalized_path.startswith(mount_point_normalized):
        print(f"✓ Path already valid Linux path: {normalized_path}")
        return normalized_path

    # If path starts with / and exists, it's already a Linux path
    if normalized_path.startswith('/') and os.path.exists(normalized_path):
        print(f"✓ Path is valid Linux path: {normalized_path}")
        return normalized_path

    # If no pattern matched, return original
    print(f"⚠ Could not resolve path: {windows_path}")
    print(f"⚠ Returning original path as-is")
    return windows_path


def test_path_resolution():
    """Test various path resolution scenarios"""

    print("=" * 80)
    print("PATH RESOLUTION TEST")
    print("=" * 80)
    print(f"\nConfiguration:")
    print(f"  WINDOWS_BASE: {WINDOWS_BASE}")
    print(f"  MOUNT_POINT: {MOUNT_POINT}")
    print("\n" + "=" * 80)

    # Test cases
    test_cases = [
        ("F:/work/MyProject/file.txt", "/mnt/work/MyProject/file.txt"),
        ("F:\\work\\project\\scan.json", "/mnt/work/project/scan.json"),
        ("F:/work/scan-results.txt", "/mnt/work/scan-results.txt"),
        ("f:/work/myproject/file.py", "/mnt/work/myproject/file.py"),
        ("F:/work", "/mnt/work"),
        ("/f:/work/test/file.txt", "/mnt/work/test/file.txt"),
        ("/mnt/work/already/valid.txt", "/mnt/work/already/valid.txt"),
    ]

    passed = 0
    failed = 0

    for i, (input_path, expected_output) in enumerate(test_cases, 1):
        print(f"\n--- Test Case {i} ---")
        result = resolve_windows_path(input_path)

        if result == expected_output:
            print(f"✓ PASS: Got expected result: {result}")
            passed += 1
        else:
            print(f"✗ FAIL: Expected {expected_output}, got {result}")
            failed += 1
        print("-" * 80)

    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total tests: {len(test_cases)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print("=" * 80)

    return failed == 0


if __name__ == "__main__":
    success = test_path_resolution()
    exit(0 if success else 1)
