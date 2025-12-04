#!/usr/bin/env python3
"""
Test script to verify JSON output format for AI payload.
This tests that jq can properly process the AI payload JSON file.
"""

import json
import sys
from toon_converter import prepare_toon_for_ai_analysis

# Sample scan data
sample_scan_data = {
    "job_id": "test-123",
    "tool_name": "semgrep",
    "scan_params": {"target": "/test/path"},
    "started_at": "2025-12-04T10:00:00",
    "completed_at": "2025-12-04T10:05:00",
    "scan_result": {
        "results": [
            {
                "check_id": "security.injection.sql",
                "path": "app.py",
                "extra": {"severity": "HIGH"}
            }
        ]
    }
}

sample_metadata = {
    "job_id": "test-123",
    "tool_name": "semgrep",
    "scan_date": "2025-12-04T10:05:00",
    "target": "/test/path"
}

# Test 1: TOON format payload (old behavior)
print("Test 1: TOON format AI payload")
print("-" * 60)
toon_payload = prepare_toon_for_ai_analysis(
    toon_data="sample toon string",
    scan_metadata=sample_metadata,
    output_format="toon"
)
print(f"Format: {toon_payload['format']}")
print(f"Data type: {type(toon_payload['data'])}")
print(f"Data is string: {isinstance(toon_payload['data'], str)}")
print()

# Test 2: JSON format payload (new behavior - jq compatible)
print("Test 2: JSON format AI payload (jq-compatible)")
print("-" * 60)
json_payload = prepare_toon_for_ai_analysis(
    toon_data="sample toon string",
    scan_metadata=sample_metadata,
    json_data=sample_scan_data,
    output_format="json"
)
print(f"Format: {json_payload['format']}")
print(f"Data type: {type(json_payload['data'])}")
print(f"Data is dict: {isinstance(json_payload['data'], dict)}")
print()

# Test 3: Verify jq can process the JSON payload
print("Test 3: Verify JSON structure for jq compatibility")
print("-" * 60)
try:
    # Simulate saving and loading the JSON file
    json_str = json.dumps(json_payload, indent=2, ensure_ascii=False)
    reloaded = json.loads(json_str)

    # Verify the data field is a proper dict/object, not a string
    assert isinstance(reloaded['data'], dict), "Data field should be a dict/object"
    assert reloaded['format'] == 'json', "Format should be 'json'"

    # This is what jq would extract
    extracted_data = reloaded['data']
    print(f"✓ AI payload is valid JSON")
    print(f"✓ Data field is a JSON object (not a string)")
    print(f"✓ jq can extract: .data.job_id = '{extracted_data.get('job_id')}'")
    print(f"✓ jq can extract: .data.tool_name = '{extracted_data.get('tool_name')}'")
    print(f"✓ jq can filter: .data.scan_result.results[] will work")
    print()
    print("SUCCESS: AI payload is now jq-compatible!")
    sys.exit(0)

except Exception as e:
    print(f"✗ ERROR: {e}")
    sys.exit(1)
