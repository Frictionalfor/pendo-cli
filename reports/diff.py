"""
diff.py - Compare two scan report files and highlight differences
"""
import json
import sys
from utils.formatter import print_info, print_success, print_error

def diff_reports(path_a, path_b):
    """
    Load two JSON reports and print new/resolved findings.
    """
    a = _load(path_a)
    b = _load(path_b)

    if a is None or b is None:
        return

    old_keys = {_key(f) for f in a.get("findings", [])}
    new_keys = {_key(f) for f in b.get("findings", [])}

    added   = new_keys - old_keys
    removed = old_keys - new_keys

    print_info(f"Comparing: {path_a}  →  {path_b}")
    print()

    if not added and not removed:
        print_success("No differences found between reports.")
        return

    if added:
        print(f"  [+] New findings ({len(added)}):")
        for k in sorted(added):
            print(f"      + {k}")

    if removed:
        print(f"\n  [-] Resolved findings ({len(removed)}):")
        for k in sorted(removed):
            print(f"      - {k}")

def _load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print_error(f"Could not load report: {path} ({e})")
        return None

def _key(finding):
    return f"{finding.get('type')}|{finding.get('endpoint')}|{finding.get('param')}|{finding.get('header')}"


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python -m reports.diff <report_a.json> <report_b.json>")
        sys.exit(1)
    diff_reports(sys.argv[1], sys.argv[2])
