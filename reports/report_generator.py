"""
report_generator.py - Terminal display + JSON/TXT report output
"""
import json
import os
from datetime import datetime
from utils.formatter import print_issue, print_success, print_error, print_info

OUTPUT_DIR = "output/scans"

def generate_report(results, target, output_path=None, fmt="txt", explain=False, silent=False):
    """
    Display results in terminal and optionally save to file.
    """
    print()
    if not results:
        if not silent:
            print_success("No issues detected.")
    else:
        if not silent:
            print_info(f"{len(results)} finding(s):")
        for issue in results:
            print_issue(issue)

    if output_path:
        _save(results, target, output_path, fmt)
    else:
        # Auto-save to output/scans/
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = target.replace("https://", "").replace("http://", "").replace("/", "_")
        auto_path = os.path.join(OUTPUT_DIR, f"{safe}_{ts}.{fmt}")
        _save(results, target, auto_path, fmt)
        print_info(f"Report saved → {auto_path}")

def _save(results, target, path, fmt):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if fmt == "json":
        _save_json(results, target, path)
    else:
        _save_txt(results, target, path)

def _save_txt(results, target, path):
    lines = [
        "=" * 60,
        "  PENDO CLI - Security Scan Report",
        f"  Target : {target}",
        f"  Date   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Issues : {len(results)}",
        "=" * 60,
    ]
    if not results:
        lines.append("\n  [+] No issues detected.")
    else:
        for i, issue in enumerate(results, 1):
            lines.append(f"\n  [{i}] {issue.get('type')}")
            for key, label in [
                ("header",     "Header  "),
                ("endpoint",   "Endpoint"),
                ("param",      "Param   "),
                ("payload",    "Payload "),
                ("detail",     "Detail  "),
                ("risk",       "Risk    "),
                ("confidence", "Confidence"),
                ("reason",     "Reason  "),
            ]:
                val = issue.get(key)
                if val:
                    lines.append(f"      {label} : {val}")
    lines.append("\n" + "=" * 60)
    with open(path, "w") as f:
        f.write("\n".join(lines))

def _save_json(results, target, path):
    data = {
        "target": target,
        "date": datetime.now().isoformat(),
        "total_issues": len(results),
        "findings": results,
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
